# Store-driven live polling — design

**Status:** approved design, pending implementation plan
**Date:** 2026-08-19
**Repo:** `secator` (core). Touches the runner poll + the store hooks/query backends.

## Goal

Replace the runner's live poll — which reads per-task state from the **Celery result
backend** every cycle — with a poll that reads everything from the **secator store**
(json / sqlite / mongodb) via `QueryEngine`. The Celery result backend is flaky and we
poll (and write) the same per-task state into it over and over, in a *second* data model
that duplicates the store's own runner docs. Since #1312 every consumer already streams
findings from the store; this collapses live status onto the same single model.

## Background (current state, confirmed in code)

- The live poll is secator **core**'s `CeleryData.iter_results` (`secator/celery_utils.py`),
  used by any async runner (CLI `secator x/w/s` remote, and any embedder). Each cycle it
  reads `AsyncResult(task_id).state` + `.info` for every task to assemble per-task
  **state** (PENDING/RUNNING/SUCCESS/FAILURE/REVOKED), **progress %**, **count**, and the
  **topology** (`ids_map`, seeded at build time, extended mid-run when chunk/dynamic
  subtasks announce via `Info` messages).
- Findings are already store-backed (#1312); the runner even backfills store findings the
  poll missed. So the poll's *only* remaining unique job is live **state / progress /
  topology**.
- **Runner docs already exist** for two of three backends:
  - **mongodb**: `db.tasks/workflows/scans`, `update_runner`, `on_build` mints pending
    child docs. secator-api + the inactivity watchdog already read these.
  - **sqlite**: `tasks/workflows/scans` tables, `update_runner`, `on_build`
    (`build_pending_doc`).
  - **json**: `update_runner` writes each runner's own `report.json` (and per-child
    `report_{fqn}.json`), and the query backend discovers runners from the report tree —
    **but there is no `on_build`**, so a workflow's not-yet-run children have no doc until
    they start. This is the "individual task data not saved" gap.
- `QueryEngine` already exposes `list_runners(has_parent=…)` and `get_runner(id, type)`.
- **secator-api already reads runner docs** (`crud.get_runner/get_runners`), not Celery —
  so the platform live path is already store-based. The Celery poll is essentially the
  core/CLI path.

## Decisions (locked)

1. **Fully store-driven completion** — the poll exits when the root runner doc's `status`
   is terminal; zero Celery reads. (Not hybrid, not Celery-fallback.)
2. **Core hard replace** — change core so the store poll is THE path; remove the Celery
   poll. Store is assumed always present (local defaults to json). Verified-store-present
   is a pre-implementation gate (see Risks).
3. **Runner docs are the state model** (not `State`/`Progress` output items) — the model
   secator-api + the watchdog already run on, extended to json parity.

## Design

### 1. `StorePoller` (replaces `CeleryData.iter_results`)

A backend-agnostic poller driven by `QueryEngine`. Once per `CONFIG.runners.poll_frequency`:

- **Topology + progress:** `engine.list_runners(scope)` returns the run's task/workflow/scan
  tree with `status`, `progress`, `chunk_count`, `name`, `full_name`. This replaces
  `ids_map` as the source of the rich progress panel. Chunk/dynamic subtasks appear because
  they are persisted as runner docs (mongodb/sqlite already; json via §2), so there is no
  more `Info`-message topology discovery.
- **New findings:** `engine.iterate(findings_query_scoped_to_run)` streams findings; the
  poller yields any whose `_uuid` was not yielded before (same dedup contract as today's
  `yielded_uuids`). Peak memory stays flat (StreamView, one batch at a time).
- **Count:** per-runner finding `count` shown in the panel comes from the runner doc when
  present, else `engine.count(scope_for_that_runner)`.
- **Exit:** when the **root** runner doc `status ∈ {SUCCESS, FAILURE, REVOKED}` (done).

The rich progress panel rendering (`PanelProgress`, `init_progress`, `update_progress`,
`STATE_COLORS`) is unchanged — only its *data source* moves from `ids_map`/Celery to
`list_runners`.

**Scope:** the poller queries the store scoped to the run via the top-most `{type}_id`
(scan > workflow > task) — the same `run_scope_query` scoping the extractors already use.

### 2. json parity — mint pending child runner docs

Add `on_build` to json's `HOOKS` for `Scan`/`Workflow`, mirroring sqlite's
`build_pending_doc` + `on_build`: when the parent assembles its Celery canvas, write a
PENDING runner doc for each child (into `report_{fqn}.json`), so the child appears in
`list_runners` before it runs. Confirm/extend json's `list_runners` so the full child tree
(root + `report_{fqn}.json`) is returned with live `status`/`progress`. After this, all
three backends persist a complete, live, queryable runner tree.

### 3. Completion + client-side safety net

- The async runner's `_finalize` keys completion off the store doc (root `status` terminal)
  instead of `celery_result.ready()`.
- `StorePoller` carries a **max-inactivity timeout** (config-driven, default aligned with
  the server-side `RUNNER_INACTIVITY_HOURS`): if the root doc has not reached a terminal
  status and no runner doc / finding has advanced within the window, the poll stops and
  reports the run as stalled. The server-side watchdog independently revokes such runs,
  which flips the doc to `REVOKED` and lets the poll exit normally; the client timeout is
  the backstop for when even the watchdog can't (e.g. store reachable but run wedged).

### 4. Drop the redundant Celery writes

The worker's `update_state(state='RUNNING', meta=…)` (`secator/celery.py`) snapshots
per-task state into the result backend solely for the old poll. With nobody reading it, the
worker stops writing it — removing the duplicate write half of "the same data over and
over." Celery keeps only: dispatch, `revoke_task`, and worker liveness (`inspect`, used by
the watchdog). `celery_result` stays on the runner for dispatch + revoke.

### 5. Removals

- `CeleryData.iter_results` / `poll` / `get_all_data` / `get_tasks_data` / `get_task_data`
  and the `Info`-message topology discovery in `iter_results`.
- `update_state`'s RUNNING-meta write (kept only if still needed for revoke bookkeeping —
  determined during implementation).
- `celery_ids_map` as the poll's topology source (kept only if still needed to build the
  canvas / for `revoke`).

### Error handling & edge cases

- **Worker dies before finalizing:** client timeout (§3) + server watchdog. No hang.
- **Revoked run:** watchdog/`stop_runner` writes `status=REVOKED` to the doc → poll exits.
- **Store transiently unreachable:** a failed `list_runners`/`iterate` cycle is logged and
  retried next interval (same tolerance as today's per-poll exception swallow); it never
  aborts the run.
- **No-store run:** assumed impossible post-#1312 (json default). Gate before deleting the
  Celery path; if a store-less mode exists, the Celery poll survives as its sole fallback.

## Testing

- **Unit — `StorePoller`:** against a seeded in-memory/json `QueryEngine`: renders topology
  from `list_runners`; yields only new findings across cycles (dedup by `_uuid`); exits on
  terminal root status; stops on inactivity timeout.
- **Unit — json parity:** a workflow's pending child appears in `list_runners` at build
  time (before it runs) once `on_build` is wired.
- **Integration:** an async run with the worker's `update_state` disabled — assert the live
  topology, per-task state/progress, and streamed findings all come from the store, and the
  poll terminates on the store's terminal status.

## Risks / open items

- **Store-always-present** gate (blocks the hard delete of the Celery path).
- **Progress fidelity:** confirm the runner doc's `progress`/`status` update cadence
  (`on_interval` fires `update_runner`) is frequent enough to match the old per-poll panel
  smoothness; if not, tune the `on_interval` cadence or compute progress in the poller.
- **json concurrency:** pending-child writes go through `atomic_json` (existing) to stay
  correct under the redelivery/duplicate-write hazards already documented in `hooks/json.py`.
- **`count` semantics** parity with the old panel (findings owned by the runner vs all
  descendants).

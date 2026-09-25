# Store-driven live polling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Drive the runner's live progress panel + findings stream from the secator store (`QueryEngine`) instead of the Celery result backend, on all backends (json/sqlite/mongodb).

**Architecture:** A new `StorePoller` reads run-scoped runner docs (`list_runners`, topology/state/progress) + findings (`iterate`, incremental) each cycle and renders the existing rich panel; it exits when the root runner doc reaches a terminal status. json gains runner-doc read+write parity (per-child `report_{fqn}.json` discovery + `on_build` pending docs) to match mongodb/sqlite. The runner prefers `StorePoller` and falls back to the untouched `CeleryData` poll when no store is present (hard-delete of the Celery path deferred to review).

**Tech Stack:** Python, secator core (`secator/query/*`, `secator/hooks/*`, `secator/runners/_base.py`, `secator/celery_utils.py`), pytest.

**Spec:** `docs/superpowers/specs/2026-08-19-store-driven-live-polling-design.md`

## Global Constraints

- Runner doc identity/fields come from `Runner.toDict()`: `name`, `status`, `progress`, `has_children`, `has_parent`, `chunk`, `chunk_count`, `context` (`{type}_id`, `celery_ids`, `workspace_id`), `full_name`/`fqn`.
- Panel fields (unchanged renderer in `CeleryData`): `id, name, full_name, descr, state, count, progress` (+ chunk).
- Finding dedup contract: yield a finding once, tracked by `_uuid` (mirrors `yielded_uuids`).
- Poll cadence: `CONFIG.runners.poll_frequency`. Inactivity bound: reuse an env-configurable hours value (default 2, aligned with server `RUNNER_INACTIVITY_HOURS`).
- json writes go through `atomic_json` (concurrency-safe).
- Non-regression: `StorePoller` failure or no-store → fall back to `CeleryData.iter_results`.

---

### Task 1: json `list_runners` reads per-child reports (read parity)

**Files:**
- Modify: `secator/query/json.py` (`list_runners`, ~345) + a scoped discovery helper.
- Test: `tests/unit/test_query_json_runners.py` (new).

**Interfaces:**
- Produces: `JsonBackend.list_runners(workspace_id=None, runner_type=None, has_parent=None, report_dir=None)` → `list[dict]` where each dict is the runner `info` block + `_type`, `_id`, `_path`. When `report_dir` is given, discovers `report.json` **and** `report_*.json` under that dir (the run subtree); else falls back to the existing workspace-wide `list_reports` (top-level only).

- [ ] **Step 1: Failing test** — seed a temp reports dir: `<ws>/scans/0/report.json` (scan, `has_parent=False`) and `<ws>/scans/0/report_task_httpx.json` (task, `has_parent=True`, `status=RUNNING`). Assert `JsonBackend(...).list_runners(report_dir=<dir>)` returns BOTH, and `has_parent=True` returns only the task.
- [ ] **Step 2: Run — fails** (child not discovered).
- [ ] **Step 3: Implement** — add `report_dir` param; when set, `for p in sorted(Path(report_dir).rglob('report*.json'))` load each `data['info']`, derive `_type` from the info's `config.type` (child reports live in the parent's dir so path-derived type is wrong — read `info['config']['type']`), apply `has_parent` filter. Keep the `list_reports` path for `report_dir=None`.
- [ ] **Step 4: Run — passes.**
- [ ] **Step 5: Commit** `feat(query/json): list_runners discovers per-child reports under a report_dir`.

---

### Task 2: json `on_build` mints PENDING child runner docs (write parity)

**Files:**
- Modify: `secator/hooks/json.py` (add `on_build` + `build_pending_report`; wire into `HOOKS` for `Scan`/`Workflow`).
- Test: `tests/unit/test_hooks_json_on_build.py` (new).

**Interfaces:**
- Consumes: Task 1 `list_runners(report_dir=…)`.
- Produces: `on_build(self, task_spec)` writes `report_{fqn}.json` with a PENDING info block (`{name, status: 'PENDING', done: False, has_parent: True, config, context, chunk, chunk_count}`) into `self.reports_folder`, mirroring sqlite's `build_pending_doc`. Uses `atomic_json`. Returns `task_spec` (json keys by fqn, so — unlike sqlite — no id is injected into `task_spec['context']`; the child overwrites its own file on run).

- [ ] **Step 1: Failing test** — a Workflow with a pending task_spec; call `on_build`; assert a `report_<fqn>.json` exists in reports_folder with `info.status == 'PENDING'` and that Task 1's `list_runners(report_dir=…)` returns it.
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** `build_pending_report(parent, task_spec, child_type)` + `on_build`; wire `'on_build': [on_build]` into `HOOKS[Scan]` and `HOOKS[Workflow]`. Derive fqn from task_spec (name + node id) consistent with `runner.fqn`.
- [ ] **Step 4: Run — passes.**
- [ ] **Step 5: Commit** `feat(hooks/json): on_build writes PENDING child runner docs (mongodb/sqlite parity)`.

---

### Task 3: run-scoped `list_runners` on the QueryEngine

**Files:**
- Modify: `secator/query/__init__.py` (QueryEngine.list_runners passthrough w/ scope), `secator/query/_base.py` (signature), `secator/query/mongodb.py` + `secator/query/sqlite.py` (context-id filter).
- Test: `tests/unit/test_query_runner_scope.py` (new; json + sqlite in-memory).

**Interfaces:**
- Produces: `QueryEngine.list_runners(scope: dict = None, has_parent=None) -> list[dict]`. `scope` = `{'_context.scan_id': id}` / `workflow_id` / `task_id` (the run's top id, from `run_scope_query`). json resolves scope→`report_dir` via context; sqlite/mongodb add the scope to the `data`/doc filter. Returns runner docs newest-first.

- [ ] **Step 1: Failing test** — sqlite in-memory: insert 1 scan + 2 child tasks (one under scope scan_id S, one under a different scan); assert `list_runners(scope={'_context.scan_id': S})` returns the scan + its task only.
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** the scope filter per backend (sqlite: `json_extract(data,'$.context.scan_id')=?`; mongodb: `{'context.scan_id': S}`; json: map scope id → the run's `report_dir` from `self.context['report_dir']`, else workspace scan).
- [ ] **Step 4: Run — passes.**
- [ ] **Step 5: Commit** `feat(query): run-scoped list_runners across backends`.

---

### Task 4: `StorePoller` (the store-driven poll)

**Files:**
- Create: `secator/store_utils.py` (`StorePoller`).
- Test: `tests/unit/test_store_poller.py` (new).

**Interfaces:**
- Consumes: Task 3 `QueryEngine.list_runners(scope, has_parent)`, `QueryEngine.iterate(query)`, `QueryEngine.count(query)`.
- Produces:
  ```python
  class StorePoller:
      def __init__(self, engine, scope, root_id, ids_map=None,
                   refresh_interval=CONFIG.runners.poll_frequency,
                   inactivity_seconds=RUNNER_INACTIVITY_SECONDS,
                   print_remote_info=True, print_remote_title='Results'): ...
      def iter_results(self):
          """Generator yielding OutputType findings; renders the same PanelProgress
          from list_runners each cycle; exits when the root runner doc status is
          terminal (SUCCESS/FAILURE/REVOKED) or the inactivity window elapses."""
  ```
  Reuses `CeleryData`'s `PanelProgress`/`init_progress`/`update_progress`/`STATE_COLORS` (extract to a shared `_progress.py` or import from `celery_utils`).

- [ ] **Step 1: Failing tests** against a fake engine:
  - `list_runners` returns [scan RUNNING 40%, task RUNNING] then [scan SUCCESS 100%, task SUCCESS]; `iterate` returns 2 findings first cycle, 1 new second cycle → `iter_results()` yields 3 findings total, no dup, and stops after the SUCCESS cycle.
  - root stuck RUNNING with no advance + `inactivity_seconds=0` → stops within one cycle (timeout path).
- [ ] **Step 2: Run — fails** (module missing).
- [ ] **Step 3: Implement** `StorePoller.iter_results`: loop `while not terminal and not timed_out`: `runners = engine.list_runners(scope)`; update panel from runners (map status→state, progress, count); `for batch in engine.iterate(findings_scope): for item in batch: if uuid not seen: seen.add; yield`; advance-tracking (max mtime / count) resets the inactivity clock; `terminal = root.status in TERMINAL`; `sleep(refresh_interval)`. Final panel flush like `CeleryData`.
- [ ] **Step 4: Run — passes.**
- [ ] **Step 5: Commit** `feat(core): StorePoller — store-driven live poll`.

---

### Task 5: wire `StorePoller` into the runner (prefer store, Celery fallback)

**Files:**
- Modify: `secator/runners/_base.py` (`yielder` ~1035, `_finalize` ~750).
- Test: `tests/unit/test_runner_store_poll.py` (new; monkeypatch engine + celery_result).

**Interfaces:**
- Consumes: Task 4 `StorePoller`.
- Produces: `Runner._has_store()` → bool (context drivers resolve to a real backend, not `local` with no report / not empty). `yielder`: when `self.celery_result` and `_has_store()`, poll via `StorePoller(engine=<built like process_extractor>, scope=run_scope_query(ctx), root_id=self.celery_result.id...)`; else current `CeleryData.iter_results`. `_finalize`: async completion reads root doc status from the store; keep the `celery_result.ready()` branch only in the fallback path.

- [ ] **Step 1: Failing test** — a fake runner with a store engine returning a terminal root doc + 1 finding; assert `yielder()` yields the finding via `StorePoller` and never calls `AsyncResult`. A second test with `_has_store()=False` asserts it uses `CeleryData`.
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** `_has_store`, the branch in `yielder`, and the store-based completion in `_finalize` (fallback keeps `ready()`).
- [ ] **Step 4: Run — passes; then run `tests/unit/test_celery.py -q` to confirm no regression in the fallback path.**
- [ ] **Step 5: Commit** `feat(core): runner prefers StorePoller, Celery poll as fallback`.

---

## Self-Review

- **Spec coverage:** §1 StorePoller → Task 4; §2 json parity → Tasks 1–2; §3 completion+timeout → Tasks 4–5; §4 drop Celery writes → **deferred** (documented in PR, not this plan — kept to avoid worker-side risk overnight); §5 removals → **deferred** (fallback retained per the prudent-autonomous decision); testing → each task. Gap intentional & noted.
- **Placeholder scan:** none — every task has concrete signatures + test cases.
- **Type consistency:** `list_runners(scope=…, has_parent=…)` and the runner-doc fields (`status`, `progress`, `has_parent`, `context.{type}_id`) are consistent across Tasks 1/3/4/5; `StorePoller` fields match `CeleryData`'s panel fields.

## Deferred to review (not implemented tonight)
- Hard-delete of `CeleryData` poll + `celery_ids_map` topology (spec §5) — fallback retained instead.
- Worker `update_state` RUNNING-meta write removal (spec §4) — kept; only the read side moves.

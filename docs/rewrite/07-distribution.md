# Distributed Execution (Celery)

Secator runs the *same runner code* either locally (sync, eager) or across workers
(async). Orchestration is always expressed as a **Celery canvas** (signature graph).
Source: `secator/celery.py`, `secator/celery_utils.py`, `secator/celery_signals.py`,
and the `build_celery_workflow()` methods on Task/Workflow/Scan.

For a Go/Rust rewrite this is the subsystem most worth re-architecting (Celery is
Python-specific), but its *semantics* must be preserved.

---

## 1. The Celery app

`app = Celery(__name__)` configured (`celery.py`) with:
- **Broker**: `CONFIG.celery.broker_url` — default `filesystem://` (a directory-based
  broker, zero infra); redis/amqp supported.
- **Result backend**: default `file://<dirs.celery_results>`.
- **Serialization**: `pickle` for tasks/results/events (so live `Runner` and
  `OutputType` objects cross the wire). When MongoDB is enabled, payloads shrink to
  uuid lists re-hydrated from the DB.
- **Routing**: orchestrator tasks → `celery` queue; `forward_results` →`results`;
  mongodb hooks → `mongodb`; per-task work routed by **profile** name (queue).
- Worker knobs: `worker_max_tasks_per_child`, `prefetch_multiplier`, pool `gevent`.

`IN_WORKER` (definitions.py) detects worker/airflow context; only then are signal
handlers installed (`celery_signals.setup_handlers`).

---

## 2. Registered Celery tasks

- **`start_runner(config, targets, results, run_opts, hooks, validators, context)`** —
  remote entrypoint for a whole runner. Forces async/no-poll/no-live-updates, picks the
  runner class by `config.type`, builds it, runs it.
- **`run_command(results, name, targets, opts)`** — the **unit of work**: runs ONE task
  by name. Sets celery_id/worker_name in context, forwards prior results, decides
  chunking, marks started, then either replaces itself with a chunked chord (6.4) or
  iterates the task while pushing live state. Returns results (or uuids w/ MongoDB).
- **`forward_results(results)`** — bridge task: flatten + dedupe results between steps
  (by `_uuid`). Needed between two adjacent groups and between chained steps.
- **`mark_runner_started(results, runner, enable_hooks)`** / **`mark_runner_completed`** —
  lifecycle bookends placed at the head/tail of every chain; run on the `results` queue.
  `mark_runner_started` also resolves **scope-tagged targets** (see `02-architecture.md`
  §8) and runs `on_start`; `mark_runner_completed` adds results, runs `mark_duplicates`
  and `on_end`.

---

## 3. Building the canvas (`build_celery_workflow`)

- **Task** → `chain(run_command.si(results, name, targets, opts))`.
- **Workflow** → walk the runner tree:
  - `task` node: evaluate `if:` (restricted `eval`), merge opts (config defaults < node
    opts < run opts), build `task.s(inputs, **opts)`; strip dynamic opts; set context
    (`node_id`, `ancestor_id`, `parent_scope`, aliases).
  - `group` node → Celery `group(...)`. Two adjacent groups need a `forward_results`
    bridge (can't chain two groups directly). A 1-child group degrades to a task.
  - `chain` node → Celery `chain(...)`.
  - Wrap: `chain(mark_runner_started, *sigs, mark_runner_completed)`.
- **Scan** → for each workflow (eval its `if:`), build the Workflow canvas with
  `chain_previous_results=True`, then `chain(mark_runner_started, *workflow_sigs,
  mark_runner_completed)`.

Sync mode runs the canvas eagerly: `workflow.apply().get()`. Async mode dispatches it
(`workflow()`) and the client polls.

---

## 4. Chunking (parallelizing one task over many targets)

A `Command` with many targets and no file-input flag can't run as a single sync process.
`needs_chunking(sync)` decides; `break_task()` then:
- chunks inputs by `input_chunk_size` (default 100),
- divides `rate_limit` across chunks (`chunk_rate_limit`),
- builds one `run_command.si(chunk, …)` per chunk (with `chunk`/`chunk_count` set),
- wraps them in a Celery **chord**: `chord(chunks, mark_runner_completed)`.

Inside the worker, `run_command` calls `self.replace(workflow)` (Celery `replace`) to
swap the running task for the chord, inheriting its task id and trailing chain. Chunk
results are recognized as the parent's own via the `<name>_<n>` source-suffix rule.

---

## 5. Live results & progress (`celery_utils.CeleryData`)

When async, the client doesn't block; it polls the Celery result graph:
- `iter_results(result, ids_map, …)` walks all task ids, reads each task's `meta`
  (the `celery_state` dict: name, state, progress, results, counts, chunk info), renders
  a live Rich progress panel, and yields newly-seen `OutputType` results as they appear.
- Worker side, `update_state(celery_task, task)` writes `task.celery_state` into the
  Celery task meta, throttled by `backend_update_frequency`.
- `poll`, `get_all_data`, `get_tasks_data`, `get_task_data`, `get_task_ids` implement the
  traversal and per-task extraction.

`State`/`Progress`/`Info` output items carry `task_id` so the client can correlate live
updates with the right node (`add_result` special-cases them).

---

## 6. Execution modes summary

| Mode | Trigger | Behavior |
|---|---|---|
| **sync (eager)** | `--sync`, `--dry-run`, or no worker alive | `canvas.apply().get()` runs everything in-process; groups not truly parallel. One `Command` = one subprocess + monitor thread. |
| **async (worker)** | worker alive and not `--sync` | canvas dispatched to workers; groups/chords run concurrently across processes; client live-polls. |

Sentinel constants and toggles relevant to distribution: `IN_WORKER`, `no_poll`,
`no_live_updates`, `has_parent`/`has_children`, `chunk`/`chunk_count`.

---

## 7. Rewrite guidance

Replace Celery with a single concurrency runtime + work queue, but preserve these
semantics:
- **Composition primitives**: chain (sequential), group (parallel), chord
  (parallel-then-join). The whole workflow/scan engine is expressed in these.
- **The unit of work** = run one task over a chunk of targets, returning typed results.
- **Result forwarding + dedup** between steps (`forward_results`).
- **Lifecycle bookends** that run start/end hooks and dedup at the aggregating runner.
- **Chunking** of large target sets with rate-limit division.
- **Live progress streaming** to the client (per-node state + progress + incremental
  results), throttled.
- **Scope/ancestry tagging** so extractors only consume their own subtree's results.
- **Local vs remote parity**: the same composition runs in-process or distributed.

A natural Go design: a DAG of task nodes; an executor that runs nodes honoring
chain/group/chord edges over a worker pool (or a remote queue like NATS/Redis/AMQP for
distributed mode); a results bus with dedup; a streaming status channel for the CLI.
The default "filesystem broker / no infra" mode is worth keeping as a zero-dependency
local default.

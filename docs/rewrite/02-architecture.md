# Architecture

This document describes Secator's runtime architecture: the runner hierarchy, the
execution model, the result/streaming pipeline, hooks, and the data flow that ties
everything together. It is the backbone reference for a rewrite.

---

## 1. The Runner abstraction

Everything that *executes* in Secator is a `Runner` (`secator/runners/_base.py`).
A Runner is a long-lived object that:

1. Takes a **config** (a `TemplateLoader`/dict describing what to run),
2. Takes **inputs** (targets) and optional prior **results**,
3. Produces a **stream of typed output items** (`OutputType` instances) via Python
   iteration (`__iter__` / `yielder`),
4. Manages **lifecycle** (start/end), **hooks**, **validators**, **deduplication**,
   **progress**, **reporting/export**, and (optionally) **distributed execution**.

```
Runner (abstract, _base.py)
├── Command   (command.py)   — executes an external CLI tool; ~the workhorse
│   └── <50 task classes>    (secator/tasks/*.py)  e.g. nmap, httpx, nuclei
├── PythonRunner (python.py) — executes arbitrary Python instead of a shell command
├── Task      (task.py)      — runs ONE task by name (thin wrapper, builds a 1-task celery sig)
├── Workflow  (workflow.py)  — composes many tasks from a YAML config (DAG of tasks)
├── Scan      (scan.py)      — composes many workflows from a YAML config
└── Celery    (celery.py)    — adapts an existing celery result into a Runner
```

Key subclassing rule: **`Command` and `PythonRunner` are the only runners that
actually do work.** `Task`/`Workflow`/`Scan` are *orchestrators* — they build a
Celery canvas (signature graph) of `Command` executions and either run it inline
(`sync`) or dispatch it to a worker (`async`). Even in `sync` mode, orchestration
goes through Celery's `.apply()` (eager execution). See §6.

### Runner contract (what every runner exposes)

Constructor: `Runner(config, inputs=[], results=[], run_opts={}, hooks={}, validators={}, context={})`

Class-level attributes a subclass can set:
- `input_types: list[str]` — accepted target types (URL, IP, HOST, …); used by the
  built-in `_validate_inputs` validator to skip unsupported targets.
- `output_types: list[OutputType]` — the typed outputs this runner can emit. Drives
  schema discrimination when parsing (`_convert_item_schema`).
- `default_inputs` — fallback targets when none provided.
- `default_exporters: list` — exporters to run on completion (Task/Workflow/Scan each
  default to `CONFIG.{tasks,workflows,scans}.exporters`).
- `profiles: list` — option presets.
- `enable_hooks`, `enable_validators`, `enable_duplicate_check` — feature toggles.

Iteration protocol:
- `run()` → `list(self.__iter__())` — eager convenience.
- `__iter__()` — the heart: marks started, drains a results buffer, then iterates
  `self.yielder()` and pipes each raw item through `_process_item()`, finally
  `_finalize()`s (joins threads, marks completed, exports reports).
- `yielder()` — subclass-specific source of raw items. For `Command` it reads the
  subprocess stdout line by line; for orchestrators the default `yielder()` builds a
  Celery workflow (`build_celery_workflow()`) and yields its results.

Async entry points (classmethods): `delay()`, `.s()`, `.si()` create Celery
signatures. `Runner.delay()` enqueues `start_runner`; `Command.delay/s/si` enqueue
`run_command`.

### Important runner state
- `self.results: list[OutputType]` — every item ever added (findings + execution +
  stats + targets).
- `self.uuids: set[str]` — dedup guard so the same item isn't added twice.
- `self.results_buffer: list` — items waiting to be yielded to the caller.
- `self.progress: int`, `self.status` (PENDING/RUNNING/SUCCESS/FAILURE/REVOKED/SKIPPED).
- `self.context: dict` — propagated metadata: `workspace_name`, `celery_id`,
  `task_id`/`workflow_id`/`scan_id`, `node_id`, `ancestor_id`, `parent_scope`, drivers.
- `self.chunk` / `self.chunk_count` — set when a task is split across targets (§6.3).

### Result identity, sources, and "self" filtering
Each item carries internal fields (`_uuid`, `_source`, `_context`, `_timestamp`,
`_duplicate`, `_related`). When an item is added (`add_result`):
- a `_uuid` is assigned if missing,
- `_source` is set to the runner's `unique_name` if missing,
- `_context` is merged with the runner context (preserving `ancestor_id`).

`_is_own_source()` recognises a runner's own output including chunk suffixes
(`nmap`, `nmap_1`, `nmap_2`) while rejecting sibling names (`nmap_light`). This powers
`self_results`, `self_findings`, `self_errors`, etc. — used so a workflow doesn't
attribute a child task's errors to itself.

---

## 2. The execution lifecycle (`__iter__`)

```
__iter__:
  sync?  mark_started()      : log_start()
  yield buffered results (e.g. Targets, prior results)
  if validation errors -> finalize, stop
  for raw_item in yielder():        # subprocess lines / celery results / python yields
      for out in _process_item(raw_item):
          yield out
      run_hooks('on_interval')      # throttled DB sync hook
  on BaseException:
      add Error, set revoked, stop remote celery tasks, drain remaining results
  finally:
      finalize(): join_threads, gc, (sync? mark_completed), export_reports
```

`mark_started()` → sets `started`, `start_time`, runs `on_start` hooks, prints the
runner tree.
`mark_completed()` → sets `done`, `progress=100`, `end_time`, runs **`mark_duplicates()`**,
runs `on_end` hooks, exports profiler, logs result summary.

### `_process_item` (raw → typed)
For each raw item yielded:
1. If it's a `str` line → add to `output`, optionally print, return (no typing).
2. If `no_process` → drop.
3. Run `validate_item` validators.
4. If it's a `dict` → run `on_item_pre_convert` hook → `_convert_item_schema()` to turn
   it into a concrete `OutputType`.
5. `add_result()` then `yield` it.

### Schema discrimination (`_convert_item_schema`)
Turning a parsed `dict` into the right `OutputType`:
- If already an `OutputType`, pass through.
- If the runner defines `output_discriminator(item)`, use its return type.
- Else if the dict has a `_type` key, pick the matching output type by `get_name()`.
- Else try each class in `self.output_types` in order, calling `klass.load(item, output_map)`,
  taking the first that doesn't raise `TypeError`/`KeyError`.
- On failure, emit a `Warning` ("Failed to load item as output type").

This "try each candidate type until one fits" is central and must be replicated.

---

## 3. The Command runner (external tool execution)

`Command` (`secator/runners/command.py`, ~1300 lines) is where a tool actually runs.
A concrete task (e.g. `Nmap`) subclasses `Command` and declares *how* its CLI works.
See `04-task-integration.md` for the full task-author contract. Here is the runtime.

### Command construction (`__init__`)
1. Build an on-the-fly `TemplateLoader` config (`type='task'`, name=class name).
2. Pop run-opts: hooks, results, context (extract `node_id`/`node_name`).
3. Set up validators: `_validate_input_nonempty` (unless `skip_if_no_inputs`),
   `_validate_chunked_input` (sync mode can't take >1 target without a file flag).
4. `super().__init__()` (registers hooks/validators, resolves inputs/opts/profiles/exporters).
5. Apply `CONFIG.tasks.overrides[<ClassName>]` (per-task config overrides).
6. `configure_proxy()` — prepend proxychains or inject a proxy opt.
7. **`_build_cmd_input()`** — decide how targets are passed (arg, stdin pipe, file).
8. **`_build_cmd()`** — assemble the full command string from options.
9. Run `on_cmd` hook; prepend `sudo` if `requires_sudo`.
10. Assemble `item_loaders` (class loaders + instance `item_loader`).

### Building the command string (`_build_cmd` + `_process_opts`)
This is the option engine. For each option declared in `opts`/`meta_opts`:
- `_get_opt_value()` resolves the value, trying aliases (`<prefix>.<opt>`,
  `<prefix>_<opt>`, the raw name, and the `short` alias) against `run_opts`, falling
  back to the option's `default`. `OPT_NOT_SUPPORTED (-1)` short-circuits to "skip".
- Falsy values (`None`/`False`/`[]`) are skipped.
- `opt_value_map[name]` (value or callable) or the option's `pre_process` transforms
  the value; `opt_key_map[name]` renames/skips the flag (`OPT_NOT_SUPPORTED` → drop).
- Names get `_`→`-` and the `opt_prefix` (default `-`) prepended.
- `_build_opt_str()` emits `--flag value` (shlex-quoted unless `shlex=False`), or just
  `--flag` for boolean `True`, or repeats for list values.
- Options marked `internal: True` are resolved but not added to the cmd string.
- `on_cmd_opts` hook can mutate the assembled option dict before stringifying.

The result is `self.cmd` (a single string). `self.shell` is set True if the cmd
contains a pipe (`echo x | tool`).

### Passing inputs (`_build_cmd_input`)
- 1 input: `OPT_PIPE_INPUT` → `echo <input> | cmd`; no `input_flag` → positional arg;
  else `cmd <input_flag> <input>`.
- many inputs: write them to `<reports>/.inputs/<fqn>.txt`, then `file_flag`:
  `OPT_PIPE_INPUT` → `cat file | cmd`; `OPT_SPACE_SEPARATED` → inline; a flag →
  `cmd <file_flag> <file>`; none → positional file path. `file_copy_sudo` copies to
  `/tmp` for sudo'd tools.

### Running the process (`yielder`)
- Skips if `has_children` (it was chunked) or `dry_run` (just prints the cmd).
- Skips with a Warning if no inputs and `skip_if_no_inputs`.
- Prompts for sudo password if needed and no passwordless sudo (TTY required).
- Auto-installs the tool if missing and `CONFIG.security.auto_install_commands`.
- `subprocess.Popen` with `stdout=PIPE, stderr=STDOUT`, own process group
  (`preexec_fn=os.setsid`) unless sudo/`disable_preexec`.
- Spawns a **monitor thread** that periodically emits `Stat` items (CPU/mem via psutil),
  enforces `task_memory_limit_mb` and `task_max_timeout` (SIGTERM on breach).
- Reads stdout line-by-line: `process_line()` (strip ANSI, `on_line` hook, then run
  `item_loaders`) yields raw strings and parsed dicts; monitor-queue items interleaved.
- `on_cmd_done` hook can yield extra items after the process completes.
- `_wait_for_end()` sets `return_code`, and if non-zero emits `Error`s parsed from the
  last 10 output lines (`parse_errors` greps for err/fatal/traceback/ANSI-red).

### Item loaders (parsing tool output)
`run_item_loaders(line)` runs each configured loader:
- A **callable** loader: `loader(self, line)` yields items directly.
- A **Serializer instance** (`JSONSerializer`, `RegexSerializer`, …): `loader.run(line)`
  yields dicts/strings; an optional `on_<name>_loaded(self, item)` callback per task
  post-processes each (default just re-yields). E.g. a `JSONSerializer` paired with
  `on_json_loaded`.

Serializers (`secator/serializers/`):
- `JSONSerializer(strict, list)` — extracts the first `{...}` (or `[{...}]`) substring
  from a line and `json.loads` it. Tolerant by design (tools mix logs + JSON).
- `RegexSerializer(regex, fields, findall)` — regex match → dict of named groups (or
  raw matches with `findall`).
- `dataclass.py` — (de)serialize OutputType dataclasses to/from JSON (see data model).

---

## 4. Hooks and validators

Hooks are the primary extension mechanism. They are registered from three sources and
merged: (a) methods defined on the runner/task class, (b) per-class user hooks
(`hooks[SomeRunnerClass][hook_name]`), (c) global user hooks (`hooks[hook_name]`).

**Runner-level hooks** (`HOOKS` in `_base.py`):
`before_init`, `on_init`, `on_start`, `on_end`, `on_item_pre_convert`, `on_item`,
`on_duplicate`, `on_interval`.

**Command-level hooks** (added by `Command`):
`on_cmd`, `on_cmd_opts`, `on_cmd_done`, `on_line`.

`run_hooks(type, *args)` calls each registered hook as `hook(self, *args)`, returning
the (possibly mutated) first arg. Hooks are skipped under `no_process`/`dry_run`/
disabled-hooks. `on_interval` is additionally throttled by
`CONFIG.runners.backend_update_frequency`. Hook exceptions become `Error` results
(unless `raise_on_error`).

**Validators** (`VALIDATORS`): `validate_input` (runs on the target list at init) and
`validate_item` (runs per yielded item). A failing validator adds an `Error` whose
message is the validator's docstring.

**Drivers** are bundles of hooks. The CLI `--driver mongodb,api,...` imports
`secator.hooks.<driver>.HOOKS` (a dict mapping hook names → callables) and merges them
in, so MongoDB persistence / API sync / Discord notifications are *just hooks*. See
`08-subsystems.md`.

---

## 5. Deduplication model

Dedup is finding-identity logic and must be ported carefully.

- Each `OutputType` is a `@dataclass`. Fields marked `compare=False` are excluded from
  equality; the remaining (comparable) fields form the identity. E.g. a `Url`'s
  identity is essentially its `url`; `status_code`, `title`, etc. are `compare=False`.
- `_compare_key()` returns a hashable tuple of the comparable fields → used for O(n)
  grouping.
- `mark_duplicates()` (run once at `mark_completed`): group all results by
  `_compare_key()`; in each group of >1, the **newest by `_timestamp`** (via `__gt__`)
  becomes the "main", the rest get `_duplicate=True` and their uuids appended to
  `main._related`. `on_item`/`on_duplicate` hooks fire for duplicates.
- Some types override `__gt__` to prefer a source (e.g. `Url` prefers `httpx` output).
- `add_result()` also guards against re-adding the same `_uuid`.

---

## 6. Distributed execution (Celery)

Secator runs the *same code* locally (sync, eager) or on a worker (async). The
orchestration always builds a **Celery canvas**.

### 6.1 Tasks registered on the Celery app (`secator/celery.py`)
- `start_runner(config, targets, …)` — entrypoint to run a whole runner remotely.
- `run_command(results, name, targets, opts)` — runs ONE task by name; the unit of
  work. Handles chunking (see 6.3), live state updates, returns results (or uuids when
  MongoDB is enabled).
- `forward_results(results)` — bridge task: flatten + dedupe results between steps.
- `mark_runner_started` / `mark_runner_completed` — lifecycle bookends in the chain;
  run on the dedicated `results` queue; emit scope-tagged targets, run hooks.

### 6.2 How orchestrators build the canvas (`build_celery_workflow`)
- **Task**: builds a single `run_command.si(...)` signature, wrapped in `chain(sig)`.
- **Workflow**: walks the **runner tree** (built from YAML by `build_runner_tree`).
  - For each `task` node: evaluates its `if:` condition against `opts`/`targets`
    (Python `eval` with a restricted `__builtins__` of just `len`); skips if false.
    Merges options (config defaults < node opts < run opts), builds `task.s(...)`.
  - `_group/*` nodes → Celery `group(...)` (parallel). Two adjacent groups need a
    `forward_results` bridge task (can't chain two groups directly).
  - `chain` nodes → Celery `chain(...)` (sequential).
  - The whole thing is wrapped: `chain(mark_runner_started, *sigs, mark_runner_completed)`.
- **Scan**: for each workflow in the YAML, evaluate its `if:`, build the Workflow's
  canvas with `chain_previous_results=True`, and chain them all between
  `mark_runner_started`/`mark_runner_completed`.

### 6.3 Chunking
A `Command` with many targets and no file-input flag can't run as one process in sync
mode. `needs_chunking()` decides; if so the task is split: `break_task()` chunks inputs
by `input_chunk_size` (default 100), divides `rate_limit` across chunks, builds one
`run_command.si(chunk, …)` per chunk, and replaces the task with a Celery **chord**
(`chord(chunks, mark_runner_completed)`). Inside the worker `run_command` calls
`self.replace(workflow)` to swap itself for the chord.

### 6.4 Live results & progress (client side)
When async, the client polls Celery via `CeleryData.iter_results` (`celery_utils.py`),
walking the result graph, reading each task's `meta` (`celery_state`: status, progress,
results, counts), rendering a live Rich progress panel, and yielding new results as they
appear. `update_state()` (worker side) pushes `celery_state` into Celery task meta,
throttled by `backend_update_frequency`.

### 6.5 Queues
Routing by **profile** (resource class): a task's `profile` attribute (`'small'` by
default, or a callable of opts) is used as the Celery queue name. Lifecycle/bridge
tasks go to the `results` queue; MongoDB hooks to the `mongodb` queue; orchestrators to
`celery`.

### 6.6 Serialization
Celery is configured with **pickle** task/result serialization (so live `Runner` and
`OutputType` objects cross the wire). When MongoDB is enabled, results are passed as
**uuid lists** instead and re-hydrated from the DB (`get_results`) to keep payloads
small.

---

## 7. Reports, workspaces, and the filesystem layout

- A runner gets a **reports folder**:
  `<CONFIG.dirs.reports>/<workspace>/<type>s/<auto-incrementing id>/` with `.inputs/`
  and `.outputs/` subdirs. The id is the next integer (`get_task_folder_id`).
- On completion (async runners by default), `export_reports()` builds a `Report`
  (`secator/report.py`) and runs the resolved **exporters** (json/csv/txt/markdown/
  table/gdrive/console). See `08-subsystems.md`.
- **Workspaces** are just top-level folders under `dirs.reports` (and a logical grouping
  in MongoDB/API backends). `--workspace` selects one; `secator workspace` manages them.

---

## 8. The dynamic-targets / extractor system

This is one of the most distinctive features and the hardest to replicate. Workflow
YAML lets a task derive its **inputs** and **option values** dynamically from the
results produced by *earlier* tasks, via `targets_` / `<opt>_` keys (trailing
underscore = "dynamic/extractor").

An extractor (`secator/runners/_helpers.py::run_extractors`) is `{type, field,
condition, group_by}` (or a `"type.field"` shorthand). At runtime:
- Filter `results` to items of `type` (e.g. `port`, `url`, `vulnerability`).
- Apply the `condition` (a Python `eval` with restricted builtins; supports a custom
  `~=` regex-match operator and `item.<field>` access).
- Scope filtering: results are restricted to the right ancestry (`ancestor_id`) or
  `parent_scope` (so a scan's workflows only consume their own subtree's findings).
- Extract `field` (supports `{nested.key}` formatting), optionally `group_by`.
- The extracted values become the task's `inputs` (for `targets_`) or an option value.

Example (from `host_recon.yaml`): nmap's `targets_` pulls `port.host` where
`opts.scanners`, and `ports_` pulls `port.port`; httpx's `targets_` formats
`{host}:{port}` from `port` findings. This is how recon results "flow" into the next
tool without the user wiring anything.

Conditions also gate whole nodes via `if:` (evaluated in `build_celery_workflow` and in
`prune_runner_tree` for display).

---

## 9. Data flow summary (end to end)

```
CLI (secator x nmap 1.2.3.4)
  └─ register_runner builds click cmd from task opts
     └─ Task(config, inputs, run_opts) [Runner]
        ├─ sync? worker alive? → decide eager vs async
        └─ __iter__
           └─ yielder → build_celery_workflow → run_command (Command)
              └─ Command.yielder
                 ├─ build cmd string from opts
                 ├─ subprocess.Popen, read stdout lines
                 ├─ item_loaders parse line → dict
                 └─ _convert_item_schema → OutputType (Port/Url/Vuln/…)
           └─ _process_item → add_result → yield to caller
        └─ mark_completed → mark_duplicates → on_end hooks
        └─ export_reports → exporters write json/csv/txt/markdown
```

For workflows/scans, the middle expands into a chain/group/chord canvas of many
`run_command`s, with `forward_results` bridging steps and extractors re-targeting each
task from accumulated results.

---

## 10. Concurrency model (for the rewrite)

- **Sync mode**: Celery *eager* execution (`workflow.apply().get()`) runs everything in
  the calling process; groups are not actually parallel under eager execution. A `Command`
  itself is one subprocess plus one monitor thread.
- **Async mode**: real parallelism is provided by Celery workers (default pool `gevent`,
  high concurrency). Tasks in a `group`/`chord` run concurrently across worker processes.
- **Threads**: each `Command` uses a daemon monitor thread; runners track `self.threads`
  and join them at finalize. `secator/thread.py` provides a small thread helper that
  returns errors on join.

A Go/Rust rewrite would naturally replace "Celery eager vs worker" with a single
concurrency runtime (goroutines/tasks + a work queue), but must preserve: per-task
isolation, the chunking semantics, the chain/group/chord composition, live progress
streaming, and the result-forwarding/dedup between steps.

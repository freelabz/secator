# Design Choices & Style Choices

This file captures the *why* behind the architecture and the coding conventions — the
things a rewrite should consciously keep, change, or drop.

---

## Part A — Design choices

### A1. Everything is a streaming `Runner`
A single `Runner` abstraction unifies tasks, workflows, and scans. It is a **generator**:
`for item in runner` yields typed results in real time. This gives live output, pipeability,
and uniform lifecycle/hook/export handling for free.
- *Trade-off*: the base class is large (~1350 lines) and carries a lot of conditional
  state (sync/async, print toggles, chunk state, celery state). A rewrite should keep the
  streaming contract but split responsibilities (execution vs. presentation vs. transport).

### A2. Local/remote parity via one composition model
Sync (eager Celery) and async (worker Celery) run the *same* canvas. Composition is
expressed as chain/group/chord. This means there's one execution semantic to reason about.
- *Why*: pentesters run locally for small jobs and distribute big ones without rewriting.
- *Trade-off*: Celery's eager mode doesn't truly parallelize groups; "sync" is sequential.

### A3. Unified, denormalized, dedup-aware output schema
The product's core. Each finding type is a flat dataclass; a subset of fields
(`compare=True`) defines identity; cross-references are denormalized strings, not object
pointers. Dedup is O(n) by a comparable-field tuple, "newest (or preferred-source) wins."
- *Why*: lets heterogeneous tools merge into one consistent, queryable, exportable model;
  flat records are trivial to serialize/store/diff.
- *Trade-off*: per-type `compare` flags are inconsistent and must be ported exactly;
  denormalization means no referential integrity.

### A4. Declarative tool integration + behavioral hooks
A task is mostly **data** (cmd template, option schema, key/value maps, parsing config,
install metadata) plus a few optional **hook functions**. The engine does the rest
(build cmd, run, parse, install, proxy, chunk).
- *Why*: adding a tool is fast and consistent; the engine centralizes cross-cutting
  concerns.
- *Trade-off*: the option-resolution engine (aliases, key/value maps, sentinels,
  pre/process) is intricate; two output paradigms (streaming vs file) add branches.

### A5. The extractor / dynamic-targets DSL
Workflows wire one tool's results into the next via `targets_`/`<opt>_` extractors with
conditions, instead of hardcoding glue. This is what makes "recon → probe → vuln" flow.
- *Why*: declarative, reusable, condition-gated composition without code.
- *Trade-off*: it relies on Python `eval` of condition strings (sandboxed to `len` +
  a custom `~=`); a rewrite needs a safe expression evaluator (not `eval`).

### A6. Hooks as the universal extension seam
Lifecycle events (`on_init/on_start/on_item/on_end/...`) plus command events
(`on_cmd/on_line/on_cmd_done`) are where tasks customize behavior AND where drivers
(mongodb/api/discord/gcs) plug in persistence/notification. One mechanism, many uses.
- *Why*: keeps the core agnostic; integrations are additive and optional.

### A7. Feature-gated addons, zero-config default
Optional capabilities (worker/redis/mongodb/gdrive/gcs/ai/discord/api/trace) are detected
at import (`ADDONS_ENABLED`) and gated by `CONFIG.addons.*.enabled`. The default broker is
`filesystem://` (no Redis/RabbitMQ needed) and reports persist to the local filesystem.
- *Why*: works out of the box; scales up only when you opt in.

### A8. Auto-install of tools
Missing tools are installed on demand (GitHub release → source → OS packages), controlled
by `security.auto_install_commands`. `secator health` reports versions.
- *Why*: lowers the "40 tools to install" barrier.
- *Trade-off*: security-sensitive (running install commands); gated by config + sudo prompt.

### A9. Workspaces + reports as first-class
Every run writes to `<reports>/<workspace>/<type>s/<id>/` with `.inputs/.outputs`. Reports
are queryable later (`report show`) through a backend-agnostic `QueryEngine` (filesystem /
mongodb / api) with a shared MongoDB-style query dialect.
- *Why*: assessments are long-lived; results need re-querying, dedup across runs, export.

### A10. Pickle-based transport, uuid-list optimization
Celery uses pickle so live `Runner`/`OutputType` objects cross the wire; when MongoDB is
on, only uuid lists move and objects re-hydrate from the DB.
- *Trade-off*: pickle is Python-only and a security/portability liability; a rewrite must
  define an explicit wire format (JSON/protobuf) for findings.

### A11. CLI generated from metadata
Subcommands and options are generated at startup from task classes + YAML templates
(`get_config_options`), including conflict disambiguation and help grouping.
- *Why*: the CLI surface always matches the available tools/workflows with no duplication.
- *Trade-off*: the option-flattening logic is one of the most complex pieces to port.

### A12. AI agent as a first-class, sandboxed runner
The `ai` task is a full autonomous agent (litellm) with a rule-based permission engine,
reversible PII encryption, context-window management, and interactive/remote/auto backends.
It reuses the same Task/Workflow runners and output types.
- *Why*: differentiator; reuses the whole framework as the agent's toolset.
- *Trade-off*: large, optional, provider-dependent; a rewrite can defer it.

---

## Part B — Style choices (coding conventions)

These are observable conventions a rewrite's Python-facing parts (or a faithful port)
should be aware of.

### B1. Formatting
- **Tabs for indentation** (not spaces). `ruff.format` `indent-style = "tab"`.
- **Single quotes** preferred (`ruff.format quote-style = "single"`).
- Line length: flake8 `max-line-length = 120`; ruff `line-length = 200` (long lines are
  common, often with `# noqa: E501`).
- flake8 ignores `W191, E101, E128, E265, W605` (tabs, some indent/comment/regex rules).
- isort multi_line_output=5, line_length=120.

### B2. Data modeling
- **`@dataclass` everywhere** for output types; `field(compare=…, default_factory=…,
  repr=…)` carries semantic metadata (compare = dedup key, repr = console).
- **Pydantic `StrictModel` (`extra='forbid'`)** for app config sections.
- **`DotMap`** for attribute-style dict access (configs, templates, contexts). The
  template loader and the `Config` object both subclass `DotMap`.

### B3. Naming conventions
- Output type `_type` string = snake_case of class name (`get_name()`).
- Internal/meta fields are `_`-prefixed (`_uuid`, `_source`, `_context`, `_timestamp`,
  `_duplicate`, `_related`, `_tagged`).
- Dynamic options/targets use a **trailing underscore** convention (`targets_`,
  `ports_`). Print toggles are `print_*`. Class hook methods are named exactly after the
  event (auto-wired by reflection).
- Sentinel constants: `OPT_NOT_SUPPORTED=-1`, `OPT_PIPE_INPUT=-2`, `OPT_SPACE_SEPARATED=-3`.

### B4. Control flow & extensibility
- **Reflection-based wiring**: hooks/validators registered by attribute name; tasks
  discovered by `__task__` marker; exporters/drivers imported dynamically by name
  (`import_dynamic`).
- **Lazy/local imports** to break circular dependencies (e.g. `from secator.celery
  import ...` inside methods). The module graph is highly interdependent.
- **Generators** as the universal data-production interface (yielders, action handlers,
  serializers, item loaders all yield).
- **`@cache`/`functools.cache`** on discovery/loader functions (tasks, templates).

### B5. Error handling
- Errors are **values, not exceptions** at the boundary: exceptions become `Error`
  output items (`Error.from_exception`); the background `Thread` returns errors from
  `join()`. `raise_on_error` opts back into raising.
- Tool failures parsed heuristically from the last output lines (`parse_errors` regex).

### B6. Presentation
- **Rich markup** embedded in strings throughout (e.g. `[bold green]...[/]`), rendered to
  ANSI via `rich_to_ansi`. Two consoles: `console` (stderr) for UI, `console_stdout`
  (stdout) for piped data — a deliberate separation so UI never pollutes piped output.
- `__rich__()` on output types defines console rendering; `__repr__` = `rich_to_ansi`.
- Emoji/icons per runner type and finding type.

### B7. Configuration ergonomics
- Env override for every key (`SECATOR_<DOTTED_KEY>`), `.env` autoload, partial-config
  persistence, dotted `get/set/unset`.
- Per-task attribute overrides via `CONFIG.tasks.overrides[<ClassName>]`.

### B8. Testing
- A custom test runner (`secator test unit|integration|lint`) wrapping pytest/flake8.
- Fixtures are real tool outputs in `tests/fixtures/<tool>_output.(json|xml|txt)`;
  integration inputs/outputs in `tests/integration/{inputs,outputs}.py`.
- Adding a tool requires a fixture + test entries (documented in CLAUDE.md).

### B9. Known rough edges (carry-or-fix in rewrite)
- `install_pre_cmd` typo (should be `install_cmd_pre`) in `wpscan.py`/`x8.py` — dead config.
- `compare` flags inconsistent across output types (intentional per-type, easy to get
  wrong).
- Heavy use of `eval` for conditions/extractors (sandboxed but still `eval`).
- Pickle serialization across Celery (Python-only, security caveat).
- The base `Runner` mixes execution, transport, and presentation concerns.

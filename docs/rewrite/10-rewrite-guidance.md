# Rewrite Guidance (Rust / Go)

A pragmatic blueprint for porting Secator. It maps each Python subsystem to a
language-agnostic design, flags what *must* be preserved exactly, and suggests a build
order. Read alongside the other files in this directory.

---

## 1. What to preserve exactly (semantic contracts)

These define observable behavior; getting them wrong breaks compatibility with existing
workflows/reports/users.

1. **Output type schemas + dedup keys** (`03-data-model.md`). Port each type's fields and
   its exact `compare=True` set, `__post_init__` normalization, and source-preference
   ordering. `_type` = snake_case of the type name; it is the discriminator and join key.
2. **The dict→record mapper**: `output_map` (string-rename or fn), `output_discriminator`,
   and `load()`'s "all-None ⇒ reject, try next type" rule (`04` §3F).
3. **Option resolution**: alias lookup order, `opt_key_map`/`opt_value_map`,
   `pre_process`/`process`, the three sentinels (`OPT_NOT_SUPPORTED/PIPE_INPUT/
   SPACE_SEPARATED`), flag vs value-flag emission, shlex quoting (`04` §3C/D, `02` §3).
4. **Input wiring**: single vs file vs stdin-pipe; chunking by `input_chunk_size`; the
   `<name>_<n>` chunk source-suffix rule for "own results."
5. **The workflow/scan DSL**: `tasks` ordering, `_group` parallelism, `if:` conditions,
   `targets_`/`<opt>_` extractors (`{type, field, condition, group_by}`, `{nested.key}`
   formatting, `~=` regex operator), profile merging (enforced last), option flattening +
   conflict disambiguation (`05`).
6. **Composition + dedup semantics**: chain/group/chord, result forwarding between steps,
   dedup at the aggregating runner, scope/ancestry tagging so extractors stay in-subtree
   (`07`).
7. **Report data structure** (`{info, results: {type: [items]}}`) and exporter outputs
   (file names, CSV columns = fields, txt = `str(item)`), since people consume these.
8. **Config keys + env override scheme** (`SECATOR_<DOTTED>`), default dirs layout,
   `filesystem://` zero-infra default.
9. **CLI surface**: command names + aliases (`x/w/s`, etc.), global option names
   (`--output/-o`, `--profiles/-pf`, `--workspace/-ws`, `--sync/--worker`, `--json/--raw`,
   `--tree`, `--dry-run`), stdin/pipe + comma-list + file-of-targets ingestion.

## 2. What to redesign (Python-specific or rough)

1. **Transport**: replace Celery+pickle with an explicit composition engine + wire format
   (JSON or protobuf for findings). Keep chain/group/chord semantics, chunking, live
   progress, and local/remote parity. For distributed mode use NATS/Redis/AMQP or a Go
   work-queue; keep a zero-dependency in-process executor as the default.
2. **Condition/extractor evaluation**: replace `eval` with a small safe expression
   evaluator (a real parser/VM, or a vetted expr lib). Support the documented operators
   and `item.<field>`/`opts.<x>`/`targets` namespaces and the `~=` regex op.
3. **Tool/template discovery**: replace import-time reflection with explicit registration
   of built-in tasks + a manifest scan for external ones. Consider expressing tasks as a
   declarative manifest (TOML/YAML) plus optional compiled hooks.
4. **The `Runner` god-object**: split into Execution (run + stream), Orchestration (build
   the DAG/canvas), Transport (local/remote), and Presentation (CLI rendering).
5. **Presentation/markup**: keep stderr(UI)/stdout(data) separation; replace embedded
   rich markup with a structured rendering layer (e.g. a `Renderable` trait).
6. **AI subsystem**: optional, behind a build flag/feature; large and provider-coupled.

## 3. Suggested module decomposition (target codebase)

```
core/
  model/         # output types (structs) + dedup keys + (de)serialization
  runner/        # Runner trait + Command + Python-equiv (native task) impls
  options/       # option schema + resolver (aliases, key/value maps, sentinels)
  parse/         # serializers (json/regex) + dict→record mapper
  dag/           # tree model + chain/group/chord engine + chunking + forwarding
  exec/          # local executor + remote worker client (pluggable transport)
  expr/          # safe condition/extractor evaluator
config/          # typed config (validate) + env overrides + dirs
templates/       # workflow/scan/profile loader + option flattening
tasks/           # built-in tool integrations (declarative + hooks)
drivers/         # mongodb/api/discord/gcs (hook bundles)
exporters/       # json/csv/txt/markdown/table/(gdrive)
providers/       # cve/exploit (circl/vulners/ghsa/exploitdb) + version matching
query/           # backend-agnostic query (fs/mongo/api) + query dialect
installer/       # github-release/source/os-package installers + health
cli/             # dynamic command generation + ingestion + output options
ai/              # optional agent (loop, tools, guardrails, history, encryption)
report/          # aggregation + reports-folder layout + workspaces
ui/              # console/stderr-stdout split, tables, progress, prompts
```

### Trait/interface sketches (illustrative, Rust-flavored)
```
trait Runner {
    fn run(&mut self) -> ResultStream<OutputItem>;   // streaming
    fn config(&self) -> &RunnerConfig;
}
trait OutputType {                 // each finding/exec/stat type
    fn type_name() -> &'static str;            // snake_case discriminator
    fn compare_key(&self) -> CompareKey;       // dedup identity
    fn to_map(&self) -> Map; fn load(m: &Map, map: &OutputMap) -> Result<Self>;
    fn render(&self) -> Renderable;
}
trait Serializer { fn run(&self, line: &str) -> Box<dyn Iterator<Item = Item>>; }
trait Exporter   { fn send(&self, report: &Report) -> Result<()>; }
trait Driver     { fn hooks(&self) -> HookSet; }           // lifecycle hooks
trait QueryBackend { fn search(&self, q:&Query,..) -> Vec<Map>; fn count/update(..); }
trait Provider   { fn lookup_cve(&self, id:&str) -> Option<Vulnerability>; }
// Tasks: a declarative TaskSpec (cmd, opts schema, key/value maps, input wiring,
// parsing config, install meta) + optional Hooks impl.
```

### Concurrency
- Local executor: a worker pool (goroutines / tasks) honoring chain (sequential), group
  (parallel), chord (parallel-then-join) edges. Each task = one subprocess + a monitor
  goroutine (CPU/mem via a psutil-equivalent, enforce memory/timeout, kill the process
  group). Results flow on a channel; dedup at the aggregating runner.
- Remote mode: same DAG, but task execution dispatched over a queue; live status streamed
  back to the CLI (per-node state/progress/incremental findings, throttled).
- Errors as values (a `Result`/error-item on the stream), mirroring `Error.from_exception`.

## 4. Suggested build order (incremental, testable)

1. **Model** — output types + dedup + (de)serialization. Port the data model first; it's
   the spine and the easiest to unit-test against `tests/fixtures/`.
2. **Command runner** — subprocess exec, line streaming, serializers, the dict→record
   mapper, option resolver. Get a few tools (httpx, subfinder, nmap, nuclei) end-to-end.
   Reuse the existing fixtures as golden tests.
3. **Config + templates loader** — typed config, env overrides, YAML workflow/scan/profile
   parsing, the runner tree, option flattening.
4. **DAG engine (local)** — chain/group/chord, chunking, forwarding/dedup, conditions,
   extractors (with the safe expr evaluator). Run a real workflow (host_recon) locally.
5. **CLI** — dynamic command generation, ingestion, output options, `--tree/--dry-run`.
6. **Report + exporters + workspaces + query** — persistence and re-query.
7. **Drivers, providers, installer** — integrations and tool management.
8. **Remote execution** — pluggable transport for distributed mode.
9. **AI subsystem** — last, optional.

At each step, validate against the Python implementation's behavior using the existing
fixtures and integration inputs/outputs (`tests/integration/{inputs,outputs}.py`).

## 5. Risk register (where ports go wrong)

- **Per-type `compare` flags** — inconsistent by design; mis-porting silently breaks
  dedup. Cross-check every type against `03-data-model.md`.
- **Option resolution edge cases** — aliasing, sentinels, value-flag vs flag, list-repeat,
  `internal` opts, shlex quoting. Table-test against real generated command strings.
- **Extractor semantics** — scope/ancestry filtering, `group_by`, `{nested.key}`, `~=`.
  Without the scope rules, tasks consume the wrong subtree's results.
- **Sync ≠ parallel** — Celery eager mode runs groups sequentially; if the rewrite
  parallelizes "sync" it may change observed ordering/behavior some workflows rely on.
- **Stdout/stderr discipline** — piping breaks if UI bleeds into stdout. Keep the split.
- **Auto-install + sudo + security toggles** — preserve the gates
  (`security.auto_install_commands`, `prompt_sudo_password`, `allow_local_file_access`).

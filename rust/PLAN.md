# secator-rs — Architecture Plan

The rewrite target. Read `../docs/rewrite/` first for the analysis of the Python
implementation; this plan assumes that context and focuses on the Rust design and the
decisions taken.

Locked decisions: **Tokio** async runtime · **distributed from day one** (local + remote
parity behind a `Transport` trait, Redis Streams default) · **MVP** = subfinder/httpx/
nmap/nuclei + `host_recon` + json/csv/txt exporters.

---

## 1. Design goals & non-negotiables

1. **Behavioral compatibility** with the Python tool where it's observable: output schema
   + dedup keys, the workflow/scan DSL, report layout, CLI surface, config keys. (See
   `../docs/rewrite/10-rewrite-guidance.md` §1 — "preserve exactly".)
2. **Streaming everywhere**: a runner produces typed results as a stream; the CLI renders
   them live and pipes raw data on stdout.
3. **Local/remote parity**: the same DAG runs in-process or across workers; choosing the
   transport is a config switch, not a code change.
4. **Declarative tasks**: integrating a tool is mostly data (a `TaskSpec`) + optional
   hooks; the engine does build/run/parse/install/proxy/chunk.
5. **Safe by construction**: no `eval` (a real expression VM), explicit wire format (no
   pickle), typed config.
6. **Zero-config local default**: works with no broker/DB; remote infra is opt-in.

## 2. Workspace & crate graph

Crates are small and layered; dependencies point downward only (acyclic).

```
                        secator-cli (bin)
                              │  (depends on most)
        ┌─────────────┬───────┼─────────┬───────────────┐
   secator-exec   secator-templates  secator-report  secator-ui
        │              │                   │
   secator-dag     secator-expr       secator-exporters
        │                                  │
   secator-runner ───────────────┐        │
     │     │        │            │         │
  secator-options secator-parse  └─────────┴──► secator-model
                       │                              ▲
                       └──────────────────────────────┘
   secator-tasks ──► secator-runner, secator-model, secator-options, secator-parse
   secator-config (leaf; used by cli/exec/templates)
```

| Crate | Maps to (Python) | Responsibility |
|---|---|---|
| `secator-model` | `output_types/` | Finding/exec/stat structs, `OutputType` trait, dedup `CompareKey`, (de)serialization. **The spine.** |
| `secator-expr` | `eval` in `workflow.py`/`_helpers.py` | Safe parser+evaluator for `if:` conditions & extractor conditions (`opts.x`, `item.f`, `~=`, `and/or`, `len`). |
| `secator-options` | option engine in `command.py` | Option schema, alias resolution, key/value maps, sentinels, command-string assembly. |
| `secator-parse` | `serializers/`, `_convert_item_schema` | JSON/Regex serializers, the dict→record mapper (`output_map`/discriminator/`load`). |
| `secator-runner` | `runners/` | `Runner` trait; `CommandRunner` (subprocess) + `NativeRunner` (PythonRunner-equiv); hooks/validators. |
| `secator-dag` | `tree.py` + `build_celery_workflow` | Runner tree, chain/group/chord composition, chunking, result forwarding, extractor wiring. |
| `secator-exec` | `celery.py`, `celery_utils.py` | Executor + `Transport` trait; `LocalTransport` (in-process) + `RemoteTransport` (Redis Streams); live progress. |
| `secator-config` | `config.py` | Typed config, env overrides (`SECATOR_*`), dirs layout, addon gating. |
| `secator-templates` | `template.py`, `loader.py` | Load workflow/scan/profile YAML, build the tree, flatten options + conflict resolution. |
| `secator-tasks` | `tasks/` | Built-in tool integrations. MVP: subfinder, httpx, nmap, nuclei. |
| `secator-report` | `report.py` | Aggregate results into the report data structure; workspaces / reports folder. |
| `secator-exporters` | `exporters/` | `Exporter` trait + json/csv/txt (table/markdown/gdrive later). |
| `secator-ui` | `rich.py` | Console (stderr UI / stdout data split), tables, progress, prompts. |
| `secator-cli` | `cli.py`, `cli_helper.py` | Binary; dynamic command/option generation; ingestion; output options. |

Later crates (post-MVP): `secator-drivers` (mongodb/api/discord/gcs hooks),
`secator-providers` (cve/exploit), `secator-query` (fs/mongo/api), `secator-installer`,
`secator-ai`.

## 3. Core abstractions (target API)

These are sketched in the crate skeletons; final signatures firm up in M1–M3.

```rust
// secator-model
pub trait OutputType {
    fn type_name() -> &'static str where Self: Sized;   // snake_case discriminator
    fn compare_key(&self) -> CompareKey;                 // dedup identity (per-type field subset)
    fn to_map(&self) -> Map;
    fn load(m: &Map, map: &OutputMap) -> Result<Self> where Self: Sized; // all-None ⇒ Err
    fn render(&self) -> Renderable;
}
pub enum OutputItem { Url(Url), Port(Port), Vulnerability(Vulnerability), /* … */ Info(Info), Error(Error), Target(Target) }

// secator-runner
pub struct RunCtx { /* targets, opts, context(ancestor_id, scope, …), toggles */ }
#[async_trait-ish]                       // async fn in trait
pub trait Runner {
    async fn run(&mut self, ctx: &RunCtx, tx: ResultSink);   // streams OutputItem via tx
    fn config(&self) -> &RunnerConfig;
}

// secator-parse
pub trait Serializer { fn run<'a>(&self, line: &'a str) -> Box<dyn Iterator<Item = Item> + 'a>; }

// secator-exec
pub trait Transport {           // local/remote parity
    async fn submit(&self, unit: WorkUnit) -> Handle;       // run one task over a chunk
    async fn poll(&self, h: &Handle) -> ProgressUpdate;     // live state/progress/results
}
pub struct LocalTransport;      // in-process worker pool (Tokio tasks)
pub struct RemoteTransport;     // Redis Streams consumer groups

// secator-exporters
pub trait Exporter { fn send(&self, report: &Report) -> Result<()>; }
```

`ResultSink` = a Tokio mpsc sender of `OutputItem`; the CLI consumes the receiver and
renders/pipes. Errors are values: an `OutputItem::Error` on the stream (mirrors
`Error.from_exception`), with a `raise_on_error` mode for fail-fast.

## 4. Distributed model (from day one)

- **DAG** (`secator-dag`) compiles a workflow/scan into a graph of `WorkUnit`s with
  chain (sequential), group (parallel), chord (parallel-then-join) edges — the same three
  primitives Celery uses.
- **Transport** (`secator-exec`) executes the DAG. Two impls behind one trait:
  - `LocalTransport`: a Tokio task pool; zero infra; the default.
  - `RemoteTransport`: **Redis Streams** with consumer groups as the work queue + a
    results channel; workers (`secator worker`) consume units, run them, and publish
    typed results + progress. (NATS JetStream is the documented alternative — same trait.)
- **Wire format**: `OutputItem` serializes via serde (JSON by default; bincode/msgpack
  optional) — explicit, language-neutral, no pickle. Large result sets can move as id
  lists rehydrated from a store (the MongoDB optimization), once `secator-query` lands.
- **Chunking**: a `CommandRunner` over many targets with no file-input flag is split into
  chunks (`input_chunk_size`), rate-limit divided, executed as a chord. Chunk results are
  attributed to the parent via the `<name>_<n>` source-suffix rule.
- **Live progress**: per-unit state/progress/incremental results stream back to the CLI,
  throttled (mirrors `CeleryData.iter_results`).

## 5. Data flow (end-to-end, target)

```
cli  →  parse args (clap, dynamically built from tasks+templates)
     →  ingest targets (stdin/pipe / file / comma-list)
     →  build Runner (Task/Workflow/Scan) from config
     →  exec: compile DAG → submit via Transport (local pool or Redis)
              each WorkUnit = CommandRunner: build cmd (options) → spawn subprocess
              → stream stdout lines → serializers → dict→record mapper → OutputItem
     →  results stream: dedup at aggregating runner, forward between steps,
              run lifecycle/driver hooks, update progress
     →  ui renders live (stderr) / pipes raw (stdout)
     →  report: aggregate → exporters write json/csv/txt under reports/<ws>/<type>/<id>/
```

## 6. Dependencies

Declared per-crate as implementation begins (the scaffold is std-only so it builds
offline). Intended choices:

| Concern | Crate |
|---|---|
| async runtime | `tokio` (rt-multi-thread, process, macros, sync, time) |
| serialization | `serde`, `serde_json`, `serde_yaml` (templates/config), optional `rmp-serde` |
| CLI | `clap` (derive + dynamic `Command` building) |
| terminal UI | `ratatui`/`crossterm` or `comfy-table` + `indicatif` (TBD in ADR-0007) |
| errors | `thiserror` (libs), `anyhow` (bin) |
| HTTP | `reqwest` (providers, installer, api driver) |
| redis transport | `redis` (aio + streams) |
| process stats | `sysinfo` (CPU/mem, kill — psutil-equivalent) |
| regex | `regex` |
| versions/CVE | `semver`, a CPE parser (or hand-rolled) |
| expr eval | hand-rolled small parser (no `eval`); or `evalexpr` if it fits |
| tracing/debug | `tracing` + `tracing-subscriber` |
| YAML | `serde_yaml` |

## 7. Testing strategy

- **Golden tests against the Python fixtures**: reuse `tests/fixtures/<tool>_output.*` and
  `tests/integration/{inputs,outputs}.py` to verify parsers + the dict→record mapper +
  dedup produce identical findings. This is the primary correctness anchor.
- **Unit tests** per crate (option resolution, expr evaluator, dedup keys, DAG shapes).
- **Integration**: run a real `host_recon` locally end-to-end (M4) and via Redis (M5).
- CI: `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`.

## 8. Open questions (tracked as ADRs)

- Exact terminal-UI stack (ADR-0007).
- Whether to express built-in tasks as Rust code or a declarative manifest loaded at
  build/runtime (ADR-0006 leans: Rust structs for built-ins, manifest for external).
- NATS vs Redis as the long-term default transport (ADR-0003: Redis default, revisit).
- CPE/CVE version-matching: port `cve.py` logic vs. use an existing crate.

See `ROADMAP.md` for sequencing.

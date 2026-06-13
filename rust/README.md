# secator-rs

A ground-up **Rust rewrite** of [secator](https://github.com/freelabz/secator) — the
task & workflow runner for security assessments.

This folder is the rewrite's home. It currently contains the **plan** and a **compiling
cargo workspace scaffold** (crate skeletons with trait/type definitions and `todo!()`
bodies — no real logic yet). It builds with `cargo check`.

## Where to start

| Doc | Purpose |
|---|---|
| [PLAN.md](PLAN.md) | Architecture, crate graph, mapping from the Python codebase, key decisions. |
| [ROADMAP.md](ROADMAP.md) | Milestones M0–M9 with concrete deliverables and exit criteria. |
| [docs/adr/](docs/adr/) | Architecture Decision Records (runtime, transport, data model, etc.). |
| `../docs/rewrite/` | The full analysis of the Python implementation this rewrite is based on. |

## Foundational decisions (locked)

- **Language/runtime**: Rust + **Tokio** (async/await). See [ADR-0002](docs/adr/0002-async-runtime.md).
- **Distributed from day one**: local + remote parity behind a `Transport` trait; default
  remote broker **Redis Streams**, NATS JetStream as documented alternative. See
  [ADR-0003](docs/adr/0003-distributed-transport.md).
- **MVP tool set**: `subfinder`, `httpx`, `nmap`, `nuclei` + the `host_recon` workflow +
  `json`/`csv`/`txt` exporters. See [ADR-0006](docs/adr/0006-task-definition.md).

## Layout

```
rust/
  Cargo.toml          # workspace
  PLAN.md ROADMAP.md
  docs/adr/           # decision records
  crates/
    secator-model         # output types + dedup + serde      (← output_types/)
    secator-expr          # safe condition/extractor evaluator (← eval in workflow/_helpers)
    secator-options       # option schema + resolver           (← command.py option engine)
    secator-parse         # serializers + dict→record mapper   (← serializers/, _convert_item_schema)
    secator-runner        # Runner trait + Command + native    (← runners/)
    secator-dag           # tree + chain/group/chord engine     (← tree.py + build_celery_workflow)
    secator-exec          # executor + Transport (local+redis)  (← celery.py)
    secator-config        # typed config + env overrides        (← config.py)
    secator-templates     # workflow/scan/profile loader        (← template.py, loader.py)
    secator-tasks         # built-in tool integrations (MVP×4)  (← tasks/)
    secator-report        # report aggregation + workspaces     (← report.py)
    secator-exporters     # json/csv/txt (+later)               (← exporters/)
    secator-ui            # console / tables / progress         (← rich.py)
    secator-cli           # binary; dynamic command generation  (← cli.py, cli_helper.py)
```

## Building

```sh
cd rust
cargo check        # the scaffold compiles (std-only at this stage)
```

Dependencies (tokio, serde, clap, redis, …) are declared per-crate as implementation
begins; the scaffold is intentionally dependency-light so it builds offline. See
[PLAN.md §Dependencies](PLAN.md#dependencies).

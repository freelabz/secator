# ADR-0006: Task definition strategy & MVP scope

**Status:** Accepted

## Context
A task is mostly declarative (cmd template, option schema, key/value maps, input wiring
sentinels, parsing config, install metadata) plus optional hook functions
(`../docs/rewrite/04-task-integration.md`). Python discovers tasks by importing modules and
checking a `__task__` marker — not portable to Rust. We also chose an MVP of 4 tools.

## Decision
- **Built-in tasks = Rust code.** Each is a value implementing the task contract: a
  `TaskSpec` struct (declarative fields) + an optional `Hooks` impl (the behavioral
  overrides: `on_cmd`, `on_line`, `on_item`, `on_cmd_done`, validators, …). Register them
  in a static table in `secator-tasks` (no reflection). This keeps hooks as real,
  type-checked Rust.
- **External tasks = declarative manifest** (YAML/TOML describing a `TaskSpec`) loaded from
  the templates dir, for the common case of "wrap a tool with no custom logic." Manifests
  can't carry arbitrary hooks; tools needing hooks ship as a built-in or a plugin (future).
- Model the option schema, the three input sentinels (`OPT_NOT_SUPPORTED/PIPE_INPUT/
  SPACE_SEPARATED`), `opt_key_map`/`opt_value_map`, and the dict→record mapper
  (`output_map`/discriminator/`load`) faithfully (ADR-0004, `secator-options`/`secator-parse`).
- `profile` (queue/resource class) may be a constant or a closure of opts — model as an
  enum `Profile { Const(Queue), Dynamic(fn(&Opts)->Queue) }`.

## MVP tool set (chosen by maintainer)
`subfinder` (passive subdomains, JSONL), `httpx` (HTTP probe, JSONL), `nmap` (XML
file-output + NSE), `nuclei` (vuln, severity discriminator + multi-class output_map),
wired by the **`host_recon`** workflow, exported via **json/csv/txt**. These four exercise
every parsing paradigm (streaming JSON, file-output XML, discriminator-based typing) and
the extractor flow (ports→httpx targets), so they validate the whole pipeline.

## Consequences
- Adding a built-in tool is a struct + (maybe) a small hook impl + a golden test — fast
  and type-safe.
- The declarative manifest path covers simple external tools without recompiling.
- Hooks-with-logic external tools need a plugin mechanism (deferred; out of MVP scope).

## Alternatives considered
- *Everything as a manifest + a scripting language for hooks*: flexible but reintroduces a
  sandbox/`eval` problem and weakens type-checking; rejected for built-ins.
- *Codegen tasks from the Python definitions*: brittle; rejected. We hand-port the MVP set
  and grow the catalog in M7.

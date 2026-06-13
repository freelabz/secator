# Secator — Architecture & Rewrite Reference

A thorough analysis of the Secator codebase (Python, ~29k LOC) intended to be re-used as
the reference for a complete **Rust or Go rewrite**. It documents the architecture,
features, design choices, and style choices, plus exact behavioral contracts a port must
reproduce.

Analysis basis: the `secator/` package at commit on branch `main` (v0.32.0). Files cite
real source paths so claims can be verified against the code.

## Read in this order

| # | File | What it covers |
|---|---|---|
| 01 | [Overview & Features](01-overview-features.md) | What Secator is, the conceptual model (task/workflow/scan/profile/driver/exporter/provider/workspace), headline features, dependency footprint. |
| 02 | [Architecture](02-architecture.md) | The `Runner` abstraction, execution lifecycle, the `Command` engine, hooks/validators, dedup, distributed execution overview, the extractor/dynamic-targets system, end-to-end data flow, concurrency. |
| 03 | [Data Model](03-data-model.md) | The unified output schema: `OutputType` base, every finding/execution/stat type with fields and dedup keys, relationships, and the deduplication algorithm. **The schema spec.** |
| 04 | [Task Integration](04-task-integration.md) | How tools are wrapped: category hierarchy, the full declarative contract (options, mapping, parsing, install, proxy, profiles), hooks/validators, and the catalog of ~50 tasks. |
| 05 | [Config & Templates](05-config-templates.md) | App config (pydantic + env), template loading/discovery, the runner tree, and the YAML workflow/scan/profile DSL (conditions + extractors), CLI option flattening. |
| 06 | [CLI](06-cli.md) | The rich-click CLI, dynamic command/option generation, request handling, ingestion (stdin/pipe/file), utility commands. |
| 07 | [Distribution](07-distribution.md) | Celery app, registered tasks, building the chain/group/chord canvas, chunking, live progress, sync vs async, and rewrite guidance for the transport. |
| 08 | [Subsystems](08-subsystems.md) | Exporters, drivers (hooks), providers, query, serializers, installer, tree, the AI agent, `cve.py`/`report.py`, and misc (thread/requests/rich). |
| 09 | [Design & Style Choices](09-design-style-choices.md) | The *why* behind the architecture (12 design choices with trade-offs) and the coding conventions/style (formatting, naming, error handling, presentation, known rough edges). |
| 10 | [Rewrite Guidance](10-rewrite-guidance.md) | What to preserve exactly vs. redesign, a target module decomposition + trait sketches, a build order, and a risk register. |

## TL;DR of the architecture

- Everything that executes is a streaming **`Runner`** (Task ⊂ Workflow ⊂ Scan;
  `Command`/`PythonRunner` do the work). Iterating a runner yields typed results live.
- Every tool's output is normalized into a small set of **`OutputType`** dataclasses with
  per-type dedup keys, denormalized string references, and consistent
  serialize/sort/export/stream behavior.
- Tools are integrated **declaratively** (option schema + parsing config + install
  metadata) plus optional **hooks**; the engine builds the command, runs it, parses and
  types the output, installs missing tools, handles proxy/chunking.
- Workflows/scans are **YAML DAGs** with `if:` conditions and `targets_`/`<opt>_`
  extractors that flow one tool's results into the next.
- Execution composes into Celery **chain/group/chord** canvases that run identically
  in-process (sync/eager) or across **workers** (async), with chunking, result
  forwarding/dedup, and live progress.
- Around the core: pluggable **exporters** (report formats), **drivers** (persistence/
  notify hooks), **providers** (CVE enrichment), a backend-agnostic **query** layer, an
  **installer**, and an optional autonomous **AI** agent.

See [10-rewrite-guidance.md](10-rewrite-guidance.md) for the port blueprint.

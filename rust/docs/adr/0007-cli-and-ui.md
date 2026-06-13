# ADR-0007: CLI framework & terminal UI

**Status:** Accepted (CLI = clap); terminal-UI stack provisional

## Context
The Python CLI (rich-click) generates task/workflow/scan subcommands and their options
**dynamically** at startup from task classes + YAML templates, with conflict
disambiguation and help grouping (`../docs/rewrite/06-cli.md`). It also relies on a strict
stdout(data)/stderr(UI) split for piping, plus live progress panels, trees, and tables.

## Decision
- **CLI: `clap`.** Build the root commands statically (`task/x`, `workflow/w`, `scan/s`,
  `worker`, `config`, `report`, `health`, `install`, …) and **dynamically register**
  per-task/workflow/scan subcommands + their flattened options at startup using clap's
  builder (`Command`/`Arg`) API. The hard part is porting `get_config_options`
  (option flattening + conflict resolution + help grouping) into `secator-templates`, not
  the clap wiring.
- **Ingestion**: replicate stdin/pipe detection, comma-list expansion, and
  file-of-targets, preserving the `--sync/--worker` auto-detect and `--tree/--dry-run/
  --yaml` introspection.
- **stdout/stderr split** is mandatory: a `secator-ui` layer renders UI to **stderr** and
  pipes raw data to **stdout** (mirrors the two-console design), so `secator x subfinder |
  secator x httpx` works.
- **Terminal UI stack: provisional.** Start with `comfy-table` (tables) + `indicatif`
  (progress/live) + `crossterm` (capabilities/prompts); reserve `ratatui` for richer live
  panels if needed. Replace Python's embedded rich-markup strings with a structured
  `Renderable` produced by each `OutputType::render`.

## Consequences
- The CLI surface stays auto-derived from available tools/templates (no duplication), as
  today.
- Option flattening/disambiguation is a notable chunk of work (`secator-templates`),
  independent of the UI choice.
- The UI crate choice can change without touching the engine, since rendering is behind
  `Renderable`/`secator-ui`.

## Alternatives considered
- *Hand-rolled arg parsing*: rejected — clap gives help/completion/validation for free.
- *Commit to `ratatui` now*: heavier than needed for v1's mostly-streaming output; defer.
- *Keep rich-style markup strings*: rejected — structured rendering is cleaner and testable.

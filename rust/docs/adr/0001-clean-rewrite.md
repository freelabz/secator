# ADR-0001: Clean rewrite in Rust (not a port)

**Status:** Accepted

## Context
The Python implementation has a large `Runner` god-object mixing execution/transport/
presentation, `eval`-based conditions, pickle-over-Celery transport, and import-time
reflection for discovery. These are productive in Python but are poor fits for a Rust
design and limit portability/perf. We have a thorough analysis of the current behavior in
`../docs/rewrite/`.

## Decision
Do a **clean rewrite** that preserves *observable behavior* (output schema + dedup keys,
the workflow/scan DSL, report layout, CLI surface, config keys) but is free to redesign
internals. Use the Python implementation as an executable specification and its test
fixtures as golden tests — not as code to translate line-by-line.

## Consequences
- We keep the parts users/tools depend on (`../docs/rewrite/10-rewrite-guidance.md` §1).
- We redesign transport (no pickle), conditions (no `eval`), discovery (explicit
  registration), and split the `Runner` into layered crates.
- Migration is incremental and milestone-gated (`ROADMAP.md`); the Python tool stays
  runnable for side-by-side diffing.

## Alternatives considered
- *Mechanical transliteration*: rejected — would import the Python design's weaknesses.
- *Incremental Rust extensions to the Python codebase (PyO3)*: rejected — doesn't deliver
  a standalone native tool, the actual goal.

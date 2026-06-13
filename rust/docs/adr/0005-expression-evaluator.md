# ADR-0005: Expression evaluator (no `eval`)

**Status:** Accepted

## Context
The workflow/scan DSL evaluates strings at runtime in Python via `eval` with a restricted
`__builtins__` (`len`) and a custom `~=` regex operator
(`../docs/rewrite/05-config-templates.md` §4, `02-architecture.md` §8):
- node `if:` conditions — namespace `{opts, targets}`.
- extractor `condition`s — namespace `{item, <type>, opts, targets}`, plus `~=`.

Rust has no `eval`; we also don't *want* arbitrary code execution from templates.

## Decision
Implement a **small safe expression language** in `secator-expr`: a hand-written
tokenizer + Pratt parser + tree-walking evaluator over a typed `Value` (bool/int/float/
str/list/map/null). Supported surface (matching current template usage):
- literals, identifiers, member access `a.b.c`, indexing.
- comparisons `== != < <= > >=`, membership `in`, boolean `and/or/not` (and `&&`/`||`).
- the `len(x)` function (allow-listed; extensible function table).
- the `~=` regex-match operator (`value ~= pattern`).
- variables injected by the engine: `opts`, `targets`, `item`, and the type alias
  (`port`, `url`, …).

No attribute calls beyond the allow-list; no I/O; no Python semantics leakage.

## Consequences
- Templates are safe to load from untrusted-ish sources; no RCE via conditions.
- We must reproduce a few Python truthiness/coercion quirks the existing templates rely on
  (empty list falsy, string membership, etc.) — pinned by a condition test suite ported
  from real workflow conditions.
- Slightly more code than reusing a crate, but full control over the operator set
  (notably `~=`) and error messages.

## Alternatives considered
- *`evalexpr`/`rhai`/`mlua` crates*: usable, but bring their own grammar/semantics; mapping
  `~=` and matching Python truthiness is friction. Revisit if the hand-rolled evaluator
  grows unwieldy.
- *Compile conditions to a precomputed form at load*: optimization for later; not needed
  for v1.

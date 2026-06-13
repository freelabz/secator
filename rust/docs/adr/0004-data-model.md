# ADR-0004: Data model & serialization

**Status:** Accepted

## Context
The unified output schema is the product's core (`../docs/rewrite/03-data-model.md`).
Python uses dataclasses where a per-type subset of fields (`compare=True`) defines
identity; cross-references are denormalized strings; dedup is O(n) by a comparable-field
tuple with "newest/preferred-source wins". Instances are unhashable; `_type` (snake_case
of the class) is the discriminator.

## Decision
- Model each finding/execution/stat type as a **struct** in `secator-model`; collect them
  in an `OutputItem` enum (tagged by `_type` on the wire).
- Encode the **dedup key per type explicitly** as `compare_key(&self) -> CompareKey`
  (a hashable tuple/`Vec` of the comparable fields), matching each Python type's
  `compare=True` set **exactly** (they are deliberately inconsistent across types).
- Keep references **denormalized** (string FKs: `Port.ip`, `Vulnerability.matched_at`,
  `Url.tech`), as today. No embedded object graph.
- Port `__post_init__` normalization (e.g. `Url` deriving host/protocol/verified;
  `Vulnerability` severity↔cvss + ordinal maps) into constructors/`From` impls.
- **Serialization via serde** (no pickle): `to_map`/`load` mirror Python's
  `toDict`/`load(item, output_map)` including the `output_map` (rename or fn) and the
  "all-None ⇒ reject" rule. JSON is the canonical format; `_type` is the join key for
  reconstruction.
- Ordering/dedup: implement the "equal ⇒ newest by timestamp, with source preference
  (Url→httpx, Port→nmap)" comparison; provide `remove_duplicates` and the workflow-level
  `mark_duplicates` (group by `compare_key`, mark losers `_duplicate`, fill `_related`).

## Consequences
- Flat, serde-friendly records: trivial to store/diff/export/stream and to send over the
  transport.
- The per-type `compare_key` is a correctness hotspot — covered by golden tests vs the
  Python fixtures.
- Internal meta fields (`_uuid`, `_source`, `_context`, `_timestamp`, `_duplicate`,
  `_related`, `_tagged`) live on each record (or a shared `Meta` substruct); only the
  documented subset participates in `compare_key`.

## Alternatives considered
- *Real referential graph instead of string FKs*: cleaner in theory, but the dedup keys
  and exporters assume denormalized records; rejected for compatibility.
- *A single dynamic `Map` instead of typed structs*: loses Rust's type safety and the
  per-type rendering/dedup; rejected.

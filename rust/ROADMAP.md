# secator-rs — Roadmap

Milestones are vertical where possible (each ends with something runnable/testable).
Correctness is anchored to the Python implementation via its existing fixtures.

Legend: 🎯 exit criteria.

---

## M0 — Scaffold & decisions  ✅ (this commit)
- Cargo workspace, crate skeletons (compiling), PLAN/ROADMAP/ADRs.
- 🎯 `cargo check` passes; architecture + decisions documented.

## M1 — Data model (`secator-model`)
- Port every `OutputType` (findings + execution + stat) with exact fields and
  **`compare=True` dedup keys**; `__post_init__` normalization; serde (de)serialization;
  the `OutputType` trait; `CompareKey`; `OutputItem` enum; reconstruction by `_type`.
- Port dedup: `compare_key` grouping + "newest/preferred-source wins" + `remove_duplicates`.
- 🎯 Round-trip + dedup unit tests; load Python `report.json` fixtures and re-emit identically.

## M2 — Command runner + parsing (`secator-runner`, `secator-options`, `secator-parse`)
- `CommandRunner`: build command string from an option schema (aliases, key/value maps,
  the three sentinels, shlex quoting, flag vs value); input wiring (arg/stdin/file);
  spawn subprocess (Tokio), stream stdout lines; process monitor (sysinfo: mem/timeout/kill).
- Serializers (JSON/Regex) + the dict→record mapper (`output_map`/discriminator/`load`,
  incl. "all-None ⇒ try next type").
- 🎯 Run subfinder + httpx locally, parse to `OutputItem`s matching the fixtures.

## M3 — Native runner, hooks, config, expr (`secator-runner`, `secator-config`, `secator-expr`)
- `NativeRunner` (no subprocess); the hook/validator registry + lifecycle events.
- Typed config + `SECATOR_*` env overrides + dirs layout.
- Safe expression evaluator for `if:`/extractor conditions (`opts`, `item`, `targets`,
  `len`, `and/or`, comparisons, `~=` regex). **No `eval`.**
- 🎯 Hooks fire; config loads + overrides; expr evaluator passes a condition test suite.

## M4 — DAG engine + local execution (`secator-dag`, `secator-exec`, `secator-templates`)
- Runner tree from YAML; chain/group/chord composition; chunking; result forwarding/dedup;
  extractor wiring (`targets_`/`<opt>_`, scope/ancestry filtering).
- `Transport` trait + `LocalTransport` (Tokio pool). Template loader + option flattening.
- 🎯 Run `host_recon` end-to-end **locally** over the 4 MVP tools (nmap XML + nuclei
  discriminator included), producing deduped findings.

## M5 — Distributed execution (`secator-exec`)
- `RemoteTransport` (Redis Streams consumer groups) + `secator worker`; serde wire format;
  live progress streaming back to the client; revoke/cancel.
- 🎯 Same `host_recon` runs across ≥2 workers with live progress; results identical to M4.

## M6 — CLI, report, exporters, UI (`secator-cli`, `secator-report`, `secator-exporters`, `secator-ui`)
- Dynamic command/option generation from tasks+templates; ingestion (stdin/pipe/file/
  comma-list); `--tree/--dry-run/--yaml`; sync/worker auto-detect; output options.
- Report aggregation + reports-folder/workspace layout; json/csv/txt exporters; live UI
  (stderr) vs piped data (stdout).
- 🎯 `secator x|w|s` UX parity with the Python CLI for the MVP set; reports on disk match.

## M7 — Tool breadth
- Expand `secator-tasks` toward the full ~50-tool catalog (categories: http/recon/vuln/
  crawl/fuzz/secret/…); more workflows/scans/profiles; table/markdown exporters.
- 🎯 Top ~20 tools + the common workflows/scans run with parity.

## M8 — Integrations
- `secator-drivers` (mongodb/api/discord/gcs hook bundles), `secator-providers`
  (circl/vulners/ghsa/exploitdb + version matching from `cve.py`), `secator-query`
  (fs/mongo/api + query dialect), `secator-installer` (github-release/source/os-package),
  `secator health`.
- 🎯 Persistence + CVE enrichment + tool install/health working.

## M9 — AI agent (optional) & polish
- `secator-ai`: agent loop, tool schemas, permission/guardrail engine, history/context
  management, PII encryption, interactivity backends. Behind a feature flag.
- Full tool parity, gdrive exporter, packaging/release, docs.
- 🎯 Feature parity sufficient to deprecate the Python CLI for covered use cases.

---

## Sequencing notes
- M1→M2→M3 are the foundation and the highest-value golden-test surface; do them carefully.
- M4 proves the composition engine locally before M5 adds the network — even though
  "distributed from day one" is the goal, the local executor is the reference behavior the
  remote one must match.
- Keep the Python repo runnable side-by-side and diff outputs at every milestone.

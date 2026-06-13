# Python ↔ Rust JSON report comparison

Snapshot: 2026-06-13. Side-by-side `report.json` outputs from
the same task / workflow run on both runtimes. Method:

```bash
DEMO=/tmp/secator-parity-<ts>; mkdir -p $DEMO/py $DEMO/rs
SECATOR_DIRS_DATA=$DEMO/py secator task jswhois example.com
SECATOR_DIRS_DATA=$DEMO/rs /…/rust/target/release/secator task jswhois example.com
```

Two runs compared:
1. `secator task jswhois example.com` — single command-task path
2. `secator workflow url_crawl https://example.com -pf passive` — workflow + extractor + profile

---

## Result: ~90% schema parity, 7 discrepancies (4 bugs, 3 documented additions)

### 1. Top-level keys
| Key | Python | Rust |
|---|:-:|:-:|
| `info` | ✅ | ✅ |
| `results` | ✅ | ✅ |

### 2. `info` keys

| Key | Python | Rust | Notes |
|---|:-:|:-:|---|
| `context` | ✅ | ✅ | Rust populates `{}` on task runs (bug #B-INFO-CONTEXT) |
| `elapsed`, `elapsed_human` | ✅ | ✅ | |
| `start_time`, `end_time` | ✅ | ✅ | Python uses ISO-8601; Rust uses unix seconds (cosmetic drift) |
| `errors` | ✅ | ✅ | |
| `name`, `targets`, `status`, `title` | ✅ | ✅ | `title` cosmetic drift: Python uses `task_<name>` / `workflow_<name>`, Rust uses the spec description |
| `run_opts` | ✅ | ✅ | **bug #B-INFO-OPTS**: Rust returns `{}` instead of the resolved opts |
| `errors_count` | ➖ | ✅ | Rust-only extra (documented) |
| `results_count` | ➖ | ✅ | Rust-only extra |
| `task_name` | ➖ | ✅ | Rust-only extra |
| `workspace` | ➖ | ✅ | Rust-only extra (Python keeps it in `context.workspace_name`) |

### 3. `results.<type>` buckets (14 finding types + target)

| Bucket | Python | Rust |
|---|:-:|:-:|
| ai · certificate · domain · exploit · ip · port · record · subdomain · tag · target · technology · url · user_account · vulnerability | ✅ | ✅ |

All 14 bucket keys match exactly.

### 4. Per-item schema (`results.tag[0]`, etc.)

Every typed item carries the same 17 fields on both sides: `_context, _duplicate, _related, _source, _tagged, _timestamp, _type, _uuid` (meta) + the type-specific fields (`category, extra_data, is_acknowledged, is_false_positive, match, name, stored_response_path, tags, value` for `Tag`; etc.).

**Per-item VALUE drift on `secator task X` (bug #B-TASK-META):**

| Field | Python value | Rust value |
|---|---|---|
| `_source` | `"jswhois"` | `""` |
| `_timestamp` | unix epoch float | `0.0` |
| `_uuid` | UUID v4 | `""` |
| `_context` | populated with workspace, worker, drivers, celery_id, ancestor_id | `{}` |

For workflow / scan runs, Rust's `tag_meta` populates `_source` + `_context.{ancestor_id,node_id}` correctly — the gap is specific to single-task invocations.

### 5. Behavior-level drift (workflow run)

**Run**: `workflow url_crawl https://example.com -pf passive`

| Aspect | Python | Rust | Notes |
|---|:-:|:-:|---|
| URLs returned | 4714 | 0 | **bug #B-WF-PASSIVE**: Rust's expression evaluator returns `false` for `'xurlfind3r' in opts.crawlers and opts.passive`; Python returns `true` and runs xurlfind3r. Likely cause: `in` list-membership not honored, or `passive` not propagated from `--pf passive` profile through workflow inheritance. |
| `Target` items emitted | 2 | 0 | **bug #B-TARGET-EMIT**: Python emits a `Target` per CLI input (one for the raw input, one for the workflow-wrapped form); Rust doesn't emit any. |
| `report.json` written when zero findings | ✅ | ❌ | **bug #B-EMPTY-REPORT**: Python writes the report even when results are empty (so drivers + the run-folder structure are consistent); Rust skips the write. |

---

## Filed follow-ups

| ID | Slug | Severity |
|---|---|---|
| #B-TASK-META | Stamp `_source` / `_timestamp` / `_uuid` / `_context` on items emitted from `secator task X` (parity with workflow/scan emission) | medium |
| #B-INFO-OPTS | Populate `info.run_opts` in the report instead of returning `{}` | medium |
| #B-INFO-CONTEXT | Populate `info.context` with workspace + driver + worker metadata (Python parity) | low (most operators read these via the dedicated `info.workspace` / `info.task_name` extras anyway) |
| #B-WF-PASSIVE | Expression evaluator drift: `'xurlfind3r' in opts.crawlers and opts.passive` returns `false` in Rust where Python returns `true`. Either `in` list-membership semantics or profile-propagation of `passive=true` doesn't reach the leaf node. | high (silently skips passive crawlers) |
| #B-TARGET-EMIT | Emit a `Target` item per CLI input the same way Python does (one for the raw input, one for any extractor-derived shape) | medium |
| #B-EMPTY-REPORT | Always write `report.json` even on a 0-finding run (Python parity: keeps run-folder layout uniform; downstream queries can rely on the file existing) | medium |

Documented additions (not bugs): `info.errors_count`, `info.results_count`, `info.task_name`, `info.workspace` are Rust-only extras intentionally added because the Rust side computes them cheaply upstream. Python keeps the analogous data in `info.context`.

---

## Reproduction commands

```bash
DEMO=/tmp/secator-parity-$(date +%s); mkdir -p $DEMO/{py,rs}
# Python
source /home/jahmyst/Workspace/secator/.venv/bin/activate
SECATOR_DIRS_DATA=$DEMO/py secator task jswhois example.com
SECATOR_DIRS_DATA=$DEMO/py secator workflow url_crawl https://example.com -pf passive
# Rust
SECATOR_DIRS_DATA=$DEMO/rs rust/target/release/secator task jswhois example.com
SECATOR_DIRS_DATA=$DEMO/rs rust/target/release/secator workflow url_crawl https://example.com --pf passive
# Diff
diff <(jq -S .info $DEMO/py/reports/default/tasks/0/report.json) \
     <(jq -S .info $DEMO/rs/reports/default/tasks/0/report.json)
```

# Fan-in extractors via QueryEngine (RC#6 OOM fix) — Design

**Goal:** Stop rehydrating the entire fan-in result set onto the worker heap. Task input/option extraction and runner status derive from **narrow QueryEngine queries** instead of an in-memory scan of the full accumulated results. Kills the RC#6 fan-in OOM (52k/303k-result zombies) at its source.

**Non-negotiable constraint:** **Zero behavior change in task input filtering.** The set of inputs and computed options an extractor produces must be identical before and after, for every workflow/scan config we ship. This is enforced by a differential golden test (below), not by inspection.

**Scope:** `secator/runners/_helpers.py` (`run_extractors` / `process_extractor`), `secator/celery.py` (`mark_runner_started`, `mark_runner_completed`), and `secator/query/utils.py` (`python_expr_to_mongo` extensions). `get_results`, `chain_results`, and the runner `add_result`/results plumbing are **not** re-signatured.

---

## Background — where the memory goes today

The Celery chain passes results between tasks as **uuids** (persisted findings, reduced by `chain_results`) plus **objects** (non-persisted execution outputs). Two worker hooks then rehydrate the *whole* payload into full `OutputType` objects purely so in-memory consumers can scan it:

- `mark_runner_started` (`celery.py:456`): `results = get_results(results)` → `runner.add_result(...)` for each. The **only** consumer of these full objects at start is `run_extractors` (dynamic targets/opts). This is the OOM: a child receiving a 300k-result fan-in materializes all 300k before its tool ever runs.
- `mark_runner_completed` (`celery.py:524`): same rehydration, so `runner.mark_completed()` can compute `status` from `self_errors` and (historically) run duplicate checks.

Verified consumers of the full in-memory set, and why none actually need it:

| Consumer | Needs | Replacement |
|---|---|---|
| `run_extractors` / scope-tagged targets | findings matching each extractor | per-extractor `QueryEngine.search(query)` |
| `status` → `self_errors` (`_base.py:447`) | this runner's `Error` objects | `QueryEngine.search({_type: 'error', ...})` — `Error` is persisted (in `OUTPUT_TYPES`, `Task.on_item` → `update_finding`) so it's queryable |
| `mark_duplicates` (`_base.py:890`) | full set for `_compare_key` grouping | **already disabled** (`enable_duplicate_check=False` for Task/Workflow/Command/celery); mongodb dedups DB-side via `tag_duplicates(ws_id)` |

Conclusion (confirmed): nothing in the mongodb worker path needs the full hydrated set. The chain keeps carrying uuids/objects; we simply stop hydrating them.

---

## Design

### Part 1 — `run_extractors` / `process_extractor` → QueryEngine

`process_extractor` today: filter `results` by `_type`, append scope/ancestor fragments onto `_condition`, `eval()` the condition per item (with `re_match`, `len`), then format `_field` and apply `_group_by`. New flow:

```
engine = QueryEngine(workspace_id, context={drivers, results, workspace_name})
for each extractor (_type, _field, _condition, _group_by):
    query = build_extractor_query(_type, _condition, ctx)   # see translation below
    items = engine.search(query)                            # backend does the filtering
    # _field formatting, deduplicate(), and _group_by run in Python on `items` (unchanged)
```

- **Backend auto-selects** from `context['drivers']` (existing `QueryEngine` logic). `local` → `JsonBackend` filters the in-memory `context['results']` (mirrors today exactly; local has no DB and no OOM). `mongodb`/`api`/`sqlite` → the store does the filtering with the same Mongo-style query dict.
- The Python **`eval` and `re_match` are deleted** from `process_extractor`. The condition becomes a query.
- `_field` formatting, `deduplicate(values)`, `_group_by`, and the empty-result handling stay in Python, operating on the (already-filtered) returned items — byte-identical to today.
- The **`parent_scope` fallback** in `run_extractors` (lines 119–127: scoped `target` items when there is no `targets_` extractor) becomes a query `{_type: 'target', _context.scope: parent_scope}` through the same engine.
- Call-site (`_base.py:683` and the scope-tagged block at `celery.py:472`) passes `workspace_id` + `context` (drivers, results, workspace_name) into `run_extractors`. No other caller changes.

#### Condition → query translation (`query/utils.py`)

Reuse `python_expr_to_mongo` (already handles `and`/`or`, `==`/`!=`/`>=`/`<=`/`>`/`<`, `~=`→`$regex`, `!~=`, `in [...]`, `type.field`). Extend it to cover the full shipped corpus:

1. **ctx-constant pre-substitution.** `opts.*` and `targets` are runtime values known at extract time (`ctx['opts']`, `ctx['targets']`), not finding fields. Before translating, substitute their concrete values into the condition string:
   - `port.host in targets` → `port.host in ['1.2.3.4', ...]` → `$in`.
   - `opts.scanners` (constant bool) → drop the clause when truthy, or make the whole extractor yield nothing when falsy (matching today's per-item eval that returned nothing).
   - `len(targets) == 0` → evaluate against the substituted list to a constant bool, then gate.
2. **Method-call mappings:**
   - `field.startswith('x')` → `{field: {$regex: '^x'}}`.
   - `'x' in field.lower()` (and `field.lower()` comparisons) → case-insensitive `$regex` (`{$regex: 'x', $options: 'i'}` for mongo; the JSON backend's `_regex_match` already ignores case via `re.search` — confirm parity).
3. Anything still untranslatable must **raise** (not silently pass), so the corpus test catches it rather than shipping a filter that quietly matches everything/nothing.

Real corpus this must satisfy (from `secator/configs/**`): `url.verified`, `ip.alive`, `target.type == 'host'`, `item.name == 'email_address'`, `item.stored_response_path != ''`, `not url.verified`, `item.name in ['sqli']`, `opts.probe` / `not opts.probe` / `opts.ports` / `opts.scanners` / `opts.hunt_secrets`, `item.name == 'net_cidr' and len(targets) == 0`, `port.host in targets and opts.scanners`, `item._source.startswith('httpx'|'gf'|'urlparser'|'arjun'|'x8')`, `port.port == 22 or 'ssh' in port.service_name.lower()`, `url.is_root`, `item.is_directory`, `item.type == 'url'`.

### Part 2 — `celery.py`: stop rehydrating

- **`mark_runner_started`:** remove the `get_results(results)` rehydration (the `IN_WORKER and mongodb` block at `453–461`). The incoming `results` (uuids + non-persisted objects) is **not** expanded to full findings. Extractors query independently. The chain forward at return (`chain_results(runner.results)`) is unchanged — uuids continue to propagate. Non-persisted objects that must survive the round-trip (scope-tagged `Target`s) are still added as objects, exactly as `chain_results` already documents.
- **`mark_runner_completed`:** remove the `get_results(results)` rehydration at `521–529`. `status`/`self_errors` derive from a narrow `QueryEngine.search({_type: 'error', _context.ancestor_id: <runner>})` (own errors), not a full-set scan. Duplicate checks remain DB-side (`tag_duplicates`), unaffected.
- `get_results` and `chain_results` are untouched and remain available for any non-worker / full-object caller.

### What explicitly does NOT change

- `get_results`, `chain_results` / `chain_output` signatures and behavior.
- `runner.add_result`, `runner.results`, the uuid-passing chain contract.
- Local (non-mongodb) behavior: results are already full objects in memory; `JsonBackend` filters them — same inputs out.
- The JSON-driver work (separate PR #1299) — orthogonal, not wired here.

---

## Testing (the safety net for "no behavior change")

1. **Differential golden test (primary).** For each extractor condition in the shipped config corpus, run a representative synthetic result set through **both** the old Python-eval path and the new query path and assert the extracted `inputs` + computed `opts` are **identical** (order-insensitive set equality, matching `_run_extractors`' `sorted(set(...))`). Include: truthy-field, equality/inequality, negation, `in [...]`, `and`/`or`, `startswith`, `.lower()`-`in`, `opts.*` gates (both truthy and falsy), `targets` membership, `len(targets)==0`, and `group_by`. This is the test that proves the constraint.
2. **Corpus translation test.** Walk every `condition:` in `secator/configs/**` through the extended translator; assert each yields a query dict (or an explicit raise for a genuinely unsupported form) — no silent match-all/match-none.
3. **Backend parity.** Same query, same synthetic findings, asserted equal across `JsonBackend` (in-memory) and `MongoDBBackend` (mongomock or a live test DB) — local and mongodb must extract the same inputs.
4. **Memory bound.** A ~300k-id fan-in through the worker start path stays within a small heap ceiling (`tracemalloc`), proving no full-set materialization; the fetch touches only the queried type/subset.
5. **Status.** A runner whose child produced an `Error` reports `FAILURE` via the `_type: 'error'` query with no rehydration; a clean runner reports `SUCCESS`.

Full unit suite (`secator test unit`) and lint must stay green.

---

## Risks / edge cases

- **Case sensitivity** of `.lower()`-`in` between Mongo `$regex $options:i` and the JSON backend's `re.search` — assert parity in test 3.
- **`opts`/`targets` falsy gates** must reproduce today's semantics exactly: a per-item eval that is constant-false over all items yields an empty extraction (no inputs), which upstream may treat as "no dynamic inputs → keep original inputs." The golden test must cover the fall-through.
- **Untranslatable condition** slipping through as match-all — prevented by test 2's explicit-raise requirement.
- **`_group_by` + query** ordering — group_by stays a Python post-step on returned items; test 1 covers a group_by case.

## Out of scope (follow-ups, not this PR)

- Wiring the live JSON driver so the `local` backend can be read mid-run (enabled by PR #1299).
- Any change to `mark_duplicates` (already inert in this path).

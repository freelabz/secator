# Design: query-by-id extractors (fan-in OOM, RC#6/#9)

## Problem

Every runner receives the **full accumulated result set** of the chain as its
input. A `_base` runner then computes its targets from those results with
`run_extractors` / `process_extractor` (`secator/runners/_helpers.py`). For very
large sets this materialises the whole list on the worker Python heap during
setup and OOMs the worker *before* the tool even runs (so `command.py`'s
subprocess memory guard is blind to it). Two confirmed live prod zombies:
`maigret` with 52,337 results and `nmap` with 303,499 results, each in an
infinite OOM→requeue→OOM loop.

When the MongoDB addon is enabled, results are already shrunk to their Mongo
`_id` **string** in the chain (`celery.chain_results`) and rehydrated downstream
by `hooks.mongodb.get_results` — but the runner still calls `get_results` to
materialise the whole list to reason over it. The fan-in is the id list; the
heap blow-up is the rehydration + Python-side filtering.

## Goal

Let a `_base` runner **query** previous results to compute its targets instead of
holding them all — push the work into the `Query` engine
(`secator/query/`), which filters at the datastore (cheap, especially for
MongoDB) and returns only the matching rows.

## Prerequisite (this PR): `{'_id': {'$in': ids}, **filters}` per backend

Since results are fanned in by id string, the query layer must support an id +
filter query. Verified with tests (`tests/unit/test_query.py::TestIdFanInQuery`,
`TestMongoDBIdConversion`; secator-api `tests/test_query_sanitization.py`):

| backend  | `{'_id':{'$in':ids}, **filters}` | notes |
|----------|----------------------------------|-------|
| **api**  | ✅ already works | server-side `api.db.utils.convert_query` converts `_id` `$in`/`$nin` **string** lists → `ObjectId`. Regression test added. The core `ApiBackend` just POSTs the query as JSON; ids stay strings on the wire and are converted server-side. |
| **mongodb** | ✅ **fixed here** | the core `MongoDBBackend` passed the query straight to pymongo with **no** `ObjectId` conversion, so a raw-string `_id` `$in` matched **nothing**. Added `_convert_id_query` (mirrors `get_results` + the api `convert_query`), applied in `_execute_search` / `_execute_count` / `_execute_update`. |
| **local (json)** | ✅ mechanism works; ⚠️ n/a by id | `match_query` supports `$in` + sibling filters, but local report.json findings key on `_uuid`, not `_id`. Local runs never fan-in by id (MongoDB addon off) — the full objects are already in memory and the `JsonBackend` filters them via `context['results']`. So the id path is not needed locally; the type/condition filter path is. |
| sqlite   | `$in` supported; `_id` not a mirrored column | not on the prod fan-in path; out of scope. |

**Base query is safe for id filters:** `_id` is not a `PROTECTED_FIELD`, so
`_merge_query` ANDs in the enforced `_context.workspace_id` +
`is_false_positive` without dropping the client `_id` filter (tested).

## Deferred: the extractor refactor itself

Rewire `_base.py::_run_extractors` → `run_extractors`/`process_extractor` to,
when results are id strings (MongoDB addon on), build a `QueryEngine` query
`{'_id': {'$in': ids}, '_type': <extractor type>, ...}` and read back only the
projected field(s) it needs (e.g. `email_address`, host name) — never
materialising the 300k objects. Fold in #9 (`forward_results` stream/batch
dedup) since it is the same "don't hold the whole set" problem.

**Why it is not in this PR — the hard part:** extractor `condition`s are
arbitrary Python `eval` expressions, not Mongo filters. Real examples from the
shipped configs:

- `item.name == 'net_cidr' and len(targets) == 0`
- `item._source.startswith("gf")`
- `not url.verified`
- `item.stored_response_path != ''`

These reference sibling runner state (`len(targets)`), use Python string methods
(`.startswith`), and negate/compose freely. There is no general, safe
translation of this DSL into a Mongo query, and `_run_extractors` is on the hot
path of **every** runner. A correct refactor needs either:

1. a bounded translator for the common `type.field [op] literal` conditions,
   with a **fallback** that still fetches-then-filters for expressions it can't
   translate (so behaviour never changes), **projecting only the extractor
   field** so even the fallback stops rehydrating full objects; or
2. pushing just the cheap, always-safe part — the `_type` (+ workspace) filter
   and field projection — into the query, and keeping the Python `condition`
   eval on the (now much smaller, projected) candidate set.

Option 2 is the lazy, high-value first step: for `maigret`/`nmap` the `_type`
filter alone cuts the fan-in by orders of magnitude and the projection removes
the per-object heap cost, with **zero** change to condition semantics.

## Implemented — Option 2 (this stacked PR, on `fix/query-id-in-backends`)

Driver-branched: **db (mongodb worker)** = fetch by id + `_type` + projection;
**local** = unchanged in-memory `_results`.

Key decision: the worker rehydrates the fan-in via `hooks.mongodb.get_results`
(a direct, filter-free fetch-by-id), **not** `QueryEngine.search()`. The engine's
enforced base query (`_tagged`, `is_false_positive: {$ne:True}`) is correct for a
*user* query but **wrong** for rehydrating chain fan-in — during a live scan the
just-produced findings are untagged, so `_tagged:True` would drop them all and
change extractor targets. So `get_results` is the right primitive; PR #1's
QueryEngine id-query support remains the client/report path foundation.

Changes:
- `hooks/mongodb.py::get_results(uuids, types=None, fields=None)` — push a
  `_type` `$in` filter + include-projection into the Mongo query so an extractor
  rehydrates only the subset (and fields) it needs.
- `runners/_helpers.py::process_extractor` — when `ctx['fetch_by_type']` is set,
  source this extractor's candidates from the fetch (id+type+projection) instead
  of the fully-materialised set. Condition eval + formatting run unchanged on the
  reduced set. `_extractor_fields()` computes a **bounded, over-inclusive**
  projection (every identifier the field/group_by/condition mention, plus
  mandatory identity/context), so it only ever omits fields the extractor never
  references — never under-projects (semantics identical).
- `runners/_base.py` — `_split_fanin()` keeps the fan-in **by id** (cheap) for a
  child runner under the mongodb addon and materialises only carried
  non-persisted objects (Target/Info); `_run_extractors` wires the `fetch_by_type`
  closure. Root/sync/local runners keep the eager path.
- `celery.py` — `mark_runner_started`/`mark_runner_completed` use the same split;
  `chain_output()` re-forwards `prior_result_ids + results` so the accumulated
  fan-in keeps flowing downstream **as ids**, never rehydrated (this is the #9
  "don't hold the whole set" win — `forward_results` was already id-only for the
  mongodb path, so the materialisation was solely in `get_results`).

Tested (`tests/unit/test_fanin_query.py`): projection correctness; fetch used
instead of the (poison) full set; condition still runs on the fetched subset;
**db path == local path** targets; a **300k-id** fan-in stays < 5 MB peak
(`tracemalloc`); `get_results` pushes the type filter + projection;
`_split_fanin` driver-branch.

Nuance (documented, acceptable): a child no longer holds prior *finding* objects
in `self.results`, so it can't incidentally dedupe its own output against the
fan-in via `self.uuids` — cross-finding dedup already happens at persistence /
`tag_duplicates`, and `self_results` (own-source) is unaffected.

**Follow-up (not needed yet):** Option 1 — a translator for the common
`type.field [op] literal` conditions to push the predicate into Mongo too. Only
worth it if a same-type fan-in (all one `_type`) with a very selective condition
proves to still be too large post-projection.

## Rollout

1. **PR #1** (`fix/query-id-in-backends`) — backend id-query support + tests.
2. **This stacked PR** — Option 2 extractor push-down + memory-bound tests.
   ⚠️ Needs a real mongodb-worker integration run (a scan with a large fan-in)
   before merge — the unit tests cover the logic, not the live distributed chain.
3. Later (if needed) — Option 1 condition translator.

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
the per-object heap cost, with **zero** change to condition semantics. It should
be its own reviewable PR on top of this one.

## Rollout

1. **This PR** — backend id-query support + tests (id filters provably work on
   mongodb/api; local documented). Safe, isolated, no behaviour change to
   existing queries.
2. Next — Option 2 extractor refactor (type-filter + projection push-down,
   Python condition on the reduced set) + a 300k-result memory-bound test.
3. Later (if needed) — Option 1 condition translator for the common shapes.

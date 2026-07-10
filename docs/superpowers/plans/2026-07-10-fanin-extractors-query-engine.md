# Fan-in Extractors via QueryEngine (RC#6 OOM fix) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extractors and runner status derive from narrow `QueryEngine` queries instead of scanning the full in-memory fan-in, killing the RC#6 fan-in OOM at its source.

**Architecture:** `process_extractor` translates each extractor's `_type` + `_condition` (with `opts`/`targets` ctx-constants pre-substituted) into a Mongo-style query dict and runs it through `QueryEngine.search()`; the backend does the filtering (mongodb = store, local = in-memory `context['results']`). `celery.py`'s worker start/complete hooks stop rehydrating the fan-in; status comes from a narrow `{_type:'error'}` query. The Python `eval`/`re_match` filter is deleted.

**Tech Stack:** Python, pytest (via `secator test unit`), MongoDB-style query dicts, existing `secator/query` backends, `tracemalloc` for the memory test.

**Spec:** `docs/superpowers/specs/2026-07-10-fanin-extractors-query-engine-design.md` — read it first.

## Global Constraints

- **Zero behavior change in task input filtering.** Extracted `inputs` + computed `opts` must be identical to the current code for every shipped config condition. Enforced by the differential golden test (Task 5), which is the acceptance gate.
- Do **not** re-signature or alter `get_results`, `chain_results`/`chain_output`, `runner.add_result`, or the uuid-passing chain contract.
- An untranslatable condition must **raise**, never silently produce a match-all/match-none query.
- Local (non-mongodb) behavior filters the in-memory `context['results']` and must yield identical inputs.
- Run tests with `secator test unit --test <regex>` and `secator test lint` (not raw pytest). Line length ≤ 120.
- Branch off `origin/main`. Frequent commits, one per task. Do **not** merge or open the PR until all tasks pass; final PR is user-gated.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `secator/query/utils.py` | `python_expr_to_mongo` + helpers: the string-expr → query-dict translator | Extend: `startswith`/`.lower()`-`in` → `$regex`; explicit raise on untranslatable |
| `secator/runners/_helpers.py` | `run_extractors` / `process_extractor` / `extract_from_results` | Replace in-memory eval-filter with `build_extractor_query` + `QueryEngine.search`; delete `eval`/`re_match`; add ctx-substitution helper |
| `secator/celery.py` | `mark_runner_started`, `mark_runner_completed` | Drop `get_results()` rehydration; status via `{_type:'error'}` query |
| `tests/unit/test_query_utils_extractors.py` | translator extension unit tests | Create |
| `tests/unit/test_extractor_query.py` | ctx-substitution, corpus translation, differential golden, backend parity, memory | Create |

---

### Task 1: Translator extensions — method calls → `$regex`, explicit raise

**Files:**
- Modify: `secator/query/utils.py` (`python_expr_to_mongo` / `_parse_single_expr` and the `_OP` map region, ~lines 175–330)
- Test: `tests/unit/test_query_utils_extractors.py` (create)

**Interfaces:**
- Consumes: existing `python_expr_to_mongo(query: str) -> dict` and `_parse_single_expr`.
- Produces: `python_expr_to_mongo` now also translates `field.startswith('x')`, `'x' in field.lower()`, `field.lower() == 'x'`; raises `ValueError` on any expression it cannot translate.

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_query_utils_extractors.py
import pytest
from secator.query.utils import python_expr_to_mongo

def test_startswith_to_regex():
    assert python_expr_to_mongo("_source.startswith('httpx')") == {"_source": {"$regex": "^httpx"}}

def test_in_lower_to_case_insensitive_regex():
    q = python_expr_to_mongo("'ssh' in service_name.lower()")
    assert q == {"service_name": {"$regex": "ssh", "$options": "i"}}

def test_lower_equality_case_insensitive():
    q = python_expr_to_mongo("name.lower() == 'admin'")
    assert q == {"name": {"$regex": "^admin$", "$options": "i"}}

def test_untranslatable_raises():
    with pytest.raises(ValueError):
        python_expr_to_mongo("weird_func(name) == 3")
```

- [ ] **Step 2: Run and confirm failure**

Run: `secator test unit --test test_query_utils_extractors`
Expected: FAIL (startswith/lower not handled; untranslatable currently mis-parsed, not raised).

- [ ] **Step 3: Implement in `_parse_single_expr`**

Before the generic `left OP right` parse, detect method-call forms on the left/right operand and rewrite to regex ops. Sketch (adapt to the file's existing return shape — a `{field: condition}` dict):

```python
# inside _parse_single_expr(expr), after stripping/normalizing:
import re as _re

# `'x' in field.lower()`  -> case-insensitive contains
m = _re.match(r"""^\s*['"](.+?)['"]\s+in\s+([\w.]+)\.lower\(\)\s*$""", expr)
if m:
    val, field = m.group(1), m.group(2)
    return {field: {"$regex": _re.escape(val), "$options": "i"}}

# `field.startswith('x')`  -> anchored regex
m = _re.match(r"""^\s*([\w.]+)\.startswith\(['"](.+?)['"]\)\s*$""", expr)
if m:
    field, val = m.group(1), m.group(2)
    return {field: {"$regex": "^" + _re.escape(val)}}

# `field.lower() == 'x'`  -> anchored case-insensitive regex
m = _re.match(r"""^\s*([\w.]+)\.lower\(\)\s*==\s*['"](.+?)['"]\s*$""", expr)
if m:
    field, val = m.group(1), m.group(2)
    return {field: {"$regex": "^" + _re.escape(val) + "$", "$options": "i"}}
```

At the end of `_parse_single_expr`, where an expression falls through unmatched, replace any silent return with `raise ValueError(f"Cannot translate expression to query: {expr!r}")`. Verify no existing valid form (type-only, `type.field OP value`, bare truthy field) now raises — keep those branches ahead of the raise.

- [ ] **Step 4: Run tests**

Run: `secator test unit --test test_query_utils_extractors`
Expected: PASS (4/4).

- [ ] **Step 5: Guard existing translator tests**

Run: `secator test unit --test test_query` (or the module that already covers `python_expr_to_mongo`)
Expected: PASS — no regression in existing query parsing.

- [ ] **Step 6: Commit**

```bash
git add secator/query/utils.py tests/unit/test_query_utils_extractors.py
git commit -m "feat(query): translate startswith/.lower() to regex; raise on untranslatable"
```

---

### Task 2: ctx-constant substitution helper

**Files:**
- Modify: `secator/runners/_helpers.py` (add `substitute_ctx_constants`)
- Test: `tests/unit/test_extractor_query.py` (create)

**Interfaces:**
- Consumes: `parse_extractor` (existing, `_helpers.py:190`).
- Produces: `substitute_ctx_constants(condition: str, ctx: dict) -> str | None`. Replaces `opts.<k>` and `targets` tokens with their literal values from `ctx`. Returns `None` when a constant-only gate evaluates falsy (extractor yields nothing); returns the residual condition string (finding-field predicates only) otherwise. `len(targets)` folded to its integer.

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_extractor_query.py
from secator.runners._helpers import substitute_ctx_constants

CTX = {"opts": {"scanners": True, "probe": False, "ports": ""}, "targets": ["1.2.3.4", "5.6.7.8"]}

def test_targets_membership_substituted():
    out = substitute_ctx_constants("port.host in targets", CTX)
    assert out == "port.host in ['1.2.3.4', '5.6.7.8']"

def test_truthy_opts_gate_drops_clause():
    # `opts.scanners` True -> gate passes, no residual field predicate
    assert substitute_ctx_constants("opts.scanners", CTX) == ""

def test_falsy_opts_gate_returns_none():
    assert substitute_ctx_constants("opts.probe", CTX) is None

def test_len_targets_folded():
    assert substitute_ctx_constants("len(targets) == 0", CTX) is None      # 2 == 0 -> falsy gate
    assert substitute_ctx_constants("len(targets) == 2", CTX) == ""        # passes

def test_mixed_field_and_gate():
    out = substitute_ctx_constants("port.host in targets and opts.scanners", CTX)
    assert out == "port.host in ['1.2.3.4', '5.6.7.8']"                    # gate true -> residual field clause
```

- [ ] **Step 2: Run and confirm failure**

Run: `secator test unit --test test_extractor_query`
Expected: FAIL (`substitute_ctx_constants` not defined).

- [ ] **Step 3: Implement `substitute_ctx_constants`**

```python
# secator/runners/_helpers.py
import re

def substitute_ctx_constants(condition, ctx):
    """Replace opts.*/targets/len(targets) with runtime values from ctx.

    Returns the residual finding-field condition (str, possibly empty), or
    None if a constant-only gate is falsy (extractor should yield nothing).
    """
    opts = ctx.get('opts', {}) or {}
    targets = list(ctx.get('targets', []) or [])

    def opts_val(name):
        v = opts[name] if hasattr(opts, '__getitem__') and name in opts else getattr(opts, name, None)
        return v

    # Split on top-level ' and ' (extractor conditions never mix and/or with these gates in the corpus).
    clauses = [c.strip() for c in re.split(r'\s+and\s+', condition)]
    residual = []
    for c in clauses:
        # len(targets) folded
        m = re.match(r'^len\(targets\)\s*(==|!=|>=|<=|>|<)\s*(\d+)$', c)
        if m:
            import operator
            op = {'==': operator.eq, '!=': operator.ne, '>=': operator.ge,
                  '<=': operator.le, '>': operator.gt, '<': operator.lt}[m.group(1)]
            if not op(len(targets), int(m.group(2))):
                return None
            continue
        # bare opts.<k> or `not opts.<k>` gate
        m = re.match(r'^(not\s+)?opts\.(\w+)$', c)
        if m:
            val = bool(opts_val(m.group(2)))
            val = (not val) if m.group(1) else val
            if not val:
                return None
            continue
        # `<field> in targets`
        if re.search(r'\bin\s+targets\b', c):
            residual.append(re.sub(r'\btargets\b', repr(targets).replace('"', "'"), c))
            continue
        residual.append(c)
    return ' and '.join([r for r in residual if r])
```

- [ ] **Step 4: Run tests**

Run: `secator test unit --test test_extractor_query`
Expected: PASS (5/5 for these cases).

- [ ] **Step 5: Commit**

```bash
git add secator/runners/_helpers.py tests/unit/test_extractor_query.py
git commit -m "feat(extractors): substitute opts/targets ctx-constants before query translation"
```

---

### Task 3: `build_extractor_query` + corpus translation test

**Files:**
- Modify: `secator/runners/_helpers.py` (add `build_extractor_query`)
- Test: `tests/unit/test_extractor_query.py` (extend)

**Interfaces:**
- Consumes: `parse_extractor` (`_helpers.py:190`), `substitute_ctx_constants` (Task 2), `python_expr_to_mongo` (Task 1).
- Produces: `build_extractor_query(extractor, ctx) -> dict | None`. Returns a Mongo-style query `{'_type': <type>, ...condition..., ...scope/ancestor...}`, or `None` when the extractor must yield nothing (falsy gate). Scope/ancestor filters mirror today's `process_extractor` logic: `parent_scope` → `{_context.scope: parent_scope}`; else `ancestor_id and not node_chain_start` → `{_context.ancestor_id: str(ancestor_id)}`.

- [ ] **Step 1: Write failing tests + corpus test**

```python
# tests/unit/test_extractor_query.py (append)
import glob, yaml
from secator.runners._helpers import build_extractor_query

def test_build_query_type_and_condition():
    ctx = {"opts": {}, "targets": [], "parent_scope": None, "ancestor_id": None, "node_chain_start": False}
    q = build_extractor_query({"type": "url", "condition": "url.verified"}, ctx)
    assert q["_type"] == "url" and q.get("verified") in (True, {"$ne": None}) or "verified" in q

def test_build_query_scope_filter():
    ctx = {"opts": {}, "targets": [], "parent_scope": "scan-1", "ancestor_id": "wf-1", "node_chain_start": False}
    q = build_extractor_query({"type": "target", "condition": "target.type == 'host'"}, ctx)
    assert q["_context.scope"] == "scan-1"

def test_build_query_falsy_gate_returns_none():
    ctx = {"opts": {"probe": False}, "targets": [], "parent_scope": None, "ancestor_id": None, "node_chain_start": False}
    assert build_extractor_query({"type": "url", "condition": "opts.probe"}, ctx) is None

def test_every_config_condition_translates():
    """Corpus gate: every shipped extractor condition must translate or raise explicitly."""
    ctx = {"opts": {"scanners": True, "probe": True, "ports": "1-100", "hunt_secrets": True},
           "targets": ["1.2.3.4"], "parent_scope": None, "ancestor_id": "anc", "node_chain_start": False}
    conds = []
    for path in glob.glob("secator/configs/**/*.yaml", recursive=True):
        text = open(path).read()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("condition:"):
                conds.append(line.split("condition:", 1)[1].strip().strip('"\''))
    assert conds, "no conditions found — glob wrong"
    for c in conds:
        # For each type-agnostic condition, wrap with a plausible type and assert no crash / valid dict-or-None.
        q = build_extractor_query({"type": "url", "condition": c}, ctx)
        assert q is None or isinstance(q, dict)
```

- [ ] **Step 2: Run and confirm failure**

Run: `secator test unit --test test_extractor_query`
Expected: FAIL (`build_extractor_query` not defined; corpus test errors).

- [ ] **Step 3: Implement `build_extractor_query`**

```python
# secator/runners/_helpers.py
from secator.query.utils import python_expr_to_mongo

def build_extractor_query(extractor, ctx):
    parsed = parse_extractor(extractor)
    if not parsed:
        return None
    _type, _field, _condition, _group_by = parsed
    query = {'_type': _type}
    if _condition:
        residual = substitute_ctx_constants(_condition, ctx)
        if residual is None:
            return None                      # falsy gate -> yield nothing
        if residual:
            # strip a leading `item.`/`<type>.` object prefix the way process_extractor does today
            expr = residual.replace('item.', '').replace(f'{_type}.', '')
            query.update(python_expr_to_mongo(expr))
    parent_scope = ctx.get('parent_scope')
    ancestor_id = ctx.get('ancestor_id')
    node_chain_start = ctx.get('node_chain_start', False)
    if _type == 'target' and parent_scope:
        query['_context.scope'] = parent_scope
    elif ancestor_id and not node_chain_start:
        query['_context.ancestor_id'] = str(ancestor_id)
    return query
```

Note: confirm the object-prefix handling matches `process_extractor`'s current field/condition expectations (it appends conditions on the raw item; the translator expects `field OP value`). Adjust the prefix stripping so, e.g., `url.verified` → `verified`, `item.name == 'x'` → `name == 'x'`.

- [ ] **Step 4: Run tests**

Run: `secator test unit --test test_extractor_query`
Expected: PASS, including the corpus gate over `secator/configs/**`.

- [ ] **Step 5: Commit**

```bash
git add secator/runners/_helpers.py tests/unit/test_extractor_query.py
git commit -m "feat(extractors): build_extractor_query + corpus translation gate"
```

---

### Task 4: Route `process_extractor` through QueryEngine (local backend first)

**Files:**
- Modify: `secator/runners/_helpers.py` (`process_extractor`, `run_extractors`, `_run_extractors` call-site inputs)
- Modify: `secator/runners/_base.py:683` (pass `workspace_id` + `context` into `run_extractors`)
- Test: `tests/unit/test_extractor_query.py` (extend — behavior via local backend)

**Interfaces:**
- Consumes: `build_extractor_query` (Task 3), `QueryEngine` (`secator.query.QueryEngine`).
- Produces: `process_extractor` executes `QueryEngine(workspace_id, context).search(query)` (context carries `drivers`, `results`, `workspace_name`), then applies `_field` formatting + `_group_by` to the returned items. `run_extractors(results, opts, inputs, ctx, dry_run)` keeps its signature but `ctx` now must carry `workspace_id`, `drivers`, `results`, `workspace_name`. The Python `eval`/`re_match` block is removed.

- [ ] **Step 1: Write failing test (local backend parity on a small set)**

```python
# tests/unit/test_extractor_query.py (append)
from secator.output_types import Url, Ip, Target
from secator.runners._helpers import run_extractors

def _ctx(results):
    return {"opts": {}, "targets": [], "parent_scope": None, "ancestor_id": None,
            "node_chain_start": False, "workspace_id": "ws1", "workspace_name": "ws1",
            "drivers": [], "results": results}   # drivers=[] -> local JsonBackend over `results`

def test_local_extractor_filters_verified_urls():
    results = [Url(url="http://a", host="a"), Url(url="http://b", host="b")]
    results[0].verified = True
    opts = {"targets_": [{"type": "url", "field": "url", "condition": "url.verified"}]}
    ctx = _ctx(results)
    inputs, _, errors = run_extractors(results, opts, [], ctx=ctx)
    assert set(inputs) == {"http://a"} and not errors
```

- [ ] **Step 2: Run and confirm failure**

Run: `secator test unit --test test_extractor_query`
Expected: FAIL (still using in-memory eval / ctx keys unused).

- [ ] **Step 3: Rewrite `process_extractor` to query**

Replace the `_condition` eval loop and the type-filter branch in `process_extractor` with:

```python
from secator.query import QueryEngine

def process_extractor(results, extractor, ctx=None):
    if ctx is None:
        ctx = {}
    query = build_extractor_query(extractor, ctx)
    if query is None:
        return []
    engine = QueryEngine(ctx.get('workspace_id'), context={
        'drivers': ctx.get('drivers', []),
        'results': ctx.get('results', results),   # local backend filters these in-memory
        'workspace_name': ctx.get('workspace_name'),
    })
    items = engine.search(query)
    # ... keep the existing _field formatting + _group_by block below, operating on `items`
```

Keep everything from the `# Format field if needed` block onward unchanged (it already maps items → formatted strings and applies `group_by`). Ensure `run_extractors` populates `ctx` with `workspace_id/drivers/results/workspace_name` (thread them from its arguments/caller). Update `extract_from_results` only if it needs to pass ctx through (it already does).

- [ ] **Step 4: Update the `_base.py` call-site**

```python
# secator/runners/_base.py  _run_extractors (~683)
ctx = {'opts': DotMap(self.run_opts), 'targets': self.inputs, 'ancestor_id': self.ancestor_id,
       'workspace_id': self.context.get('workspace_id'),
       'workspace_name': self.context.get('workspace_name'),
       'drivers': self.context.get('drivers', []),
       'results': self.results}
inputs, run_opts, errors = run_extractors(self.results, self.run_opts, self.inputs, ctx=ctx, dry_run=self.dry_run)
```

Do the same for the scope-tagged block at `celery.py:472` (pass the same ctx keys).

- [ ] **Step 5: Run tests**

Run: `secator test unit --test test_extractor_query`
Expected: PASS.

- [ ] **Step 6: Run the extractor/runner unit suite**

Run: `secator test unit --test 'test_tasks|test_workflows|extract'`
Expected: PASS — dynamic-input workflows still resolve inputs.

- [ ] **Step 7: Commit**

```bash
git add secator/runners/_helpers.py secator/runners/_base.py secator/celery.py tests/unit/test_extractor_query.py
git commit -m "refactor(extractors): filter via QueryEngine instead of in-memory eval"
```

---

### Task 5: Differential golden test (the acceptance gate)

**Files:**
- Test: `tests/unit/test_extractor_query.py` (extend)

**Interfaces:**
- Consumes: `run_extractors` (new query path), and a captured snapshot of the **old** eval path.

Because the old path is deleted, capture its outputs as a golden fixture generated from a reference implementation embedded in the test (a minimal copy of the pre-refactor per-item eval), then assert the new path matches it over a matrix of conditions × synthetic findings.

- [ ] **Step 1: Write the differential test**

```python
# tests/unit/test_extractor_query.py (append)
import re as _re
from secator.output_types import Url, Ip, Port, Target
from secator.runners._helpers import run_extractors

def _old_eval_extract(results, extractor, ctx):
    """Reference: the pre-refactor per-item Python eval, kept ONLY to prove parity."""
    _type = extractor["type"]; cond = extractor.get("condition"); field = extractor.get("field")
    out = []
    for item in results:
        if item._type != _type:
            continue
        keep = True
        if cond:
            g = {"__builtins__": {"len": len},
                 "re_match": lambda p, v: bool(_re.search(p, str(v))) if v is not None else False}
            local = {"item": item, _type: item, "opts": ctx.get("opts", {}), "targets": ctx.get("targets", [])}
            expr = _re.sub(r'([\w.]+)\s*~=\s*(.+?)(?=\s+(?:and|or)\s+|$)', r're_match(\2, \1)', cond)
            keep = bool(eval(expr, g, local))
        if keep:
            out.append(getattr(item, field) if field else item.name if hasattr(item, "name") else item)
    return out

MATRIX = [
    ({"type": "url", "field": "url", "condition": "url.verified"}, None),
    ({"type": "url", "field": "url", "condition": "not url.verified"}, None),
    ({"type": "port", "field": "host", "condition": "port.port == 22 or 'ssh' in port.service_name.lower()"}, None),
    ({"type": "url", "field": "url", "condition": "item._source.startswith('httpx')"}, None),
    # ... one entry per distinct corpus condition shape
]

def _synthetic():
    u1 = Url(url="http://a", host="a"); u1.verified = True; u1._source = "httpx-x"
    u2 = Url(url="http://b", host="b"); u2.verified = False; u2._source = "gf-y"
    p1 = Port(port=22, host="a", service_name="SSH"); p2 = Port(port=80, host="b", service_name="http")
    return [u1, u2, p1, p2]

def test_new_query_path_matches_old_eval():
    results = _synthetic()
    ctx = {"opts": {"scanners": True, "probe": True}, "targets": ["a", "b"],
           "parent_scope": None, "ancestor_id": None, "node_chain_start": False,
           "workspace_id": "ws1", "workspace_name": "ws1", "drivers": [], "results": results}
    for extractor, _ in MATRIX:
        old = sorted(set(map(str, _old_eval_extract(results, extractor, ctx))))
        new_inputs, _, errors = run_extractors(results, {"targets_": [extractor]}, [], ctx=dict(ctx))
        assert not errors, (extractor, errors)
        assert sorted(set(map(str, new_inputs))) == old, f"behavior change for {extractor}: {new_inputs} != {old}"
```

Expand `MATRIX` to cover **every distinct condition shape** in `secator/configs/**` (truthy field, `==`/`!=`, `not`, `in [...]`, `and`/`or`, `startswith`, `.lower()`-`in`, `opts` gate truthy+falsy, `targets` membership, `len(targets)==0`, `group_by`).

- [ ] **Step 2: Run and iterate**

Run: `secator test unit --test test_extractor_query`
Expected: PASS. Any mismatch is a real behavior change — fix Task 1–4, not the assertion.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_extractor_query.py
git commit -m "test(extractors): differential golden — new query path == old eval over corpus"
```

---

### Task 6: `celery.py` — stop rehydrating; status via error query

**Files:**
- Modify: `secator/celery.py` (`mark_runner_started` ~453–461, `mark_runner_completed` ~521–529)
- Modify: `secator/runners/_base.py` (`status`/`self_errors` path if it must query when the fan-in isn't hydrated)
- Test: `tests/unit/test_extractor_query.py` (extend — status)

**Interfaces:**
- Consumes: `QueryEngine`.
- Produces: worker start/complete no longer call `get_results(results)`; `status` derives `self_errors` from `QueryEngine.search({'_type': 'error', '_context.ancestor_id': <runner>})` when running under a DB backend, else from in-memory `self.results` (unchanged for local).

- [ ] **Step 1: Write failing test**

```python
# tests/unit/test_extractor_query.py (append)
from secator.output_types import Error

def test_status_failure_from_error_without_full_hydration():
    # Local path: Error object present in results -> status FAILURE, no rehydration needed.
    from secator.runners.task import Task   # or the lightest runner constructible in unit tests
    # Build a minimal runner with an owned Error in self.results and assert status == 'FAILURE'.
    # (Follow the pattern in existing tests/unit for constructing a runner; assert self_errors path.)
```

Follow the existing unit-test runner-construction pattern (grep `tests/unit` for how runners are built with results). Assert `FAILURE` when an owned `Error` is present and `SUCCESS` when not — via the query path when `drivers` includes a DB backend (use a stubbed `QueryEngine.search` returning the error), and via in-memory results for local.

- [ ] **Step 2: Run and confirm failure**

Run: `secator test unit --test test_extractor_query`
Expected: FAIL.

- [ ] **Step 3: Edit `mark_runner_started`**

Remove the rehydration block:

```python
# secator/celery.py  mark_runner_started
if results:
    results = forward_results(results)
runner.enable_hooks = enable_hooks
# (DELETED) if IN_WORKER and CONFIG.addons.mongodb.enabled: results = get_results(results)
for item in results:
    runner.add_result(item, print=False)   # uuids stay strings; only non-persisted objects hydrate
```

Confirm `add_result` tolerates the uuid strings that were previously rehydrated. If `add_result` asserts `item._uuid` on a raw string, add a minimal guard in `celery.py` to forward-carry the string uuids without pushing them through `add_result` (do NOT change `add_result`'s contract — collect strings and let `chain_results(runner.results)` include them, or append them to a `runner`-local forward list). Keep the change confined to `celery.py`.

- [ ] **Step 4: Edit `mark_runner_completed`** the same way; make `status`/`self_errors` use the `{_type:'error'}` query under a DB backend.

- [ ] **Step 5: Run tests + full suite**

Run: `secator test unit`
Expected: PASS. Then `secator test lint` — clean.

- [ ] **Step 6: Commit**

```bash
git add secator/celery.py secator/runners/_base.py tests/unit/test_extractor_query.py
git commit -m "refactor(celery): stop rehydrating fan-in; status via error query"
```

---

### Task 7: Memory-bound + backend-parity tests

**Files:**
- Test: `tests/unit/test_extractor_query.py` (extend)

- [ ] **Step 1: Backend parity test**

```python
def test_json_and_mongo_backends_extract_same(monkeypatch):
    """Same query + same findings -> same extracted inputs across JsonBackend and MongoDBBackend."""
    # Build synthetic findings; run build_extractor_query; execute via JsonBackend(in-memory)
    # and via MongoDBBackend backed by mongomock (or skip if mongomock unavailable).
    # Assert equal extracted sets. Explicitly assert .lower()-in case-insensitivity matches.
```

- [ ] **Step 2: Memory-bound test**

```python
import tracemalloc
def test_large_fanin_does_not_materialize():
    ids = [f"{i:024x}" for i in range(300_000)]
    # Stub QueryEngine.search to assert it is called with a narrow query and returns a tiny subset,
    # and that the extractor path never builds a list proportional to len(ids).
    tracemalloc.start()
    # ... run process_extractor with the id fan-in in context; assert peak < a few MB
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    assert peak < 5 * 1024 * 1024
```

- [ ] **Step 3: Run + commit**

Run: `secator test unit --test test_extractor_query` → PASS
```bash
git add tests/unit/test_extractor_query.py
git commit -m "test(extractors): backend parity + 300k fan-in memory bound"
```

---

## Self-Review

**Spec coverage:**
- Part 1 (run_extractors → QueryEngine): Tasks 3, 4. ✓
- Translator extensions (startswith/.lower/raise): Task 1. ✓
- ctx-constant substitution (opts/targets/len): Task 2. ✓
- Part 2 (celery rehydration removal + error-query status): Task 6. ✓
- Differential golden test: Task 5. ✓
- Corpus translation test: Task 3. ✓
- Backend parity + memory bound: Task 7. ✓
- "Do not re-signature get_results/chain_results": respected (Task 6 keeps them; guard confined to celery.py). ✓

**Type consistency:** `build_extractor_query(extractor, ctx) -> dict|None`, `substitute_ctx_constants(condition, ctx) -> str|None`, `python_expr_to_mongo(str) -> dict` used consistently across tasks. `ctx` keys (`workspace_id`, `workspace_name`, `drivers`, `results`, `opts`, `targets`, `parent_scope`, `ancestor_id`, `node_chain_start`) named identically in Tasks 2–6.

**Open verification points for the implementer (resolve by reading, do not guess):**
- Exact return/dispatch shape of `_parse_single_expr` in `query/utils.py` (Task 1 sketch must match it).
- How `process_extractor`'s existing `_field` formatting + `_group_by` block consumes items (Task 4 keeps it verbatim).
- Whether `add_result` needs the string-uuid guard (Task 6) — confirm against `_base.py:758`.
- The lightest runner constructible in `tests/unit` for the status test (Task 6).

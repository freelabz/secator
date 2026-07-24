# JSON Driver NDJSON Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the local JSON store's write path O(N) instead of O(N²) by appending each finding to a per-runner `results.ndjson` instead of read-modify-writing the whole `report.json` per finding.

**Architecture:** `report.json` keeps the **info block only** (rewritten on status change via the unchanged `atomic_json` path). Findings are appended one-JSON-object-per-line to a sibling `results.ndjson` via a new locked O(1) `append_ndjson` helper. The single reader seam (`query/json.py::_read_report_dir`) streams the ndjson with last-wins-by-`_uuid` dedup, falling back to the old `report.json['results']` for pre-change/absent-ndjson reports. `report.py` already builds results via the query engine, so exporters and `report show` inherit the fix; the only other direct reader is one CLI vuln-count helper.

**Tech Stack:** Python 3.12+, secator hooks/query subsystem, `fcntl` file locking, `unittest`/`pytest`, `gevent` (concurrency test).

## Global Constraints

- Flake8: max-line-length=120; tabs for indentation (W191/E101 ignored) — match existing files.
- Run tests via `secator test unit --test <regex>` (per CLAUDE.md), not bare `pytest`.
- One JSON record per ndjson line; `json.dumps` never emits literal newlines in strings (they are escaped), so a record is always exactly one line.
- The completed-report JSON *artifact* (the JSON exporter output) and the mongodb/sqlite drivers are OUT OF SCOPE — do not touch them.
- UI / secator-api are mongodb-only — do not touch or consider them.

---

### Task 1: `append_ndjson` locked-append helper

**Files:**
- Modify: `secator/utils.py` (add `append_ndjson` next to `atomic_json`, ~L1509)
- Test: `tests/unit/test_atomic_json.py` (add appends + concurrency)

**Interfaces:**
- Produces: `append_ndjson(path: str | Path, line: str) -> None` — appends `line + "\n"` to `path` under the same layered lock (`_get_path_lock` + `flock` on `str(path)+'.lock'`) that `atomic_json` uses. Creates parent dirs. Does NOT read the file.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_atomic_json.py`:

```python
def test_append_ndjson_appends_lines(tmp_path):
    from secator.utils import append_ndjson
    p = tmp_path / 'results.ndjson'
    append_ndjson(p, '{"_uuid": "a"}')
    append_ndjson(p, '{"_uuid": "b"}')
    lines = p.read_text().splitlines()
    assert lines == ['{"_uuid": "a"}', '{"_uuid": "b"}']
```

- [ ] **Step 2: Run test to verify it fails**

Run: `secator test unit --test test_append_ndjson_appends_lines`
Expected: FAIL — `ImportError: cannot import name 'append_ndjson'`

- [ ] **Step 3: Write minimal implementation**

In `secator/utils.py`, directly after the `atomic_json` function, add (reusing the same imports `fcntl`, `_get_path_lock`, `Path` already used by `atomic_json`):

```python
def append_ndjson(path, line):
	"""Append one line (a single JSON record, no trailing newline) to an NDJSON file.

	O(1): opens in append mode and writes one line — never reads or parses the existing
	content. Uses the SAME layered lock as ``atomic_json`` (in-process path lock +
	cross-process ``flock`` on the ``.lock`` sidecar) so concurrent appenders — prefork
	processes and gevent greenlets — never interleave a partial write. A record can exceed
	``PIPE_BUF`` (4 KB), so a bare ``write`` is not atomic on its own; the lock is required.
	"""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	lock_path = str(path) + '.lock'
	with _get_path_lock(path):
		with open(lock_path, 'w') as lock_fd:
			fcntl.flock(lock_fd, fcntl.LOCK_EX)
			try:
				with open(path, 'a') as f:
					f.write(line + '\n')
			finally:
				fcntl.flock(lock_fd, fcntl.LOCK_UN)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `secator test unit --test test_append_ndjson_appends_lines`
Expected: PASS

- [ ] **Step 5: Write the concurrency failing test**

Add module-level worker + test to `tests/unit/test_atomic_json.py`:

```python
def _ndjson_proc_worker(path, worker_id, count):
    from secator.utils import append_ndjson
    import json
    for i in range(count):
        append_ndjson(path, json.dumps({'_uuid': f'{worker_id}-{i}'}))


def test_append_ndjson_concurrent_no_torn_lines(tmp_path):
    import multiprocessing as mp, json
    path = str(tmp_path / 'results.ndjson')
    ctx = mp.get_context('fork')
    procs = [ctx.Process(target=_ndjson_proc_worker, args=(path, w, 50)) for w in range(4)]
    for p in procs: p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    lines = [l for l in open(path).read().splitlines() if l]
    uuids = [json.loads(l)['_uuid'] for l in lines]      # every line valid JSON (no interleave)
    assert len(uuids) == 4 * 50
    assert len(set(uuids)) == 4 * 50                      # no loss, no dupes
```

- [ ] **Step 6: Run concurrency test to verify it passes**

Run: `secator test unit --test test_append_ndjson_concurrent_no_torn_lines`
Expected: PASS (lock serializes the 200 appends; all lines valid JSON)

- [ ] **Step 7: Commit**

```bash
git add secator/utils.py tests/unit/test_atomic_json.py
git commit -m "feat(utils): add append_ndjson O(1) locked-append helper"
```

---

### Task 2: Write path — findings append to `results.ndjson`, `report.json` is info-only

**Files:**
- Modify: `secator/hooks/json.py` (rewrite `update_finding`, add `_ndjson_path`; `update_runner` unchanged)
- Test: `tests/unit/test_json_driver.py` (update `TestJsonDriverHooks`)

**Interfaces:**
- Consumes: `append_ndjson(path, line)` from Task 1.
- Produces: `update_finding(self, item)` appends `json.dumps(record) + "\n"` to `_ndjson_path(self)` where `_ndjson_path(runner) -> Path(runner.reports_folder) / 'results.ndjson'`. `record = item.toDict()` with `record['_uuid'] = item._uuid`. Assigns `item._uuid = str(uuid.uuid4())` if empty. No in-file dedup scan. `update_runner` still writes `report.json` info via `atomic_json` (unchanged).

- [ ] **Step 1: Update the existing insert test to the ndjson model**

Replace `test_update_finding_inserts_and_assigns_uuid` in `tests/unit/test_json_driver.py` with:

```python
def test_update_finding_appends_to_ndjson(self):
    from secator.hooks import json as mod
    runner = self._runner()
    item = self._url('http://x/a')
    self.assertEqual(item._uuid, '')
    returned = mod.update_finding(runner, item)
    self.assertTrue(returned._uuid)  # uuid assigned

    lines = (Path(self.temp_dir) / 'results.ndjson').read_text().splitlines()
    self.assertEqual(len(lines), 1)
    rec = json.loads(lines[0])
    self.assertEqual(rec['url'], 'http://x/a')
    self.assertEqual(rec['_uuid'], returned._uuid)
    # report.json (if written at all here) must NOT carry results
    rp = Path(self.temp_dir) / 'report.json'
    if rp.exists():
        self.assertEqual(json.loads(rp.read_text()).get('results', {}), {})
```

- [ ] **Step 2: Run to verify it fails**

Run: `secator test unit --test test_update_finding_appends_to_ndjson`
Expected: FAIL — no `results.ndjson` (current code writes `report.json`).

- [ ] **Step 3: Rewrite `update_finding` + add `_ndjson_path`**

In `secator/hooks/json.py`, add after `_report_path`:

```python
def _ndjson_path(runner):
	return Path(runner.reports_folder) / 'results.ndjson'
```

Replace the whole `update_finding` function with:

```python
def update_finding(self, item):
	"""Append a single finding to this runner's results.ndjson (live, O(1)).

	Append-only: a re-emitted finding (on_duplicate / enrichment) appends a second line
	with the same _uuid; the query backend resolves last-wins on read. Own-emit dedup is
	the runner's in-memory self.uuids, so no in-file scan is needed here.
	"""
	if not is_output_type(item):
		return item
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	append_ndjson(_ndjson_path(self), json.dumps(record, default=str))
	return item
```

Add imports at the top of `secator/hooks/json.py`:

```python
import json
from secator.utils import atomic_json, append_ndjson, debug
```

(the existing `from secator.utils import atomic_json, debug` line — extend it with `append_ndjson`; add `import json`.)

- [ ] **Step 4: Run to verify it passes**

Run: `secator test unit --test test_update_finding_appends_to_ndjson`
Expected: PASS

- [ ] **Step 5: Update the upsert test to reader-level last-wins**

The driver is now append-only, so re-emit produces two lines and dedup happens on READ. Replace `test_update_finding_upserts_by_uuid` with:

```python
def test_update_finding_reemit_appends_second_line(self):
    from secator.hooks import json as mod
    runner = self._runner()
    item = self._url('http://x/a')
    mod.update_finding(runner, item)          # append 1
    item.status_code = 200
    mod.update_finding(runner, item)          # append 2 (same _uuid)
    lines = (Path(self.temp_dir) / 'results.ndjson').read_text().splitlines()
    self.assertEqual(len(lines), 2)           # append-only: two lines
    self.assertEqual(json.loads(lines[1])['status_code'], 200)  # later line wins on read (Task 3)
```

- [ ] **Step 6: Update the info-preservation test (info vs results now separate files)**

Replace `test_update_runner_writes_info` with:

```python
def test_update_runner_writes_info_only(self):
    from secator.hooks import json as mod
    runner = self._runner()
    mod.update_runner(runner)
    data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
    self.assertEqual(data['info']['status'], 'RUNNING')
    self.assertEqual(data['info']['name'], 'httpx')

    # A finding goes to the ndjson; a later info update must not disturb it.
    mod.update_finding(runner, self._url('http://x/a'))
    runner.status = 'SUCCESS'
    mod.update_runner(runner)
    data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
    self.assertEqual(data['info']['status'], 'SUCCESS')
    lines = (Path(self.temp_dir) / 'results.ndjson').read_text().splitlines()
    self.assertEqual(len(lines), 1)
```

`test_update_finding_ignores_non_output_type` stays as-is but assert on the ndjson instead of report.json:

```python
def test_update_finding_ignores_non_output_type(self):
    from secator.hooks import json as mod
    runner = self._runner()
    self.assertEqual(mod.update_finding(runner, {'not': 'an output type'}), {'not': 'an output type'})
    self.assertFalse((Path(self.temp_dir) / 'results.ndjson').exists())
```

- [ ] **Step 7: Run the updated hooks tests**

Run: `secator test unit --test 'test_update_finding_appends_to_ndjson|test_update_finding_reemit_appends_second_line|test_update_runner_writes_info_only|test_update_finding_ignores_non_output_type|test_hooks_structure'`
Expected: PASS (all)

- [ ] **Step 8: Commit**

```bash
git add secator/hooks/json.py tests/unit/test_json_driver.py
git commit -m "feat(hooks): json driver appends findings to results.ndjson (O(N))"
```

---

### Task 3: Read path — `_read_report_dir` streams ndjson (last-wins) with report.json fallback

**Files:**
- Modify: `secator/query/json.py` (`_read_report_dir`, ~L172-190)
- Test: `tests/unit/test_json_driver.py` (update the two query-backend tests + add ndjson-specific)

**Interfaces:**
- Consumes: `results.ndjson` written by Task 2; `report.json['results']` for legacy fallback.
- Produces: `_read_report_dir(self, report_dir, runner_type_singular, findings)` extends `findings` with the runner's records — from `results.ndjson` (last-wins by `_uuid`, torn-line tolerant) when present, else `report.json['results']`.

- [ ] **Step 1: Write failing tests for ndjson read semantics**

Add to `TestJsonDriverHooks` in `tests/unit/test_json_driver.py`:

```python
def test_reader_last_wins_and_torn_line(self):
    from secator.query.json import JsonBackend
    folder = Path(self.temp_dir) / 'ws1' / 'tasks' / 'abc123'
    folder.mkdir(parents=True)
    nd = folder / 'results.ndjson'
    # two records for uuid u1 (last wins) + one torn (partial) final line
    nd.write_text(
        json.dumps({'_type': 'url', '_uuid': 'u1', 'url': 'http://x/a', 'status_code': 0}) + '\n' +
        json.dumps({'_type': 'url', '_uuid': 'u1', 'url': 'http://x/a', 'status_code': 200}) + '\n' +
        '{"_type": "url", "_uuid": "u2", "url": "http://x/b'  # torn, no closing
    )
    backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir},
                          context={'report_dir': str(folder)})
    res = backend.search({'_type': 'url'})
    self.assertEqual(len(res), 1)                       # u2 torn line skipped; u1 deduped
    self.assertEqual(res[0]['status_code'], 200)        # later u1 line wins

def test_reader_falls_back_to_old_report_json(self):
    from secator.query.json import JsonBackend
    folder = Path(self.temp_dir) / 'ws1' / 'tasks' / 'old1'
    folder.mkdir(parents=True)
    # legacy report.json with nested results, NO ndjson
    (folder / 'report.json').write_text(json.dumps(
        {'info': {}, 'results': {'url': [{'_type': 'url', '_uuid': 'o1', 'url': 'http://old/a'}]}}))
    backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir},
                          context={'report_dir': str(folder)})
    res = backend.search({'_type': 'url'})
    self.assertEqual([r['url'] for r in res], ['http://old/a'])
```

- [ ] **Step 2: Run to verify they fail**

Run: `secator test unit --test 'test_reader_last_wins_and_torn_line|test_reader_falls_back_to_old_report_json'`
Expected: FAIL — current `_read_report_dir` only reads `report.json`; `test_reader_last_wins_and_torn_line` returns 0 (no report.json) and the fallback test may pass already.

- [ ] **Step 3: Rewrite `_read_report_dir`**

Replace `_read_report_dir` in `secator/query/json.py` with:

```python
	def _read_report_dir(self, report_dir: Path, runner_type_singular: str, findings: list):
		"""Append one runner's findings to `findings`, reading results.ndjson (live/new format)
		or falling back to report.json['results'] (legacy/completed pre-ndjson reports)."""
		ndjson = report_dir / 'results.ndjson'
		if ndjson.exists():
			by_uuid = {}
			try:
				with open(ndjson, 'r') as f:
					for line in f:
						line = line.strip()
						if not line:
							continue
						try:
							rec = json.loads(line)
						except json.JSONDecodeError:
							continue  # torn final line after a crash -> skip
						by_uuid[rec.get('_uuid') or id(rec)] = rec  # last-wins
			except IOError as e:
				debug(f'Error reading {ndjson}: {e}', sub='query.json')
				return
			items = list(by_uuid.values())
		else:
			report_file = report_dir / 'report.json'
			if not report_file.exists():
				return
			try:
				with open(report_file, 'r') as f:
					data = json.load(f)
			except (json.JSONDecodeError, IOError) as e:
				debug(f'Error loading {report_file}: {e}', sub='query.json')
				return
			items = [it for lst in data.get('results', {}).values()
			         if isinstance(lst, list) for it in lst]
		runner_id = report_dir.name
		for item in items:
			if f'{runner_type_singular}_id' not in item.get('_context', {}):
				item.setdefault('_context', {})[f'{runner_type_singular}_id'] = runner_id
		findings.extend(items)
```

- [ ] **Step 4: Run the new reader tests**

Run: `secator test unit --test 'test_reader_last_wins_and_torn_line|test_reader_falls_back_to_old_report_json'`
Expected: PASS

- [ ] **Step 5: Run the pre-existing query-backend tests (must still pass through the reader)**

`test_query_backend_reads_live_file` and `test_report_dir_scopes_read_to_one_file` drive findings through `mod.update_finding` (now ndjson) then read via `JsonBackend`. They should pass unchanged.

Run: `secator test unit --test 'test_query_backend_reads_live_file|test_report_dir_scopes_read_to_one_file'`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add secator/query/json.py tests/unit/test_json_driver.py
git commit -m "feat(query): json backend reads results.ndjson (last-wins) with legacy fallback"
```

---

### Task 4: CLI audit — `_load_report_data` counts vulns from ndjson

**Files:**
- Modify: `secator/cli.py` (`_load_report_data`, ~L1505)
- Test: `tests/unit/test_cli.py` (add a vuln-count test)

**Interfaces:**
- Consumes: `results.ndjson` (Task 2 format) / legacy `report.json['results']`.
- Produces: `_load_report_data(path)` returns `(info, vuln_counts)` reading vulnerabilities from `results.ndjson` when present (sibling of `path`), else from `report.json['results']` as today. `path` is the report.json path; info still comes from it.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_cli.py`:

```python
def test_load_report_data_counts_vulns_from_ndjson(tmp_path):
    import json
    from secator.cli import _load_report_data
    (tmp_path / 'report.json').write_text(json.dumps({'info': {'name': 'nuclei'}}))
    (tmp_path / 'results.ndjson').write_text(
        json.dumps({'_type': 'vulnerability', '_uuid': 'v1', 'severity': 'high'}) + '\n' +
        json.dumps({'_type': 'vulnerability', '_uuid': 'v2', 'severity': 'critical'}) + '\n')
    info, counts = _load_report_data(str(tmp_path / 'report.json'))
    assert info['name'] == 'nuclei'
    assert counts['high'] == 1 and counts['critical'] == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `secator test unit --test test_load_report_data_counts_vulns_from_ndjson`
Expected: FAIL — current `_load_report_data` reads only `report.json['results']`, which is empty here → counts all 0.

- [ ] **Step 3: Patch `_load_report_data`**

In `secator/cli.py::_load_report_data`, after loading `info` from the report.json, source the results from the ndjson when present:

```python
def _load_report_data(path):
	"""Read report info + count vulnerability severities (results from results.ndjson if present)."""
	info = {}
	vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
	with open(path, 'r') as f:
		data = json.load(f)
	info = data.get('info', {})
	ndjson = Path(path).parent / 'results.ndjson'
	vulns = []
	if ndjson.exists():
		with open(ndjson, 'r') as f:
			for line in f:
				line = line.strip()
				if not line:
					continue
				try:
					rec = json.loads(line)
				except json.JSONDecodeError:
					continue
				if rec.get('_type') == 'vulnerability':
					vulns.append(rec)
	else:
		vulns = data.get('results', {}).get('vulnerability', [])
	for vuln in vulns:
		severity = str(vuln.get('severity', '')).lower()
		if severity in vuln_counts:
			vuln_counts[severity] += 1
	return info, vuln_counts
```

(Ensure `from pathlib import Path` is imported in `cli.py` — it is used elsewhere in the file, so it already is.)

- [ ] **Step 4: Run to verify it passes**

Run: `secator test unit --test test_load_report_data_counts_vulns_from_ndjson`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add secator/cli.py tests/unit/test_cli.py
git commit -m "fix(cli): report vuln counts read from results.ndjson (json driver)"
```

---

### Task 5: Update the concurrency suite to the ndjson write path

**Files:**
- Modify: `tests/unit/test_json_driver.py` (`TestJsonDriverConcurrency` + module workers)

**Interfaces:**
- Consumes: `secator.hooks.json.update_finding` (Task 2) via a real runner; reads back with `JsonBackend` (Task 3).

- [ ] **Step 1: Rewrite the concurrency workers + assertion to target update_finding→ndjson**

Replace `_proc_worker` / `_gevent_child` / `_assert_no_loss` and the three concurrency tests so they drive `update_finding` (which now appends to ndjson) and assert via the reader. New module-level workers:

```python
def _proc_worker(folder, worker_id, count):
    """Append `count` findings via the real json driver (one process)."""
    from secator.hooks import json as mod
    from secator.output_types import Url
    class _R:
        config = type('C', (), {'type': 'task', 'name': 'httpx'})()
        context = {'workspace_id': 'ws1'}
        reports_folder = folder
    for i in range(count):
        u = Url(url=f'http://x/{worker_id}-{i}', _context={'workspace_id': 'ws1'})
        mod.update_finding(_R(), u)


def _gevent_child(folder, n_greenlets, count):
    import gevent.monkey; gevent.monkey.patch_all()
    import gevent
    from secator.hooks import json as mod
    from secator.output_types import Url
    class _R:
        config = type('C', (), {'type': 'task', 'name': 'httpx'})()
        context = {'workspace_id': 'ws1'}
        reports_folder = folder
    def work(wid):
        for i in range(count):
            mod.update_finding(_R(), Url(url=f'http://x/g{wid}-{i}', _context={'workspace_id': 'ws1'}))
    gevent.joinall([gevent.spawn(work, w) for w in range(n_greenlets)], raise_error=True)
```

Replace `_assert_no_loss` to read the ndjson directly (each line must be valid JSON = no interleave):

```python
def _assert_no_loss(self, folder, expected_count):
    import json as _json
    nd = Path(folder) / 'results.ndjson'
    lines = [l for l in nd.read_text().splitlines() if l]
    urls = [_json.loads(l)['url'] for l in lines]   # raises if any line torn/interleaved
    self.assertEqual(len(urls), expected_count)      # no lost appends
    self.assertEqual(len(set(urls)), expected_count) # no dupes/corruption
```

Update the three tests to pass a per-test `folder` (a fresh dir) instead of a `report.json` path, e.g.:

```python
def test_concurrent_prefork_processes(self):
    folder = str(Path(self.temp_dir) / 'run')
    Path(folder).mkdir(parents=True)
    ctx = mp.get_context('fork')
    procs = [ctx.Process(target=_proc_worker, args=(folder, w, self.PER_WORKER)) for w in range(self.N_WORKERS)]
    for p in procs: p.start()
    self._join(procs)
    self._assert_no_loss(folder, self.N_WORKERS * self.PER_WORKER)
```

Apply the same `folder` substitution to `test_concurrent_gevent_greenlets` (using `_gevent_child`) and `test_concurrent_mixed_processes_and_greenlets` (expected `2 * N_WORKERS * PER_WORKER`).

- [ ] **Step 2: Run the concurrency suite**

Run: `secator test unit --test 'TestJsonDriverConcurrency'`
Expected: PASS (all 3) — every ndjson line valid JSON, exact counts, under fork + gevent + mixed.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_json_driver.py
git commit -m "test(json): concurrency suite hammers the ndjson append path"
```

---

### Task 6: Full json-driver test pass + perf acceptance gate

**Files:** none (verification only)

- [ ] **Step 1: Run the whole json-driver + atomic_json + query unit surface**

Run: `secator test unit --test 'json_driver|atomic_json|test_query|test_cli'`
Expected: PASS — no regressions across the store, reader, concurrency, and CLI.

- [ ] **Step 2: Run lint**

Run: `secator test lint`
Expected: PASS (no new flake8 findings in the touched files).

- [ ] **Step 3: Perf acceptance gate (the "checks out" bar)**

Re-run the memray benchmark's json-driver cells (harness in `~/Workspace/gke-admin/scripts/perf-compare.sh` / the scratchpad `matrix.sh`) on this branch:

Run (once the mongodb/redis backends are free): `matrix.sh 10000 100000 1000000` with `dc` pointed at this worktree.
Expected: `sync-json` and `worker-json` cells go from **O(N²) DNF → complete at 1M** with peak RAM and walltime in the same order as the `sync-mongo` cells (not the old 7.6 GB / DNF). Record the numbers.

- [ ] **Step 4: Commit any measurement notes**

```bash
git add docs/superpowers/plans/2026-07-16-json-driver-ndjson.md
git commit -m "docs: json-driver ndjson perf results"
```

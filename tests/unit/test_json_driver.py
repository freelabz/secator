# tests/unit/test_json_driver.py

import json
import multiprocessing as mp
import tempfile
import shutil
import unittest
from pathlib import Path

import pytest


# --- module-level workers (must be importable/picklable for multiprocessing) ---

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
	"""Run in a separate process: monkey-patch gevent, then hammer one ndjson from N greenlets."""
	import gevent.monkey
	gevent.monkey.patch_all()
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


class JsonDriverTestBase(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _runner(self, rtype='task', name='httpx', ws='ws1', folder=None):
		folder = folder or self.temp_dir
		Path(folder).mkdir(parents=True, exist_ok=True)

		class FakeRunner:
			def __init__(inner):
				inner.config = type('C', (), {'type': rtype, 'name': name})()
				inner.context = {'workspace_id': ws}
				inner.reports_folder = folder
				inner.status = 'RUNNING'

			def toDict(inner):
				return {'name': name, 'status': inner.status, 'chunk': None, 'context': inner.context}

		return FakeRunner()

	def _url(self, url, ws='ws1'):
		from secator.output_types import Url
		return Url(url=url, _context={'workspace_id': ws, 'workspace_duplicate': False})


class TestJsonDriverHooks(JsonDriverTestBase):
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

	def test_update_finding_reemit_appends_second_line(self):
		from secator.hooks import json as mod
		runner = self._runner()
		item = self._url('http://x/a')
		mod.update_finding(runner, item)          # append 1
		item.status_code = 200
		mod.update_finding(runner, item)          # append 2 (same _uuid)
		lines = (Path(self.temp_dir) / 'results.ndjson').read_text().splitlines()
		self.assertEqual(len(lines), 2)           # append-only: two lines
		self.assertEqual(json.loads(lines[1])['status_code'], 200)  # later line wins on read

	def test_update_finding_ignores_non_output_type(self):
		from secator.hooks import json as mod
		runner = self._runner()
		self.assertEqual(mod.update_finding(runner, {'not': 'an output type'}), {'not': 'an output type'})
		self.assertFalse((Path(self.temp_dir) / 'results.ndjson').exists())

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

	def test_hooks_structure(self):
		from secator.hooks import json as mod
		from secator.runners import Scan, Task, Workflow
		self.assertIn(Task, mod.HOOKS)
		self.assertIn(Workflow, mod.HOOKS)
		self.assertIn(Scan, mod.HOOKS)
		self.assertIn('on_item', mod.HOOKS[Task])
		self.assertIn('on_end', mod.HOOKS[Task])

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

	def test_query_backend_reads_live_file(self):
		"""The live-written report.json is readable by the local (json) query backend mid-run."""
		from secator.hooks import json as mod
		from secator.query.json import JsonBackend
		# JsonBackend expects <reports_dir>/<ws>/tasks/<id>/report.json
		folder = Path(self.temp_dir) / 'ws1' / 'tasks' / 'abc123'
		runner = self._runner(folder=str(folder))
		mod.update_finding(runner, self._url('http://x/a'))
		mod.update_finding(runner, self._url('http://x/b'))

		backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir})
		results = backend.search({'_type': 'url'})
		urls = sorted(r['url'] for r in results)
		self.assertEqual(urls, ['http://x/a', 'http://x/b'])

	def test_report_dir_scopes_read_to_one_file(self):
		"""A run-scoped read (context['report_dir']) loads ONLY that runner's report.json, not the
		whole workspace — the hot-path fix for the per-query whole-workspace scan."""
		from secator.hooks import json as mod
		from secator.query.json import JsonBackend
		base = Path(self.temp_dir) / 'ws1' / 'tasks'
		# Two sibling runs in the same workspace.
		for rid, url in [('r1', 'http://mine/a'), ('r2', 'http://other/b')]:
			mod.update_finding(self._runner(folder=str(base / rid)), self._url(url))
		# Whole-workspace read sees both; report_dir-scoped read sees only r1's file.
		full = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir})
		self.assertEqual(len(full.search({'_type': 'url'})), 2)
		scoped = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir},
							 context={'report_dir': str(base / 'r1')})
		self.assertEqual([r['url'] for r in scoped.search({'_type': 'url'})], ['http://mine/a'])


class TestJsonDriverConcurrency(JsonDriverTestBase):
	N_WORKERS = 4
	PER_WORKER = 25

	def _assert_no_loss(self, folder, expected_count):
		nd = Path(folder) / 'results.ndjson'
		lines = [l for l in nd.read_text().splitlines() if l]
		urls = [json.loads(l)['url'] for l in lines]         # raises if any line torn/interleaved
		self.assertEqual(len(urls), expected_count)          # no lost appends
		self.assertEqual(len(set(urls)), expected_count)     # no dupes/corruption

	def _join(self, procs, timeout=60):
		"""Join workers; terminate any that time out so a regression can't hang the suite."""
		for p in procs:
			p.join(timeout)
			if p.is_alive():
				p.terminate()
				p.join(5)
			self.assertEqual(p.exitcode, 0, f'worker {p.pid} did not exit cleanly (exitcode={p.exitcode})')

	def _fresh_folder(self):
		folder = str(Path(self.temp_dir) / 'run')
		Path(folder).mkdir(parents=True, exist_ok=True)
		return folder

	def test_concurrent_prefork_processes(self):
		"""prefork pool analogue: N separate OS processes append to one results.ndjson."""
		folder = self._fresh_folder()
		ctx = mp.get_context('fork')
		procs = [
			ctx.Process(target=_proc_worker, args=(folder, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		for p in procs:
			p.start()
		self._join(procs)
		self._assert_no_loss(folder, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_gevent_greenlets(self):
		"""gevent pool analogue: N greenlets in one (monkey-patched) process append to one file."""
		pytest.importorskip('gevent')
		folder = self._fresh_folder()
		# Run monkey-patched gevent in a child process so patch_all() doesn't leak into the suite.
		ctx = mp.get_context('spawn')
		p = ctx.Process(target=_gevent_child, args=(folder, self.N_WORKERS, self.PER_WORKER))
		p.start()
		self._join([p])
		self._assert_no_loss(folder, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_mixed_processes_and_greenlets(self):
		"""Both at once: prefork processes AND a gevent-greenlet process share one file."""
		pytest.importorskip('gevent')
		folder = self._fresh_folder()
		fork = mp.get_context('fork')
		spawn = mp.get_context('spawn')
		procs = [
			fork.Process(target=_proc_worker, args=(folder, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		gproc = spawn.Process(target=_gevent_child, args=(folder, self.N_WORKERS, self.PER_WORKER))
		for p in procs:
			p.start()
		gproc.start()
		self._join(procs + [gproc])
		# N_WORKERS process-appends + N_WORKERS greenlet-appends, each PER_WORKER items.
		self._assert_no_loss(folder, 2 * self.N_WORKERS * self.PER_WORKER)


if __name__ == '__main__':
	unittest.main()

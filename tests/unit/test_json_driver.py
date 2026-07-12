# tests/unit/test_json_driver.py

import json
import multiprocessing as mp
import tempfile
import shutil
import unittest
from pathlib import Path


# --- module-level workers (must be importable/picklable for multiprocessing) ---

def _proc_worker(path, worker_id, count):
	"""Append `count` uniquely-uuid'd findings to the SAME report.json (one process)."""
	from secator.hooks.json import atomic_json_update
	for i in range(count):
		uid = f'{worker_id}-{i}'
		atomic_json_update(
			path,
			lambda data, uid=uid: data['results'].setdefault('url', []).append({'_uuid': uid}),
		)


def _gevent_child(path, n_greenlets, count):
	"""Run in a separate process: monkey-patch gevent, then hammer one file from N greenlets."""
	import gevent.monkey
	gevent.monkey.patch_all()
	import gevent
	from secator.hooks.json import atomic_json_update

	def work(worker_id):
		for i in range(count):
			uid = f'g{worker_id}-{i}'
			atomic_json_update(
				path,
				lambda data, uid=uid: data['results'].setdefault('url', []).append({'_uuid': uid}),
			)

	greenlets = [gevent.spawn(work, w) for w in range(n_greenlets)]
	gevent.joinall(greenlets, raise_error=True)


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
	def test_update_finding_inserts_and_assigns_uuid(self):
		from secator.hooks import json as mod
		runner = self._runner()
		item = self._url('http://x/a')
		self.assertEqual(item._uuid, '')
		returned = mod.update_finding(runner, item)
		self.assertTrue(returned._uuid)  # uuid assigned

		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(len(data['results']['url']), 1)
		self.assertEqual(data['results']['url'][0]['url'], 'http://x/a')
		self.assertEqual(data['results']['url'][0]['_uuid'], returned._uuid)

	def test_update_finding_upserts_by_uuid(self):
		from secator.hooks import json as mod
		runner = self._runner()
		item = self._url('http://x/a')
		mod.update_finding(runner, item)          # insert
		item.status_code = 200
		mod.update_finding(runner, item)          # update same uuid, must not duplicate

		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(len(data['results']['url']), 1)
		self.assertEqual(data['results']['url'][0]['status_code'], 200)

	def test_update_finding_ignores_non_output_type(self):
		from secator.hooks import json as mod
		runner = self._runner()
		self.assertEqual(mod.update_finding(runner, {'not': 'an output type'}), {'not': 'an output type'})
		self.assertFalse((Path(self.temp_dir) / 'report.json').exists())

	def test_update_runner_writes_info(self):
		from secator.hooks import json as mod
		runner = self._runner()
		mod.update_runner(runner)
		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(data['info']['status'], 'RUNNING')
		self.assertEqual(data['info']['name'], 'httpx')

		# Runner info update must preserve already-written findings (findings + info share the file).
		mod.update_finding(runner, self._url('http://x/a'))
		runner.status = 'SUCCESS'
		mod.update_runner(runner)
		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(data['info']['status'], 'SUCCESS')
		self.assertEqual(len(data['results']['url']), 1)

	def test_hooks_structure(self):
		from secator.hooks import json as mod
		from secator.runners import Scan, Task, Workflow
		self.assertIn(Task, mod.HOOKS)
		self.assertIn(Workflow, mod.HOOKS)
		self.assertIn(Scan, mod.HOOKS)
		self.assertIn('on_item', mod.HOOKS[Task])
		self.assertIn('on_end', mod.HOOKS[Task])

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

	def test_live_files_win_over_in_memory_results(self):
		"""#1299 shadow fix: live report.json files must be read even when the backend
		was handed an in-memory `results` payload (which is topology-only once the chain
		payload is dropped, and would otherwise shadow the files)."""
		from secator.hooks import json as mod
		from secator.query.json import JsonBackend
		folder = Path(self.temp_dir) / 'ws1' / 'tasks' / 'abc123'
		runner = self._runner(folder=str(folder))
		mod.update_finding(runner, self._url('http://live/a'))

		# A stale/topology-only payload handed in as `results` must NOT shadow the files.
		stale = [{'_type': 'url', 'url': 'http://stale/z', '_context': {'workspace_id': 'ws1'}}]
		backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir}, results=stale)
		urls = sorted(r['url'] for r in backend.search({'_type': 'url'}))
		self.assertEqual(urls, ['http://live/a'])

	def test_in_memory_results_fallback_when_no_files(self):
		"""With no report.json files on disk, the backend falls back to in-memory results."""
		from secator.query.json import JsonBackend
		payload = [{'_type': 'url', 'url': 'http://mem/a', '_context': {'workspace_id': 'ws1'}}]
		backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir}, results=payload)
		urls = [r['url'] for r in backend.search({'_type': 'url'})]
		self.assertEqual(urls, ['http://mem/a'])


class TestJsonDriverConcurrency(JsonDriverTestBase):
	N_WORKERS = 4
	PER_WORKER = 25

	def _assert_no_loss(self, path, expected_prefix_count):
		data = json.loads(Path(path).read_text())          # must be valid JSON (no torn write)
		uuids = [r['_uuid'] for r in data['results']['url']]
		self.assertEqual(len(uuids), expected_prefix_count)  # no lost updates
		self.assertEqual(len(set(uuids)), expected_prefix_count)  # no corruption/dupes

	def test_concurrent_prefork_processes(self):
		"""prefork pool analogue: N separate OS processes append to one report.json."""
		path = str(Path(self.temp_dir) / 'report.json')
		ctx = mp.get_context('fork')
		procs = [
			ctx.Process(target=_proc_worker, args=(path, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		for p in procs:
			p.start()
		for p in procs:
			p.join(60)
			self.assertEqual(p.exitcode, 0)
		self._assert_no_loss(path, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_gevent_greenlets(self):
		"""gevent pool analogue: N greenlets in one (monkey-patched) process append to one file."""
		path = str(Path(self.temp_dir) / 'report.json')
		# Run monkey-patched gevent in a child process so patch_all() doesn't leak into the suite.
		ctx = mp.get_context('spawn')
		p = ctx.Process(target=_gevent_child, args=(path, self.N_WORKERS, self.PER_WORKER))
		p.start()
		p.join(60)
		self.assertEqual(p.exitcode, 0)
		self._assert_no_loss(path, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_mixed_processes_and_greenlets(self):
		"""Both at once: prefork processes AND a gevent-greenlet process share one file."""
		path = str(Path(self.temp_dir) / 'report.json')
		fork = mp.get_context('fork')
		spawn = mp.get_context('spawn')
		procs = [
			fork.Process(target=_proc_worker, args=(path, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		gproc = spawn.Process(target=_gevent_child, args=(path, self.N_WORKERS, self.PER_WORKER))
		for p in procs:
			p.start()
		gproc.start()
		for p in procs + [gproc]:
			p.join(60)
			self.assertEqual(p.exitcode, 0)
		# N_WORKERS process-appends + N_WORKERS greenlet-appends, each PER_WORKER items.
		self._assert_no_loss(path, 2 * self.N_WORKERS * self.PER_WORKER)


if __name__ == '__main__':
	unittest.main()

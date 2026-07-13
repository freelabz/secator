# tests/unit/test_json_driver.py

import json
import multiprocessing as mp
import tempfile
import shutil
import unittest
from pathlib import Path

import pytest


# --- module-level workers (must be importable/picklable for multiprocessing) ---

def _proc_worker(path, worker_id, count):
	"""Append `count` uniquely-uuid'd findings to the SAME report.json (one process)."""
	from secator.utils import atomic_json
	for i in range(count):
		uid = f'{worker_id}-{i}'
		with atomic_json(path, default=lambda: {'info': {}, 'results': {}}) as data:
			data['results'].setdefault('url', []).append({'_uuid': uid})


def _gevent_child(path, n_greenlets, count):
	"""Run in a separate process: monkey-patch gevent, then hammer one file from N greenlets."""
	import gevent.monkey
	gevent.monkey.patch_all()
	import gevent
	from secator.utils import atomic_json

	def work(worker_id):
		for i in range(count):
			uid = f'g{worker_id}-{i}'
			with atomic_json(path, default=lambda: {'info': {}, 'results': {}}) as data:
				data['results'].setdefault('url', []).append({'_uuid': uid})

	greenlets = [gevent.spawn(work, w) for w in range(n_greenlets)]
	gevent.joinall(greenlets, raise_error=True)


def _parallelism_probe(base_dir, result_path, n, dt):
	"""Isolated gevent process: measure that two chatty --driver-json tasks run in PARALLEL.

	Emulates the gevent Celery worker. Two 'tasks' each emit `n` findings through the
	REAL json driver, with a gevent.sleep(dt) between findings (a monkey-patched,
	yielding stand-in for tool output arriving over a socket).

	- parallel_wall: two BATCHED tasks concurrently -> should be ~= n*dt (their sleeps
	  overlap: max(t1,t2)), NOT ~= 2*n*dt (the sum, i.e. serial).
	- serial_burst vs batched_burst: same work WITHOUT the sleeps, so the only
	  difference is I/O. The serial (pre-fix) path does a blocking atomic_json write +
	  fsync per finding — under gevent that can't yield, so it stalls the hub; the
	  batched path buffers and writes once. batched_burst must be << serial_burst.
	"""
	import gevent.monkey
	gevent.monkey.patch_all()
	import gevent
	import json as _json
	from time import time as _now
	from secator.hooks import json as drv
	from secator.output_types import Url
	from secator.utils import atomic_json

	def _runner(folder):
		import os
		os.makedirs(folder, exist_ok=True)
		r = type('R', (), {})()
		r.reports_folder = folder
		r.last_updated_db = None
		r.toDict = lambda: {'status': 'RUNNING', 'name': 'ffuf'}
		return r

	def _url(i):
		return Url(url=f'http://x/{i}', _context={'workspace_id': 'ws', 'workspace_duplicate': False})

	def batched_task(folder, sleep):
		runner = _runner(folder)
		for i in range(n):
			drv.update_finding(runner, _url(i))      # buffer only (O(1), no syscall)
			if sleep:
				gevent.sleep(dt)
		drv.flush_report(runner)                     # single write at the end

	def serial_task(folder, sleep):
		# Pre-fix behavior: one blocking atomic_json write + fsync PER finding.
		path = f'{folder}/report.json'
		for i in range(n):
			with atomic_json(path, default=drv._empty_report) as data:
				data['results'].setdefault('url', []).append({'_uuid': f'{i}'})
			if sleep:
				gevent.sleep(dt)

	def wall(fn, sleep):
		t0 = _now()
		gs = [gevent.spawn(fn, f'{base_dir}/{fn.__name__}-{w}-{sleep}', sleep) for w in range(2)]
		gevent.joinall(gs, raise_error=True)
		return _now() - t0

	parallel_wall = wall(batched_task, True)      # with inter-finding yields -> proves parallel
	serial_burst = wall(serial_task, False)       # no yields -> pure I/O cost, pre-fix
	batched_burst = wall(batched_task, False)     # no yields -> pure I/O cost, batched

	Path(result_path).write_text(_json.dumps({
		'parallel_wall': parallel_wall, 'ideal': n * dt,
		'serial_burst': serial_burst, 'batched_burst': batched_burst,
	}))


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
		mod.flush_report(runner)  # findings are batched — persist before asserting

		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(len(data['results']['url']), 1)
		self.assertEqual(data['results']['url'][0]['url'], 'http://x/a')
		self.assertEqual(data['results']['url'][0]['_uuid'], returned._uuid)

	def test_on_item_buffers_no_write_until_flush(self):
		"""on_item must NOT touch disk (that per-finding fsync is what stalled the gevent hub)."""
		from secator.hooks import json as mod
		runner = self._runner()
		report = Path(self.temp_dir) / 'report.json'
		for i in range(10):
			mod.update_finding(runner, self._url(f'http://x/{i}'))
		self.assertFalse(report.exists())  # zero file writes across 10 findings
		mod.flush_report(runner)            # single write persists them all
		data = json.loads(report.read_text())
		self.assertEqual(len(data['results']['url']), 10)

	def test_update_finding_upserts_by_uuid(self):
		from secator.hooks import json as mod
		runner = self._runner()
		item = self._url('http://x/a')
		mod.update_finding(runner, item)          # insert
		item.status_code = 200
		mod.update_finding(runner, item)          # update same uuid, must not duplicate
		mod.flush_report(runner)

		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(len(data['results']['url']), 1)
		self.assertEqual(data['results']['url'][0]['status_code'], 200)

	def test_upsert_across_flush_boundary(self):
		"""A finding updated in a LATER flush window upserts the earlier persisted copy."""
		from secator.hooks import json as mod
		runner = self._runner()
		item = self._url('http://x/a')
		mod.update_finding(runner, item)
		mod.flush_report(runner)                  # persisted (window 1)
		item.status_code = 200
		mod.update_finding(runner, item)
		mod.flush_report(runner)                  # window 2 must upsert, not duplicate
		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(len(data['results']['url']), 1)
		self.assertEqual(data['results']['url'][0]['status_code'], 200)

	def test_update_finding_ignores_non_output_type(self):
		from secator.hooks import json as mod
		runner = self._runner()
		self.assertEqual(mod.update_finding(runner, {'not': 'an output type'}), {'not': 'an output type'})
		mod.flush_report(runner)
		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(data['results'], {})  # nothing buffered/written for a non-output-type

	def test_update_runner_writes_info(self):
		from secator.hooks import json as mod
		runner = self._runner()
		mod.update_runner(runner)
		data = json.loads((Path(self.temp_dir) / 'report.json').read_text())
		self.assertEqual(data['info']['status'], 'RUNNING')
		self.assertEqual(data['info']['name'], 'httpx')

		# flush_report writes info + buffered findings together (findings + info share the file).
		mod.update_finding(runner, self._url('http://x/a'))
		runner.status = 'SUCCESS'
		mod.flush_report(runner)
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
		mod.flush_report(runner)

		backend = JsonBackend(workspace_id='ws1', config={'reports_dir': self.temp_dir})
		results = backend.search({'_type': 'url'})
		urls = sorted(r['url'] for r in results)
		self.assertEqual(urls, ['http://x/a', 'http://x/b'])


class TestJsonDriverConcurrency(JsonDriverTestBase):
	N_WORKERS = 4
	PER_WORKER = 25

	def _assert_no_loss(self, path, expected_prefix_count):
		data = json.loads(Path(path).read_text())          # must be valid JSON (no torn write)
		uuids = [r['_uuid'] for r in data['results']['url']]
		self.assertEqual(len(uuids), expected_prefix_count)  # no lost updates
		self.assertEqual(len(set(uuids)), expected_prefix_count)  # no corruption/dupes

	def _join(self, procs, timeout=60):
		"""Join workers; terminate any that time out so a regression can't hang the suite."""
		for p in procs:
			p.join(timeout)
			if p.is_alive():
				p.terminate()
				p.join(5)
			self.assertEqual(p.exitcode, 0, f'worker {p.pid} did not exit cleanly (exitcode={p.exitcode})')

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
		self._join(procs)
		self._assert_no_loss(path, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_gevent_greenlets(self):
		"""gevent pool analogue: N greenlets in one (monkey-patched) process append to one file."""
		pytest.importorskip('gevent')
		path = str(Path(self.temp_dir) / 'report.json')
		# Run monkey-patched gevent in a child process so patch_all() doesn't leak into the suite.
		ctx = mp.get_context('spawn')
		p = ctx.Process(target=_gevent_child, args=(path, self.N_WORKERS, self.PER_WORKER))
		p.start()
		self._join([p])
		self._assert_no_loss(path, self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_mixed_processes_and_greenlets(self):
		"""Both at once: prefork processes AND a gevent-greenlet process share one file."""
		pytest.importorskip('gevent')
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
		self._join(procs + [gproc])
		# N_WORKERS process-appends + N_WORKERS greenlet-appends, each PER_WORKER items.
		self._assert_no_loss(path, 2 * self.N_WORKERS * self.PER_WORKER)


class TestJsonDriverParallelism(JsonDriverTestBase):
	"""Acceptance gate: two chatty --driver-json tasks must run in PARALLEL on a gevent worker."""

	N = 150
	DT = 0.004  # 4ms between findings; ideal single-task wall = N*DT = 600ms

	def _join(self, procs, timeout=120):
		for p in procs:
			p.join(timeout)
			if p.is_alive():
				p.terminate()
				p.join(5)
			self.assertEqual(p.exitcode, 0, f'probe did not exit cleanly (exitcode={p.exitcode})')

	def test_two_chatty_tasks_run_in_parallel(self):
		pytest.importorskip('gevent')
		result = str(Path(self.temp_dir) / 'result.json')
		ctx = mp.get_context('spawn')  # isolate monkey-patch, like the other gevent tests
		p = ctx.Process(target=_parallelism_probe, args=(self.temp_dir, result, self.N, self.DT))
		p.start()
		self._join([p])
		m = json.loads(Path(result).read_text())

		# 1) PARALLEL: two concurrent batched tasks finish in ~= one task's time (max), not the
		#    sum. Serial would be ~= 2*ideal; allow generous scheduling slack.
		self.assertLess(
			m['parallel_wall'], 1.6 * m['ideal'],
			f"two tasks did not overlap: wall={m['parallel_wall']:.3f}s ideal(max)={m['ideal']:.3f}s "
			f"serial-would-be~={2 * m['ideal']:.3f}s")

		# 2) The fix's cause: per-finding blocking fsync (pre-fix) stalls the gevent hub; batching
		#    writes once. Burst (no yields) isolates pure I/O cost — batched must be far cheaper.
		self.assertLess(
			m['batched_burst'], 0.5 * m['serial_burst'],
			f"batched I/O not cheaper: batched={m['batched_burst']:.3f}s serial={m['serial_burst']:.3f}s")


if __name__ == '__main__':
	unittest.main()

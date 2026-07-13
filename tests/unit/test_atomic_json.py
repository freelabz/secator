# tests/unit/test_atomic_json.py
#
# Direct tests for the atomic_json / read_json primitives in secator.utils
# (mongomock-free — no driver, no output types).

import json
import multiprocessing as mp
import tempfile
import shutil
import unittest
from pathlib import Path

import pytest


# --- module-level workers (must be importable/picklable for multiprocessing) ---

def _proc_worker(path, worker_id, count):
	"""Append `count` uniquely-keyed entries to a shared list key via atomic_json (one process)."""
	from secator.utils import atomic_json
	for i in range(count):
		with atomic_json(path, default=lambda: {'items': []}) as data:
			data['items'].append(f'{worker_id}-{i}')


def _gevent_child(path, n_greenlets, count):
	"""Separate process: monkey-patch gevent, then hammer one file from N greenlets via atomic_json."""
	import gevent.monkey
	gevent.monkey.patch_all()
	import gevent
	from secator.utils import atomic_json

	def work(worker_id):
		for i in range(count):
			with atomic_json(path, default=lambda: {'items': []}) as data:
				data['items'].append(f'g{worker_id}-{i}')

	greenlets = [gevent.spawn(work, w) for w in range(n_greenlets)]
	gevent.joinall(greenlets, raise_error=True)


class AtomicJsonTestBase(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()
		self.path = str(Path(self.temp_dir) / 'data.json')

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _items(self):
		data = json.loads(Path(self.path).read_text())  # must be valid JSON (no torn write)
		return data['items']

	def _join(self, procs, timeout=60):
		"""Join workers; terminate any that time out so a regression can't hang the suite."""
		for p in procs:
			p.join(timeout)
			if p.is_alive():
				p.terminate()
				p.join(5)
			self.assertEqual(p.exitcode, 0, f'worker {p.pid} did not exit cleanly (exitcode={p.exitcode})')


class TestAtomicJson(AtomicJsonTestBase):
	N_WORKERS = 4
	PER_WORKER = 25

	def test_yields_default_when_absent(self):
		from secator.utils import atomic_json
		with atomic_json(self.path, default=lambda: {'items': []}) as data:
			self.assertEqual(data, {'items': []})
			data['items'].append('x')
		self.assertEqual(self._items(), ['x'])

	def test_exception_leaves_file_unchanged(self):
		from secator.utils import atomic_json
		# Seed the file.
		with atomic_json(self.path, default=lambda: {'items': []}) as data:
			data['items'].append('seed')
		# A block that raises must NOT write.
		with self.assertRaises(RuntimeError):
			with atomic_json(self.path, default=lambda: {'items': []}) as data:
				data['items'].append('should-not-persist')
				raise RuntimeError('boom')
		self.assertEqual(self._items(), ['seed'])  # unchanged

	def test_wholesale_replace(self):
		from secator.utils import atomic_json
		with atomic_json(self.path, default=lambda: {'items': []}) as data:
			data['items'].append('old')
		with atomic_json(self.path, default=lambda: {'items': []}) as data:
			data.clear()
			data.update({'items': ['new']})
		self.assertEqual(self._items(), ['new'])

	def test_concurrent_prefork_processes(self):
		"""N separate OS processes append to one file — no lost updates."""
		ctx = mp.get_context('fork')
		procs = [
			ctx.Process(target=_proc_worker, args=(self.path, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		for p in procs:
			p.start()
		self._join(procs)
		items = self._items()
		self.assertEqual(len(items), self.N_WORKERS * self.PER_WORKER)
		self.assertEqual(len(set(items)), self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_gevent_greenlets(self):
		"""N greenlets in one (isolated, monkey-patched) process append to one file."""
		pytest.importorskip('gevent')
		ctx = mp.get_context('spawn')
		p = ctx.Process(target=_gevent_child, args=(self.path, self.N_WORKERS, self.PER_WORKER))
		p.start()
		self._join([p])
		items = self._items()
		self.assertEqual(len(items), self.N_WORKERS * self.PER_WORKER)
		self.assertEqual(len(set(items)), self.N_WORKERS * self.PER_WORKER)

	def test_concurrent_mixed_processes_and_greenlets(self):
		"""prefork processes AND a gevent-greenlet process share one file."""
		pytest.importorskip('gevent')
		fork = mp.get_context('fork')
		spawn = mp.get_context('spawn')
		procs = [
			fork.Process(target=_proc_worker, args=(self.path, w, self.PER_WORKER))
			for w in range(self.N_WORKERS)
		]
		gproc = spawn.Process(target=_gevent_child, args=(self.path, self.N_WORKERS, self.PER_WORKER))
		for p in procs:
			p.start()
		gproc.start()
		self._join(procs + [gproc])
		items = self._items()
		self.assertEqual(len(items), 2 * self.N_WORKERS * self.PER_WORKER)
		self.assertEqual(len(set(items)), 2 * self.N_WORKERS * self.PER_WORKER)


class TestReadJson(AtomicJsonTestBase):
	def test_absent_returns_default(self):
		from secator.utils import read_json
		self.assertEqual(read_json(self.path, default=dict), {})
		self.assertEqual(read_json(self.path, default=lambda: {'items': []}), {'items': []})

	def test_corrupt_raises_not_masked(self):
		# A present-but-corrupt file is a real anomaly, not a normal partial write:
		# read_json (and atomic_json) must raise, never silently reset to default and
		# clobber accumulated data.
		from secator.utils import atomic_json, read_json
		Path(self.path).write_text('{ not valid json')
		with self.assertRaises(json.JSONDecodeError):
			read_json(self.path, default=lambda: {'items': []})
		with self.assertRaises(json.JSONDecodeError):
			with atomic_json(self.path, default=lambda: {'items': []}):
				pass
		self.assertEqual(Path(self.path).read_text(), '{ not valid json')  # unchanged

	def test_present_returns_data(self):
		from secator.utils import atomic_json, read_json
		with atomic_json(self.path, default=lambda: {'items': []}) as data:
			data['items'].append('a')
		self.assertEqual(read_json(self.path, default=lambda: {'items': []}), {'items': ['a']})

	def test_tolerates_concurrent_write(self):
		"""A lock-free read during concurrent writers always sees a complete old-or-new file."""
		from secator.utils import read_json
		ctx = mp.get_context('fork')
		procs = [ctx.Process(target=_proc_worker, args=(self.path, w, 25)) for w in range(4)]
		for p in procs:
			p.start()
		# Snapshot-read repeatedly while writers run — must never raise / see a torn file.
		for _ in range(200):
			snap = read_json(self.path, default=lambda: {'items': []})
			self.assertIsInstance(snap['items'], list)
		self._join(procs)


if __name__ == '__main__':
	unittest.main()

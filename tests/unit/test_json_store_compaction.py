"""The append-only JSON findings store: reads keep each finding's latest record, compaction drops
superseded versions at the end of a run, and lock sidecars are removed safely."""
import importlib
import json
import multiprocessing
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import orjson

from secator.query.json import JsonBackend
from secator.runners._base import Runner
from secator.utils import _file_lock, append_ndjson, compact_ndjson, remove_lock_sidecar, remove_lock_sidecars


def _rec(uid, status='OPEN', **extra):
	return {'_uuid': uid, '_type': 'vulnerability', 'name': f'v-{uid}', 'status': status, **extra}


def _write_lines(path, lines):
	with open(path, 'wb') as f:
		for line in lines:
			f.write((line if isinstance(line, bytes) else orjson.dumps(line)) + b'\n')


def _append_many(path, start, count):
	for i in range(start, start + count):
		append_ndjson(path, json.dumps(_rec(f'new{i}')))


class _StoreTestBase(unittest.TestCase):
	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)

	def _workspace(self, records_by_run):
		"""A json workspace (reports/<ws>/tasks/<n>/results.ndjson) and a backend over it."""
		for run, records in records_by_run.items():
			d = self.tmp / 'ws' / 'tasks' / str(run)
			d.mkdir(parents=True)
			_write_lines(d / 'results.ndjson', records)
		return JsonBackend('ws', config={'reports_dir': str(self.tmp)})


class TestLatestRecordReads(_StoreTestBase):

	RECORDS = {0: [_rec('u1'), _rec('u2'), _rec('u3'), _rec('u1', 'FIXED'), _rec('u2', 'FIXED')]}

	def test_search_count_iterate_agree_after_updates(self):
		backend = self._workspace(self.RECORDS)
		self.assertEqual([r['_uuid'] for r in backend.search({'status': 'OPEN'})], ['u3'])
		self.assertEqual(backend.count({'status': 'OPEN'}), 1)
		self.assertEqual(backend.count({'status': 'FIXED'}), 2)
		iterated = [r for batch in backend._execute_iterate({}) for r in batch]
		self.assertEqual({r['_uuid']: r['status'] for r in iterated}, {'u1': 'FIXED', 'u2': 'FIXED', 'u3': 'OPEN'})
		self.assertEqual(len(iterated), 3)

	def test_offset_skips_only_latest_records(self):
		backend = self._workspace(self.RECORDS)
		# latest order: u3, u1, u2 — stale u1/u2 records never take an offset slot
		self.assertEqual([r['_uuid'] for r in backend.search({}, limit=2)], ['u3', 'u1'])
		self.assertEqual([r['_uuid'] for r in backend.search({}, limit=2, offset=1)], ['u1', 'u2'])

	def test_point_read_returns_latest(self):
		backend = self._workspace(self.RECORDS)
		self.assertEqual(backend.search({'_uuid': 'u1'}, limit=1)[0]['status'], 'FIXED')

	def test_legacy_report_json(self):
		d = self.tmp / 'ws' / 'tasks' / '0'
		d.mkdir(parents=True)
		(d / 'report.json').write_text(json.dumps({'info': {}, 'results': {
			'vulnerability': [_rec('u1'), _rec('u2'), _rec('u1', 'FIXED')]}}))
		backend = JsonBackend('ws', config={'reports_dir': str(self.tmp)})
		self.assertEqual(backend.count({'status': 'OPEN'}), 1)
		self.assertEqual(backend.search({'_uuid': 'u1'})[0]['status'], 'FIXED')


class TestCompaction(_StoreTestBase):

	def test_drops_superseded_versions_keeps_everything_else(self):
		path = self.tmp / 'results.ndjson'
		_write_lines(path, [
			_rec('u1'), {'_type': 'info', 'message': 'no uuid'}, b'{corrupt', _rec('u2'), _rec('u1', 'FIXED')])
		with open(path, 'ab') as f:
			f.write(orjson.dumps(_rec('u3'))[:-5])  # partial last line, no newline
		self.assertTrue(compact_ndjson(path))
		lines = path.read_bytes().splitlines()
		self.assertEqual(len(lines), 5)
		self.assertEqual(orjson.loads(lines[0]), {'_type': 'info', 'message': 'no uuid'})
		self.assertEqual(lines[1], b'{corrupt')
		self.assertEqual(orjson.loads(lines[2])['_uuid'], 'u2')
		self.assertEqual(orjson.loads(lines[3]), _rec('u1', 'FIXED'))  # latest kept, at its position
		self.assertTrue(lines[4].startswith(b'{"_uuid":"u3"'))  # partial line kept

	def test_no_rewrite_without_duplicates_and_idempotent(self):
		path = self.tmp / 'results.ndjson'
		_write_lines(path, [_rec('u1'), _rec('u2'), _rec('u1', 'FIXED')])
		self.assertTrue(compact_ndjson(path))
		inode, content = path.stat().st_ino, path.read_bytes()
		self.assertFalse(compact_ndjson(path))
		self.assertEqual((path.stat().st_ino, path.read_bytes()), (inode, content))
		self.assertFalse(compact_ndjson(self.tmp / 'missing.ndjson'))

	def test_original_intact_if_the_rewrite_fails(self):
		path = self.tmp / 'results.ndjson'
		_write_lines(path, [_rec('u1'), _rec('u1', 'FIXED')])
		before = path.read_bytes()
		with mock.patch('secator.utils.os.replace', side_effect=OSError('disk full')):
			with self.assertRaises(OSError):
				compact_ndjson(path)
		self.assertEqual(path.read_bytes(), before)
		self.assertEqual([p.name for p in self.tmp.iterdir() if p.name.endswith('.tmp')], [])

	def test_reads_identical_before_and_after_compaction(self):
		backend = self._workspace({
			0: [_rec('u1'), _rec('u2'), _rec('u1', 'FIXED'), _rec('u3'), _rec('u3', 'FIXED')],
			1: [_rec('u4'), _rec('u4', 'FIXED'), _rec('u5')]})
		queries = [{}, {'status': 'OPEN'}, {'status': 'FIXED'}, {'_uuid': 'u3'}]

		def snapshot():
			return [(backend.search(q, limit=0), backend.count(q),
				[r for b in backend._execute_iterate(q) for r in b]) for q in queries]

		before = snapshot()
		for run in (0, 1):
			self.assertTrue(compact_ndjson(self.tmp / 'ws' / 'tasks' / str(run) / 'results.ndjson'))
		self.assertEqual(snapshot(), before)

	def test_no_append_lost_while_compacting(self):
		path = self.tmp / 'results.ndjson'
		_write_lines(path, [_rec(f'u{i}') for i in range(50)] + [_rec(f'u{i}', 'FIXED') for i in range(50)])
		ctx = multiprocessing.get_context('fork')
		writer = ctx.Process(target=_append_many, args=(str(path), 0, 300))
		writer.start()
		while writer.is_alive():
			compact_ndjson(path)
			append_ndjson(path, json.dumps(_rec('u0', 'FIXED')))  # keep a duplicate to compact
		writer.join()
		compact_ndjson(path)
		uids = [orjson.loads(line)['_uuid'] for line in path.read_bytes().splitlines()]
		self.assertEqual(len(uids), len(set(uids)))
		self.assertEqual(set(uids), {f'u{i}' for i in range(50)} | {f'new{i}' for i in range(300)})


def _passthrough_hooks(self, hook_type, *args, **kwargs):
	return args[0] if args else None


class TestRunEndStoreFinalization(_StoreTestBase):

	def _run_folder_with_duplicates(self):
		from secator.hooks import json as json_driver
		from secator.output_types import Url
		mod = importlib.import_module('secator.tasks.httpx')
		(self.tmp / 'run').mkdir(exist_ok=True)
		with mock.patch.object(Runner, 'run_hooks', _passthrough_hooks):
			task = mod.httpx(['http://localhost'], reports_folder=str(self.tmp / 'run'),
				context={'drivers': ['json'], 'workspace_id': 'ws'})
		url = Url(url='http://localhost/a', _context={'workspace_id': 'ws'})
		json_driver.update_finding(task, url)
		url.tags = ['seen']
		json_driver.update_finding(task, url)  # an update: a second record for the same _uuid
		json_driver.update_runner(task)
		return task

	def test_lock_sidecars_removed_and_store_compacted_at_run_end(self):
		task = self._run_folder_with_duplicates()
		folder = Path(task.reports_folder)
		self.assertTrue(list(folder.glob('*.lock')))
		task.mark_completed()  # top-level run end: on_run_end
		self.assertEqual(list(folder.glob('*.lock')), [])
		lines = (folder / 'results.ndjson').read_bytes().splitlines()
		self.assertEqual(len(lines), 1)
		self.assertEqual(orjson.loads(lines[0])['tags'], ['seen'])

	def test_writer_after_cleanup_still_works(self):
		task = self._run_folder_with_duplicates()
		task.mark_completed()
		folder = Path(task.reports_folder)
		append_ndjson(folder / 'results.ndjson', json.dumps(_rec('late')))
		self.assertEqual(orjson.loads((folder / 'results.ndjson').read_bytes().splitlines()[-1])['_uuid'], 'late')
		self.assertTrue((folder / 'results.ndjson.lock').exists())  # recreated by the late writer
		self.assertEqual(remove_lock_sidecars(folder), 1)

	def _task(self, **opts):
		from secator.hooks import json as json_driver
		mod = importlib.import_module('secator.tasks.httpx')
		(self.tmp / 'run').mkdir(exist_ok=True)
		with mock.patch.object(Runner, 'run_hooks', _passthrough_hooks):
			task = mod.httpx(['http://localhost'], reports_folder=str(self.tmp / 'run'),
				context={'drivers': ['json'], 'workspace_id': 'ws'}, **opts)
		json_driver.update_runner(task)
		return task

	def _locks(self):
		return sorted(p.name for p in (self.tmp / 'run').glob('*.lock'))

	def test_leaf_task_lock_removed_when_it_ends(self):
		from secator.hooks import json as json_driver
		from secator.output_types import Url
		task = self._task(has_parent=True)
		json_driver.update_finding(task, Url(url='http://localhost/a', _context={'workspace_id': 'ws'}))
		self.assertEqual(self._locks(), ['report_httpx.json.lock', 'results.ndjson.lock'])
		task.mark_completed()
		# its own report lock is gone; the run-shared results.ndjson keeps its lock until the run ends
		self.assertEqual(self._locks(), ['results.ndjson.lock'])

	def test_leaf_task_lock_removed_when_it_fails(self):
		from secator.output_types import Error
		task = self._task(has_parent=True)
		task.add_result(Error(message='boom', _source=task.unique_name), print=False)
		task.mark_completed()
		self.assertEqual(task.status, 'FAILURE')
		self.assertEqual(self._locks(), ['results.ndjson.lock'])  # the error went to the shared store

	def test_chunked_task_keeps_its_lock_until_the_last_chunk_is_done(self):
		from secator.celery import mark_runner_completed
		parent = self._task(has_parent=True, has_children=True)
		chunks = [self._task(has_parent=True, chunk=n, chunk_count=2) for n in (1, 2)]
		self.assertEqual(self._locks(), [
			'report_httpx.json.lock', 'report_httpx_1.json.lock', 'report_httpx_2.json.lock'])
		chunks[0].mark_completed()
		self.assertEqual(self._locks(), ['report_httpx.json.lock', 'report_httpx_2.json.lock'])
		chunks[1].mark_completed()
		self.assertEqual(self._locks(), ['report_httpx.json.lock'])  # the chunked task itself not done yet
		mark_runner_completed([], parent)  # chord callback, after every chunk
		self.assertEqual(self._locks(), [])

	def test_shared_locks_removed_after_the_root_run(self):
		task = self._run_folder_with_duplicates()
		child = self._task(has_parent=True)
		child.mark_completed()
		self.assertEqual(self._locks(), ['report.json.lock', 'results.ndjson.lock'])
		task.mark_completed()
		self.assertEqual(self._locks(), [])

	def test_cleanup_is_silent_when_the_dir_is_not_here(self):
		self.assertFalse(remove_lock_sidecar(self.tmp / 'elsewhere' / 'report.json'))
		self.assertEqual(remove_lock_sidecars(self.tmp / 'elsewhere'), 0)

	def test_lock_retries_when_sidecar_replaced_while_waiting(self):
		"""A waiter that got the lock on a sidecar that was unlinked meanwhile must retry on the
		current file (else it would not exclude a newcomer that created a new sidecar)."""
		path = self.tmp / 'results.ndjson'
		real_stat = os.stat
		calls = {'n': 0}

		def stat(p, *args, **kwargs):
			if str(p).endswith('.lock'):
				calls['n'] += 1
				if calls['n'] == 1:
					raise FileNotFoundError(p)  # the sidecar was removed while we waited
			return real_stat(p, *args, **kwargs)

		with mock.patch('secator.utils.os.stat', side_effect=stat):
			with _file_lock(path):
				pass
		self.assertEqual(calls['n'], 2)


if __name__ == '__main__':
	unittest.main()

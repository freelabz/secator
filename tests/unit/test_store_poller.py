"""StorePoller drives a live run entirely from the store (no Celery reads)."""
import itertools
import unittest

from secator.store_utils import StorePoller


class FakeEngine:
	"""Scripted QueryEngine: one runner-frame + one finding-frame per poll cycle."""

	def __init__(self, runner_frames, finding_frames):
		self.runner_frames = runner_frames
		self.finding_frames = finding_frames
		self.cycle = -1
		self.iterate_queries = []

	def list_runners(self, report_dir=None, **kw):
		self.cycle += 1  # one list_runners call per poll cycle
		return self.runner_frames[min(self.cycle, len(self.runner_frames) - 1)]

	def iterate(self, query, batch_size=1000):
		self.iterate_queries.append(query)
		frame = self.finding_frames[min(self.cycle, len(self.finding_frames) - 1)]
		# Honour an incremental `_timestamp: {$gte: floor}` filter like a real backend would.
		floor = (query.get('_timestamp') or {}).get('$gte') if isinstance(query.get('_timestamp'), dict) else None
		yield [f for f in frame if floor is None or f.get('_timestamp', 0) >= floor]


def _root(status, progress=0):
	return {'name': 'myscan', 'status': status, 'has_parent': False,
			'context': {'scan_id': 'S'}, 'progress': progress}


def _f(uuid, ts=0):
	return {'_uuid': uuid, '_type': 'vulnerability', 'name': uuid, '_timestamp': ts}


class TestStorePoller(unittest.TestCase):

	def _poller(self, runner_frames, finding_frames, **kw):
		engine = FakeEngine(runner_frames, finding_frames)
		return StorePoller(
			engine, findings_query={'_context.scan_id': 'S'}, root_id='S', root_type='scan',
			refresh_interval=0, print_remote_info=False, sleep_func=lambda *_: None,
			rehydrate=lambda batch: batch,  # keep raw dicts in tests
			**kw,
		)

	def test_incremental_findings_and_terminal_exit(self):
		# Cycle 0: RUNNING, findings a,b. Cycle 1: SUCCESS, findings a,b,c (store returns all so far).
		runner_frames = [[_root('RUNNING', 40)], [_root('SUCCESS', 100)]]
		finding_frames = [[_f('a'), _f('b')], [_f('a'), _f('b'), _f('c')]]
		poller = self._poller(runner_frames, finding_frames, inactivity_seconds=None)
		yielded = [item['_uuid'] for item in poller.iter_results()]
		self.assertEqual(yielded, ['a', 'b', 'c'])  # no dup of a/b, and stops on SUCCESS

	def test_scope_filters_foreign_runners(self):
		# A runner from a different scan must not count as this run's root.
		foreign = {'name': 'other', 'status': 'RUNNING', 'has_parent': False, 'context': {'scan_id': 'OTHER'}}
		runner_frames = [[foreign, _root('SUCCESS')]]
		poller = self._poller(runner_frames, [[_f('a')]], inactivity_seconds=None)
		yielded = [item['_uuid'] for item in poller.iter_results()]
		self.assertEqual(yielded, ['a'])  # root S is SUCCESS -> exits; foreign RUNNING ignored

	def test_incremental_watermark_avoids_rescanning_all(self):
		# Store accumulates findings; each poll must fetch only NEW ones (via a _timestamp floor),
		# not re-scan the whole set — otherwise it's O(findings x polls).
		runner_frames = [[_root('RUNNING')], [_root('SUCCESS')]]
		finding_frames = [[_f('a', 1), _f('b', 2)], [_f('a', 1), _f('b', 2), _f('c', 3)]]
		engine = FakeEngine(runner_frames, finding_frames)
		poller = StorePoller(
			engine, findings_query={'_context.scan_id': 'S'}, root_id='S', root_type='scan',
			refresh_interval=0, print_remote_info=False, sleep_func=lambda *_: None,
			rehydrate=lambda b: b, inactivity_seconds=None,
		)
		yielded = [item['_uuid'] for item in poller.iter_results()]
		self.assertEqual(yielded, ['a', 'b', 'c'])                       # correct + no dup
		# Cycle 2 fetched only findings at/after the cycle-1 high-water (_timestamp >= 2),
		# so it re-scanned {b,c} = 2, not the full {a,b,c} = 3.
		self.assertEqual(engine.iterate_queries[1].get('_timestamp'), {'$gte': 2})
		self.assertEqual(poller._scanned, 4)                            # 2 + 2, not 2 + 3

	def test_revoked_flushes_once_and_exits(self):
		# On Ctrl+C the runner re-yields with revoked=True; the poll must flush remaining findings
		# and exit immediately, NOT wait for a terminal status (that was the revoke hardstop).
		runner_frames = [[_root('RUNNING')]]     # never terminal
		finding_frames = [[_f('a')]]
		poller = self._poller(runner_frames, finding_frames, inactivity_seconds=None, revoked=True)
		yielded = [item['_uuid'] for item in poller.iter_results()]
		self.assertEqual(yielded, ['a'])

	def test_inactivity_timeout_terminates_without_terminal_status(self):
		# Root never finalizes and nothing new arrives -> the poll must STOP (not hang).
		runner_frames = [[_root('RUNNING')]]        # clamped: always RUNNING
		finding_frames = [[_f('a')], []]            # new finding once, then nothing
		clock = itertools.count()                    # +1 per _time() call
		poller = self._poller(runner_frames, finding_frames,
							   inactivity_seconds=5, time_func=lambda: next(clock))
		yielded = [item['_uuid'] for item in poller.iter_results()]
		self.assertEqual(yielded, ['a'])             # yielded the one finding, then timed out


if __name__ == '__main__':
	unittest.main()

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

	def list_runners(self, report_dir=None, **kw):
		self.cycle += 1  # one list_runners call per poll cycle
		return self.runner_frames[min(self.cycle, len(self.runner_frames) - 1)]

	def iterate(self, query, batch_size=1000):
		yield self.finding_frames[min(self.cycle, len(self.finding_frames) - 1)]


def _root(status, progress=0):
	return {'name': 'myscan', 'status': status, 'has_parent': False,
			'context': {'scan_id': 'S'}, 'progress': progress}


def _f(uuid):
	return {'_uuid': uuid, '_type': 'vulnerability', 'name': uuid}


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

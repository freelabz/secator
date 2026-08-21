"""The runner's yielder live-polls the store (StorePoller) when the store is a reachable shared
backend, and falls back to the Celery result-backend poll otherwise (see _base._poll_results)."""
import unittest

from secator.runners._base import Runner


class FakeEngine:
	def __init__(self, shared):
		self._shared = shared

	def pollable_shared_store(self):
		return self._shared


class FakePoller:
	def __init__(self, shared=True):
		self.called = False
		self.engine = FakeEngine(shared)

	def iter_results(self):
		self.called = True
		yield {'_uuid': 'store'}


def _runner(poller, celery_result=None):
	r = Runner.__new__(Runner)          # bypass heavy __init__; set only what the poll touches
	r.celery_result = celery_result
	r._get_store_poller = lambda: poller
	r.debug = lambda *a, **k: None
	return r


class TestRunnerStorePoll(unittest.TestCase):

	def test_yielder_polls_store_when_shared_and_reachable(self):
		poller = FakePoller(shared=True)
		out = list(Runner.yielder(_runner(poller, celery_result=object())))
		self.assertTrue(poller.called)
		self.assertEqual(out, [{'_uuid': 'store'}])

	def test_in_process_run_uses_store_even_if_not_shared(self):
		# No celery result (sync/in-process): the local store is on the same machine, so poll it
		# regardless of shared-ness.
		poller = FakePoller(shared=False)
		out = list(_runner(poller, celery_result=None)._poll_results())
		self.assertTrue(poller.called)
		self.assertEqual(out, [{'_uuid': 'store'}])

	def test_dispatched_non_shared_store_falls_back_to_celery(self):
		import secator.celery_utils as cu
		calls = {}

		def fake_iter(result, **kwargs):
			calls['kwargs'] = kwargs
			yield {'_uuid': 'celery'}

		orig = cu.CeleryData.iter_results
		cu.CeleryData.iter_results = staticmethod(fake_iter)
		try:
			poller = FakePoller(shared=False)
			r = _runner(poller, celery_result=object())
			r.celery_ids_map = {}
			r.revoked = False
			r.print_remote_info = False
			r.name = 'x'
			out = list(r._poll_results())
		finally:
			cu.CeleryData.iter_results = orig
		self.assertFalse(poller.called)                 # store poll NOT used
		self.assertEqual(out, [{'_uuid': 'celery'}])    # celery fallback used instead
		self.assertIn('kwargs', calls)

	def test_empty_without_scope_or_celery(self):
		# No store scope AND no celery result -> yields nothing rather than crashing.
		r = Runner.__new__(Runner)
		r.celery_result = None
		r._get_store_poller = lambda: None
		r.debug = lambda *a, **k: None
		self.assertEqual(list(r._poll_results()), [])


if __name__ == '__main__':
	unittest.main()

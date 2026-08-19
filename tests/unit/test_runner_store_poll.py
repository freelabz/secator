"""The runner's yielder live-polls the store (StorePoller) — now the only poll path."""
import unittest

from secator.runners._base import Runner


class FakePoller:
	def __init__(self):
		self.called = False

	def iter_results(self):
		self.called = True
		yield {'_uuid': 'store'}


def _runner(poller):
	r = Runner.__new__(Runner)          # bypass heavy __init__; set only what yielder touches
	r.celery_result = object()          # truthy -> remote poll branch
	r._get_store_poller = lambda: poller
	r.debug = lambda *a, **k: None
	return r


class TestRunnerStorePoll(unittest.TestCase):

	def test_yielder_polls_the_store(self):
		poller = FakePoller()
		out = list(Runner.yielder(_runner(poller)))
		self.assertTrue(poller.called)
		self.assertEqual(out, [{'_uuid': 'store'}])

	def test_poll_results_empty_without_scope(self):
		# No store scope (e.g. missing {type}_id) -> yields nothing rather than crashing.
		r = Runner.__new__(Runner)
		r._get_store_poller = lambda: None
		r.debug = lambda *a, **k: None
		self.assertEqual(list(r._poll_results()), [])


if __name__ == '__main__':
	unittest.main()

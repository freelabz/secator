"""The runner's yielder uses StorePoller only under SECATOR_STORE_POLL=1 (default: Celery poll)."""
import os
import unittest
from unittest.mock import patch

from secator.runners._base import Runner


class FakePoller:
	def __init__(self):
		self.called = False

	def iter_results(self):
		self.called = True
		yield {'_uuid': 'store'}


def _runner(poller):
	r = Runner.__new__(Runner)          # bypass heavy __init__; set only what yielder touches
	r.celery_result = object()          # truthy -> takes the remote-poll branch
	r._get_store_poller = lambda: poller
	r.celery_ids_map = {}
	r.revoked = False
	r.print_remote_info = False
	r.name = 'x'
	return r


class TestRunnerStorePollWire(unittest.TestCase):

	def test_flag_on_uses_store_poller(self):
		poller = FakePoller()
		with patch.dict(os.environ, {'SECATOR_STORE_POLL': '1'}):
			out = list(Runner.yielder(_runner(poller)))
		self.assertTrue(poller.called)
		self.assertEqual(out, [{'_uuid': 'store'}])

	def test_flag_off_uses_celery_poll(self):
		poller = FakePoller()
		env = {k: v for k, v in os.environ.items() if k != 'SECATOR_STORE_POLL'}
		with patch.dict(os.environ, env, clear=True), \
			 patch('secator.runners._base.CeleryData') as CD:
			CD.iter_results.return_value = iter([{'_uuid': 'celery'}])
			out = list(Runner.yielder(_runner(poller)))
		self.assertFalse(poller.called)
		CD.iter_results.assert_called_once()
		self.assertEqual(out, [{'_uuid': 'celery'}])


if __name__ == '__main__':
	unittest.main()

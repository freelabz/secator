"""Worker kill-after-task bookkeeping: in-process child tasks, process targeting, consuming."""
import unittest
from types import SimpleNamespace
from unittest import mock

from celery import signals

from secator import celery_signals
from secator.celery import app


@app.task
def _noop():
	return []


def _kill_after_task(enabled=True):
	return mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', enabled)


class TestEagerChild(unittest.TestCase):

	def test_eager_child_keeps_worker_and_marker(self):
		for signal, handler in (
			(signals.task_prerun, celery_signals.task_prerun_handler),
			(signals.task_postrun, celery_signals.task_postrun_handler),
		):
			signal.connect(handler, weak=False)
			self.addCleanup(signal.disconnect, handler)
		self.addCleanup(celery_signals.clear_task_running)
		celery_signals.set_task_running('outer')
		with _kill_after_task(), mock.patch.object(celery_signals, 'kill_worker') as kill:
			_noop.apply()
		kill.assert_not_called()
		self.assertEqual(celery_signals.get_lock_file_path().read_text(), 'outer')


class TestPostrunKill(unittest.TestCase):

	def _postrun(self, pool_child):
		task = SimpleNamespace(name='secator.celery.run_command', request=SimpleNamespace(is_eager=False))
		with (
			_kill_after_task(),
			mock.patch.object(celery_signals, 'in_pool_child', return_value=pool_child),
			mock.patch.object(celery_signals, 'kill_worker') as kill,
		):
			celery_signals.task_postrun_handler(sender=task, task=task)
		return kill

	def test_prefork_child_signals_its_parent(self):
		self._postrun(pool_child=True).assert_called_once_with(parent=True)

	def test_other_pools_signal_the_current_process(self):
		self._postrun(pool_child=False).assert_called_once_with(parent=False)
		self.assertFalse(celery_signals.in_pool_child())  # tests run in a main process


class TestStopConsumingOnReceive(unittest.TestCase):

	def _receive(self, task_name, enabled=True):
		consumer = mock.MagicMock()
		consumer.task_consumer.queues = [SimpleNamespace(name='small-fast'), SimpleNamespace(name='poll')]
		with _kill_after_task(enabled):
			celery_signals.task_received_handler(sender=consumer, request=SimpleNamespace(name=task_name))
		return consumer.cancel_task_queue

	def test_received_task_cancels_every_queue(self):
		for name in ('secator.celery.run_command', 'api.tasks.run'):
			self.assertEqual(self._receive(name).call_args_list, [mock.call('small-fast'), mock.call('poll')])

	def test_keeps_consuming_for_other_tasks_or_without_kill_after_task(self):
		self._receive('other.task').assert_not_called()
		self._receive('secator.celery.run_command', enabled=False).assert_not_called()

	def test_connected_only_with_kill_after_task(self):
		for enabled in (True, False):
			with (
				_kill_after_task(enabled),
				mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_idle_seconds', 20),
				mock.patch.object(celery_signals.CONFIG.celery, 'override_default_logging', False),
				mock.patch.object(celery_signals, 'signals') as sig,
			):
				celery_signals.setup_handlers()
			self.assertEqual(sig.task_received.connect.called, enabled)
			sig.task_revoked.connect.assert_called_once_with(celery_signals.task_revoked_handler)

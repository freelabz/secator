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


class TestKillAfterTaskSignal(unittest.TestCase):
	"""What the worker actually receives at the end of its one task, on a gevent / threads / solo
	pool (the task runs in the worker's main process, whose parent is a wrapper or PID 1)."""

	WORKER_PID = 4242
	PARENT_PID = 1

	def _run(self, *handlers):
		task = SimpleNamespace(name='secator.celery.run_command', request=SimpleNamespace(is_eager=False))
		self.addCleanup(celery_signals.clear_task_running)
		with (
			_kill_after_task(),
			mock.patch('billiard.current_process', return_value=SimpleNamespace(name='MainProcess')),
			mock.patch.object(celery_signals.os, 'getpid', return_value=self.WORKER_PID),
			mock.patch.object(celery_signals.os, 'getppid', return_value=self.PARENT_PID),
			mock.patch.object(celery_signals.os, 'kill') as kill,
		):
			for handler in handlers:
				handler(task)
		return kill

	def test_postrun_warm_stops_the_worker_process_not_its_parent(self):
		kill = self._run(
			lambda t: celery_signals.task_prerun_handler(task_id='t1', task=t),
			lambda t: celery_signals.task_postrun_handler(sender=t, task=t),
		)
		# SIGTERM is Celery's warm shutdown: the worker lets the in-flight task finish and its
		# late ack go out before exiting (a cold SIGQUIT / SIGKILL would lose the ack).
		kill.assert_called_once_with(self.WORKER_PID, celery_signals.signal.SIGTERM)

	def test_no_signal_before_the_task_has_run(self):
		consumer = mock.MagicMock()
		consumer.task_consumer.queues = [SimpleNamespace(name='small-fast')]
		kill = self._run(
			lambda t: celery_signals.task_received_handler(sender=consumer, request=SimpleNamespace(name=t.name)),
			lambda t: celery_signals.task_prerun_handler(task_id='t1', task=t),
		)
		kill.assert_not_called()
		consumer.cancel_task_queue.assert_called_once_with('small-fast')

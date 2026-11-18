"""Worker kill-after-task bookkeeping when a task runs a child task in-process."""
import unittest
from types import SimpleNamespace
from unittest import mock

from celery import signals

from secator import celery_signals
from secator.celery import app


@app.task
def _noop():
	return []


class TestPostrunEagerChild(unittest.TestCase):
	"""An in-process (eager) child task fires task_postrun in the worker's own process, whatever
	the pool type: it must not end the outer task's bookkeeping."""

	def _apply(self, eager):
		seen = []

		def record(task=None, **_):
			seen.append(task.request.is_eager)
		signals.task_postrun.connect(record, weak=False)
		signals.task_postrun.connect(celery_signals.task_postrun_handler, weak=False)
		self.addCleanup(signals.task_postrun.disconnect, record)
		self.addCleanup(signals.task_postrun.disconnect, celery_signals.task_postrun_handler)
		with (
			mock.patch.object(celery_signals, 'kill_worker', return_value=True) as kill,
			mock.patch.object(celery_signals, 'clear_task_running') as clear,
			mock.patch.object(celery_signals, 'IDLE_TIMEOUT', -1),
			mock.patch.object(celery_signals, '_shutdown_requested', False),
			mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', True),
		):
			if eager:
				_noop.apply()
			else:
				task = SimpleNamespace(name='secator.celery.run_command', request=SimpleNamespace(is_eager=False))
				celery_signals.task_postrun_handler(sender=task, task=task)
		return seen, kill, clear

	def test_eager_child_fires_postrun_but_keeps_worker(self):
		seen, kill, clear = self._apply(eager=True)
		self.assertEqual(seen, [True])
		kill.assert_not_called()
		clear.assert_not_called()

	def test_worker_task_kills_worker_after_task(self):
		# the worker's main process is the parent only when the task ran in a prefork pool child
		for pool_child in (True, False):
			with mock.patch.object(celery_signals, 'in_pool_child', return_value=pool_child):
				_, kill, clear = self._apply(eager=False)
			clear.assert_called_once()
			kill.assert_called_once_with(parent=pool_child)

	def test_main_process_is_not_a_pool_child(self):
		self.assertFalse(celery_signals.in_pool_child())


class _KillAfterTask(unittest.TestCase):

	def setUp(self):
		patches = [
			mock.patch.object(celery_signals, 'kill_worker', return_value=True),
			mock.patch.object(celery_signals, 'setup_idle_timer'),
			mock.patch.object(celery_signals, 'IDLE_TIMEOUT', 20),
			mock.patch.object(celery_signals, '_shutdown_requested', False),
			mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', True),
		]
		self.kill, self.timer = patches[0].start(), patches[1].start()
		for p in patches[2:]:
			p.start()
		for p in patches:
			self.addCleanup(p.stop)
		self.addCleanup(celery_signals.clear_task_running)
		celery_signals.clear_task_running()


class TestRevokedOwnTask(_KillAfterTask):
	"""The worker's own task being revoked ends the worker too (no task_postrun after a revoke)."""

	task = SimpleNamespace(name='secator.celery.run_command')

	def test_revoked_own_task_kills_worker(self):
		celery_signals.set_task_running('t1')
		celery_signals.task_revoked_handler(request=SimpleNamespace(id='t1'), sender=self.task)
		self.kill.assert_called_once_with(parent=False)
		self.assertFalse(celery_signals.is_task_running())
		self.timer.assert_not_called()

	def test_revoked_with_kill_after_task_off_resets_idle_timer(self):
		celery_signals.set_task_running('t1')
		with mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', False):
			celery_signals.task_revoked_handler(request=SimpleNamespace(id='t1'), sender=self.task)
		self.kill.assert_not_called()
		self.timer.assert_called_once_with(20)

	def test_revoked_other_task_keeps_running_task(self):
		celery_signals.set_task_running('t1')
		celery_signals.task_revoked_handler(request=SimpleNamespace(id='other'), sender=self.task)
		self.kill.assert_not_called()
		self.assertTrue(celery_signals.is_task_running())

	def test_eager_child_keeps_outer_task_marker(self):
		signals.task_prerun.connect(celery_signals.task_prerun_handler, weak=False)
		signals.task_postrun.connect(celery_signals.task_postrun_handler, weak=False)
		self.addCleanup(signals.task_prerun.disconnect, celery_signals.task_prerun_handler)
		self.addCleanup(signals.task_postrun.disconnect, celery_signals.task_postrun_handler)
		celery_signals.set_task_running('outer')
		_noop.apply()  # eager child: prerun + postrun in this process
		self.assertEqual(celery_signals.get_running_task_id(), 'outer')
		celery_signals.task_revoked_handler(request=SimpleNamespace(id='outer'), sender=self.task)
		self.kill.assert_called_once_with(parent=False)

	def test_cancelled_shutdown_can_be_retried(self):
		self.kill.side_effect = [False, True]
		celery_signals.shutdown_after_task()
		celery_signals.shutdown_after_task()
		celery_signals.shutdown_after_task()
		self.assertEqual(self.kill.call_count, 2)

	def test_revoke_then_postrun_shuts_down_once(self):
		celery_signals.set_task_running('t1')
		celery_signals.task_revoked_handler(request=SimpleNamespace(id='t1'), sender=self.task)
		task = SimpleNamespace(name=self.task.name, request=SimpleNamespace(is_eager=False))
		celery_signals.task_postrun_handler(sender=task, task=task)
		self.kill.assert_called_once()


if __name__ == '__main__':
	unittest.main()


class TestStopConsumingOnReceive(_KillAfterTask):
	"""A worker that ends after its task stops consuming as soon as that task is received."""

	def _consumer(self):
		consumer = mock.MagicMock()
		consumer.task_consumer.queues = [SimpleNamespace(name='small-fast'), SimpleNamespace(name='poll')]
		return consumer

	def test_received_task_cancels_every_queue(self):
		consumer = self._consumer()
		celery_signals.task_received_handler(sender=consumer, request=SimpleNamespace(name='secator.celery.run_command'))
		self.assertEqual(consumer.cancel_task_queue.call_args_list, [mock.call('small-fast'), mock.call('poll')])

	def test_other_task_keeps_consuming(self):
		consumer = self._consumer()
		celery_signals.task_received_handler(sender=consumer, request=SimpleNamespace(name='other.task'))
		consumer.cancel_task_queue.assert_not_called()

	def test_kill_after_task_off_keeps_consuming(self):
		consumer = self._consumer()
		with mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', False):
			celery_signals.task_received_handler(sender=consumer, request=SimpleNamespace(name='secator.celery.run_command'))
		consumer.cancel_task_queue.assert_not_called()

	def test_registered_only_with_kill_after_task(self):
		for enabled in (True, False):
			with (
				mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', enabled),
				mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_idle_seconds', 20),
				mock.patch.object(celery_signals.CONFIG.celery, 'override_default_logging', False),
				mock.patch.object(signals.task_received, 'connect') as connect,
				mock.patch.object(signals.celeryd_after_setup, 'connect'),
				mock.patch.object(signals.task_postrun, 'connect'),
				mock.patch.object(signals.task_prerun, 'connect'),
				mock.patch.object(signals.task_revoked, 'connect'),
				mock.patch.object(signals.worker_ready, 'connect'),
				mock.patch.object(signals.worker_shutdown, 'connect'),
			):
				celery_signals.setup_handlers()
			self.assertEqual(connect.call_args_list, [mock.call(celery_signals.task_received_handler)] if enabled else [])

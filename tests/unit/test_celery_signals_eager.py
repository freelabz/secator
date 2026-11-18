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
			mock.patch.object(celery_signals, 'kill_worker') as kill,
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
			mock.patch.object(celery_signals, 'kill_worker'),
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

	def test_revoke_then_postrun_shuts_down_once(self):
		celery_signals.set_task_running('t1')
		celery_signals.task_revoked_handler(request=SimpleNamespace(id='t1'), sender=self.task)
		task = SimpleNamespace(name=self.task.name, request=SimpleNamespace(is_eager=False))
		celery_signals.task_postrun_handler(sender=task, task=task)
		self.kill.assert_called_once()


if __name__ == '__main__':
	unittest.main()

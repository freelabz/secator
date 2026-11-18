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


if __name__ == '__main__':
	unittest.main()

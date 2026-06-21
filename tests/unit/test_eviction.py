import queue
import threading
import types
import unittest
import unittest.mock
from pathlib import Path
import shutil
import tempfile

import secator.celery_signals as cs
from secator.celery_signals import (
	clear_shutdown_flag,
	is_worker_shutting_down,
	worker_shutting_down_handler,
)
from secator.runners import command as command_mod


class TestEvictionSelfFinalize(unittest.TestCase):
	"""Worker-eviction self-finalize: on shutdown (e.g. a K8s pod SIGTERM eviction) the in-flight
	task's monitor stops it early and returns partial results, so the surrounding chord proceeds
	instead of hanging until the broker visibility timeout redelivers the task."""

	def setUp(self):
		# Isolate the shutdown flag to a per-test temp path so tests can't interfere with each
		# other (or with a real worker) through the shared global flag file.
		self._tmpdir = tempfile.mkdtemp()
		self._patcher = unittest.mock.patch.object(cs, 'SHUTDOWN_FLAG', Path(self._tmpdir) / 'worker_shutdown')
		self._patcher.start()
		clear_shutdown_flag()

	def tearDown(self):
		clear_shutdown_flag()
		self._patcher.stop()
		shutil.rmtree(self._tmpdir, ignore_errors=True)

	def _bare_command(self, process):
		"""A Command shell with only the attributes _monitor_process touches (no real subprocess)."""
		cmd = command_mod.Command.__new__(command_mod.Command)
		cmd.process = process
		cmd.monitor_stop_event = threading.Event()
		cmd.monitor_queue = queue.Queue()
		cmd.debug = lambda *a, **k: None
		return cmd

	def test_shutdown_flag_lifecycle(self):
		"""worker_shutting_down_handler raises the flag; clear_shutdown_flag drops it."""
		self.assertFalse(is_worker_shutting_down())
		worker_shutting_down_handler()
		self.assertTrue(is_worker_shutting_down())
		clear_shutdown_flag()
		self.assertFalse(is_worker_shutting_down())

	def test_monitor_stops_process_when_flag_set(self):
		"""When a shutdown is raised during the run, the monitor stops the process (exit_ok=True, so
		the task returns partial results) and emits the eviction Warning — letting the chord proceed."""
		cmd = self._bare_command(types.SimpleNamespace(pid=999999))
		stopped = {}
		cmd.stop_process = lambda **kw: (stopped.update(kw), cmd.monitor_stop_event.set())
		with unittest.mock.patch('secator.celery_signals.is_worker_shutting_down', return_value=True):
			cmd._monitor_process()
		self.assertTrue(stopped.get('exit_ok'), 'monitor did not stop the process on the shutdown flag')
		queued = []
		while not cmd.monitor_queue.empty():
			queued.append(cmd.monitor_queue.get())
		self.assertTrue(
			any('shutting down' in str(getattr(i, 'message', '')).lower() for i in queued),
			'monitor did not emit the eviction warning',
		)

	def test_monitor_clears_stale_flag_at_start(self):
		"""The monitor clears any pre-existing (stale) flag at start, so a flag left by a previous
		worker sharing the state dir does not stop a fresh task. Regression for the integration leak:
		a leaked flag had been self-aborting every later task."""
		worker_shutting_down_handler()                 # stale flag present before the task starts
		self.assertTrue(is_worker_shutting_down())
		cmd = self._bare_command(None)                 # process=None -> loop breaks right after the clear
		cmd._monitor_process()
		self.assertFalse(is_worker_shutting_down(), 'monitor did not clear the stale flag at start')


if __name__ == '__main__':
	unittest.main()

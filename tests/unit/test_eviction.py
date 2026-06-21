import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

import secator.celery_signals as cs
from secator.celery_signals import (
	clear_shutdown_flag,
	is_worker_shutting_down,
	worker_shutting_down_handler,
)
from secator.runners import Command


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

	def _eviction_signals(self, cmd):
		return [
			item for item in (cmd.warnings + cmd.results)
			if 'shutting down' in str(getattr(item, 'message', '')).lower()
		]

	def test_shutdown_flag_lifecycle(self):
		"""worker_shutting_down_handler raises the flag; clear_shutdown_flag drops it."""
		self.assertFalse(is_worker_shutting_down())
		worker_shutting_down_handler()
		self.assertTrue(is_worker_shutting_down())
		clear_shutdown_flag()
		self.assertFalse(is_worker_shutting_down())

	def test_monitor_stops_running_command_on_shutdown(self):
		"""A long-running command stops early once the flag is raised *during* the run (instead of
		running to completion), and emits the eviction Warning — proving the monitor self-stop."""
		holder = {}

		def run():
			holder['cmd'] = Command.execute('sleep 30', name='evict_sleep', process=True, quiet=True)

		t = threading.Thread(target=run, daemon=True)
		# Poll fast so the test doesn't wait the full stat-update cadence.
		with unittest.mock.patch('secator.runners.command.MONITOR_POLL_SECONDS', 1):
			start = time.monotonic()
			t.start()
			# Keep raising the flag until the task stops. The monitor clears any pre-existing flag
			# once at startup, so a single set could be wiped if it raced ahead of a slow monitor
			# start; re-raising guarantees the monitor's poll sees it once it is running.
			deadline = time.monotonic() + 20
			while t.is_alive() and time.monotonic() < deadline:
				worker_shutting_down_handler()   # simulate the eviction SIGTERM, mid-run
				time.sleep(0.5)
			t.join(timeout=5)
			elapsed = time.monotonic() - start

		self.assertFalse(t.is_alive(), 'command did not stop after the shutdown flag was raised')
		self.assertLess(elapsed, 25, 'command did not stop early (ran toward the full 30s sleep)')
		self.assertTrue(self._eviction_signals(holder['cmd']), 'no eviction warning emitted on shutdown')

	def test_stale_flag_does_not_stop_fresh_task(self):
		"""A flag already set *before* a task starts (stale, e.g. left by a previous worker sharing
		the state dir) must NOT stop it: the monitor clears it at start and only honours a shutdown
		raised during the run. This is the regression for the integration-suite leak."""
		worker_shutting_down_handler()  # pre-existing / stale flag
		self.assertTrue(is_worker_shutting_down())
		cmd = Command.execute('sleep 3', name='stale_flag', process=True, quiet=True)
		self.assertFalse(self._eviction_signals(cmd), 'a stale flag wrongly stopped a fresh task')


if __name__ == '__main__':
	unittest.main()

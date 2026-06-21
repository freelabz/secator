import threading
import time
import unittest
import unittest.mock

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
		clear_shutdown_flag()

	def tearDown(self):
		clear_shutdown_flag()

	def test_shutdown_flag_lifecycle(self):
		"""worker_shutting_down_handler raises the flag; clear_shutdown_flag drops it."""
		self.assertFalse(is_worker_shutting_down())
		worker_shutting_down_handler()
		self.assertTrue(is_worker_shutting_down())
		clear_shutdown_flag()
		self.assertFalse(is_worker_shutting_down())

	def test_monitor_stops_running_command_on_shutdown(self):
		"""A long-running command stops early once the flag is raised (instead of running to
		completion), and emits the eviction Warning — proving the monitor self-stop path."""
		holder = {}

		def run():
			holder['cmd'] = Command.execute('sleep 30', name='evict_sleep', process=True, quiet=True)

		t = threading.Thread(target=run, daemon=True)
		# Poll fast so the test doesn't wait the full stat-update cadence.
		with unittest.mock.patch('secator.runners.command.MONITOR_POLL_SECONDS', 1):
			start = time.monotonic()
			t.start()
			time.sleep(2)                    # let the subprocess + monitor thread start
			worker_shutting_down_handler()   # simulate the eviction SIGTERM
			t.join(timeout=20)
			elapsed = time.monotonic() - start

		self.assertFalse(t.is_alive(), 'command did not stop after the shutdown flag was raised')
		self.assertLess(elapsed, 25, 'command did not stop early (ran toward the full 30s sleep)')

		cmd = holder['cmd']
		signals = [
			item for item in (cmd.warnings + cmd.results)
			if 'shutting down' in str(getattr(item, 'message', '')).lower()
		]
		self.assertTrue(signals, 'no eviction warning emitted on shutdown')


if __name__ == '__main__':
	unittest.main()

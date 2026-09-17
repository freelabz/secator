"""The Command monitor thread must survive transient errors (#1374): it also enforces the task
timeout and memory limit, so bailing out on the first EMFILE silently disabled both."""
import errno
import unittest
from unittest import mock

from secator.config import CONFIG
from secator.runners import Command
from secator.output_types import Warning


class sleeper(Command):
	cmd = 'sleep'
	input_flag = None
	max_timeout = 1


class TestMonitorThreadResilience(unittest.TestCase):

	def test_timeout_still_enforced_after_transient_error(self):
		calls = {'n': 0}

		def flaky_collect_stats(self):
			calls['n'] += 1
			if calls['n'] <= 2:
				raise OSError(errno.EMFILE, 'Too many open files', '/proc/1/stat')
			return iter(())

		with mock.patch.object(CONFIG.runners, 'stat_update_frequency', 0.1), \
			mock.patch.object(Command, '_collect_stats', flaky_collect_stats):
			task = sleeper(['30'], print_cmd=False, print_item=False, print_line=False, print_progress=False)
			results = task.run()

		self.assertGreater(calls['n'], 2)  # monitor kept ticking after the errors
		warnings = [str(r.message) for r in results if isinstance(r, Warning)]
		self.assertEqual(sum('Monitor thread error' in w for w in warnings), 1)  # warned once, not per tick
		self.assertTrue(any('Task timeout' in w for w in warnings), warnings)  # ...and still killed on timeout

	def test_monitor_collects_lean_attrs_only(self):
		import psutil
		with mock.patch.object(psutil.Process, 'as_dict', return_value={'name': 'x', 'pid': 1}) as as_dict:
			with mock.patch.object(psutil.Process, 'children', return_value=[]):
				list(Command.get_process_info(psutil.Process(), children=True, attrs=Command.MONITOR_ATTRS))
		as_dict.assert_called_once_with(attrs=Command.MONITOR_ATTRS)

"""on_cmd_done runs once when a command is killed, so partial output files get parsed (#977)."""
import os
import tempfile
import unittest
from unittest import mock

from secator.runners import Command
from secator.output_types import Error, Info

OPTS = dict(print_cmd=False, print_item=False, print_line=False, print_progress=False)
OUTPUT = os.path.join(tempfile.mkdtemp(), 'out.xml')


def interrupt(self, line):
	raise KeyboardInterrupt()
	yield  # generator, like process_line


class writer(Command):
	"""Writes its output file, then hangs like a long nmap scan."""
	cmd = f'sh -c "echo partial > {OUTPUT}; echo started; sleep 30"'
	input_flag = None
	calls = []

	@staticmethod
	def on_cmd_done(self):
		writer.calls.append(1)
		with open(OUTPUT) as f:
			yield Info(message=f.read().strip())


class TestOnCmdDoneOnKill(unittest.TestCase):

	def setUp(self):
		writer.calls.clear()

	def run_task(self, cmd=writer.cmd):
		task = writer(['x'], **OPTS)
		task.cmd = cmd
		with mock.patch.object(Command, 'process_line', interrupt):
			results = task.run()
		self.assertTrue(task.killed)
		return results

	def test_partial_output_parsed_once(self):
		results = self.run_task()
		self.assertEqual(writer.calls, [1])
		self.assertIn('partial', [r.message for r in results if isinstance(r, Info)])

	def test_not_rerun_when_killed_during_on_cmd_done(self):
		def ctrl_c(self):
			writer.calls.append(1)
			raise KeyboardInterrupt()

		with mock.patch.object(writer, 'on_cmd_done', staticmethod(ctrl_c)):
			self.run_task(cmd='sh -c "exec >&- 2>&-; sleep 30"')  # no output, still running in on_cmd_done
		self.assertEqual(writer.calls, [1])

	def test_failing_hook_is_an_error(self):
		"""The kill path relies on run_hooks to report a failing hook."""
		with mock.patch.object(writer, 'on_cmd_done', staticmethod(lambda self: 1 / 0)):
			results = self.run_task()
		self.assertTrue(any(isinstance(r, Error) and 'execution failed' in r.message for r in results), results)

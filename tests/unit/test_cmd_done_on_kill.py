"""CTRL+C (KeyboardInterrupt) must still run on_cmd_done so partial output files get parsed (#977)."""
import unittest
from unittest import mock

from secator.runners import Command
from secator.output_types import Error, Info

OPTS = dict(print_cmd=False, print_item=False, print_line=False, print_progress=False)


class writer(Command):
	cmd = 'sh -c "echo started; sleep 30"'
	input_flag = None

	@staticmethod
	def on_cmd_done(self):
		yield Info(message='parsed partial output')


class TestOnCmdDoneOnKill(unittest.TestCase):

	def test_hooks_run_after_ctrl_c(self):
		def interrupt(self, line):
			raise KeyboardInterrupt()
			yield  # keep it a generator like process_line

		task = writer(['x'], **OPTS)
		with mock.patch.object(Command, 'process_line', interrupt):
			results = task.run()
		self.assertTrue(task.killed)
		self.assertTrue(any(isinstance(r, Error) and 'killed manually' in r.message for r in results))
		self.assertTrue(any(isinstance(r, Info) and r.message == 'parsed partial output' for r in results), results)

	def test_hooks_not_run_twice_when_killed_during_parsing(self):
		calls = []

		class parser(Command):
			cmd = 'echo done'
			input_flag = None

			@staticmethod
			def on_cmd_done(self):
				calls.append(1)
				raise KeyboardInterrupt()
				yield

		parser(['x'], **OPTS).run()
		self.assertEqual(len(calls), 1)

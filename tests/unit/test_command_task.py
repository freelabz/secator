import unittest

from secator.runners import Command
from secator.tasks.command import command


class TestCommandTask(unittest.TestCase):
	"""The generic `command` task runs an arbitrary command line verbatim in shell mode."""

	def test_runs_verbatim_and_captures_stdout(self):
		"""A trivial echo runs through the real Command yielder and reaches SUCCESS with stdout captured."""
		runner = command(inputs=["echo secator-pr3"], run_opts={"sync": True, "print_line": False, "print_item": False})
		runner.run()
		self.assertEqual(runner.status, "SUCCESS")
		self.assertIn("secator-pr3", runner.output)
		self.assertEqual(runner.return_code, 0)

	def test_shell_metacharacters_are_interpreted(self):
		"""Shell operators (&&) must be interpreted, not passed as literal echo args.

		Under shell=False the whole string is shlex-split and `&&` becomes a literal echo
		argument, so only the first echo runs and 'world' never appears. This proves the
		task actually runs in shell mode end-to-end.
		"""
		opts = {"sync": True, "print_line": False, "print_item": False}
		runner = command(inputs=["echo hello && echo world"], run_opts=opts)
		runner.run()
		self.assertEqual(runner.status, "SUCCESS")
		self.assertIn("hello", runner.output)
		self.assertIn("world", runner.output)
		# Under shell=False the whole thing is one echo, so '&&' is echoed literally.
		# Interpreted correctly, '&&' is an operator and never appears in stdout.
		self.assertNotIn("&&", runner.output)
		self.assertTrue(runner.shell)

	def test_empty_inputs_does_not_crash(self):
		"""With no inputs, _build_cmd must not crash (cmd stays empty rather than indexing inputs[0])."""
		runner = command(inputs=[], run_opts={"sync": True, "print_line": False, "print_item": False})
		runner._build_cmd()
		self.assertEqual(runner.cmd, "")

	def test_is_a_command_subclass(self):
		"""Sanity check on the inheritance the rest of the PR relies on."""
		self.assertTrue(issubclass(command, Command))

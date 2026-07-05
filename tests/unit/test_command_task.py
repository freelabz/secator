import os
import unittest
from unittest import mock

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

	def test_bare_single_word_command_is_not_stripped(self):
		"""A bare single-word command (no space) must run, not get type-filtered away.

		`input_types` must be [] — a non-empty input_types makes the base _validate_inputs()
		run autodetect_type() and DROP inputs whose detected type isn't listed. "true" is
		autodetected as 'slug', so [STRING] would strip it -> empty inputs -> empty cmd ->
		FAILURE. This is the exact shape that broke most ordinary commands.
		"""
		runner = command(inputs=["true"], run_opts={"sync": True, "print_line": False, "print_item": False})
		runner.run()
		self.assertEqual(runner.cmd, "true")
		self.assertEqual(runner.status, "SUCCESS")

	def test_empty_inputs_does_not_crash(self):
		"""With no inputs, _build_cmd must not crash (cmd stays empty rather than indexing inputs[0])."""
		runner = command(inputs=[], run_opts={"sync": True, "print_line": False, "print_item": False})
		runner._build_cmd()
		self.assertEqual(runner.cmd, "")

	def test_is_a_command_subclass(self):
		"""Sanity check on the inheritance the rest of the PR relies on."""
		self.assertTrue(issubclass(command, Command))

	def test_env_run_opt_is_honored(self):
		"""A custom `env` run_opt overrides the process env for the subprocess.

		The AI shell handler relies on this to pass a SANITIZED env (LLM key / cloud
		creds stripped) so an AI-run `env`/`printenv` can't leak them. PATH is included
		so /bin/sh can still resolve the shell builtin. Opts are spread as kwargs
		(command takes **run_opts) so `env` actually reaches self.run_opts.
		"""
		custom_env = {'FOO': 'bar', 'PATH': os.environ.get('PATH', '')}
		runner = command(
			['echo $FOO'],
			sync=True, print_line=False, print_item=False, env=custom_env,
		)
		runner.run()
		self.assertEqual(runner.status, 'SUCCESS')
		self.assertIn('bar', runner.output)

	def test_no_env_run_opt_uses_process_env(self):
		"""Control: with no `env` run_opt, the subprocess inherits the process env
		(default behavior unchanged)."""
		with mock.patch.dict(os.environ, {'SECATOR_ENV_PROBE': 'present'}):
			runner = command(
				['echo $SECATOR_ENV_PROBE'],
				sync=True, print_line=False, print_item=False,
			)
			runner.run()
		self.assertEqual(runner.status, 'SUCCESS')
		self.assertIn('present', runner.output)

	def test_empty_env_run_opt_is_honored(self):
		"""An explicit empty `env={}` must be honored (deliberate empty environment),
		NOT silently fall back to the full process env — otherwise a caller asking for a
		locked-down env would leak every process var. Guards the `.get('env', os.environ)`
		(vs truthiness `or os.environ`) semantics.
		"""
		with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'sk-leakme'}):
			runner = command(
				['echo "[$ANTHROPIC_API_KEY]"'],
				sync=True, print_line=False, print_item=False, env={},
			)
			runner.run()
		self.assertEqual(runner.status, 'SUCCESS')
		# With an empty env the var is unset, so the shell expands it to nothing.
		self.assertNotIn('sk-leakme', runner.output)
		self.assertIn('[]', runner.output)


class TestCommandFromResult(unittest.TestCase):
	"""`command.from_result` imports an already-run command's result into a runner doc,
	without executing anything (the forward-looking seam for importing externally-run
	commands into Secator Cloud).
	"""

	@mock.patch("subprocess.Popen")
	def test_from_result_populates_runner_without_executing(self, mock_popen):
		"""A successful imported result populates output/status and never spawns a subprocess."""
		runner = command.from_result("nmap -p80 x", "PORT 80 open", 0)

		self.assertEqual(runner.output, "PORT 80 open")
		self.assertEqual(runner.status, "SUCCESS")
		mock_popen.assert_not_called()

		data = runner.toDict()
		self.assertEqual(data["cmd"], "nmap -p80 x")
		self.assertEqual(data["output"], "PORT 80 open")
		self.assertEqual(data["status"], "SUCCESS")
		self.assertEqual(data["return_code"], 0)

	@mock.patch("subprocess.Popen")
	def test_from_result_bare_command_success(self, mock_popen):
		"""A bare single-word command imports as SUCCESS with its cmd + output intact.

		Regression for the input-type-stripping bug: before the fix, "whoami" was
		autodetected as 'slug' and dropped, so cmd came back '' and status FAILURE (the
		spurious empty-input Error). The passed-in output is a fixed literal so the
		assertion is deterministic (not machine-dependent).
		"""
		runner = command.from_result("whoami", "someoutput", 0)

		self.assertEqual(runner.status, "SUCCESS")
		self.assertEqual(runner.cmd, "whoami")
		self.assertEqual(runner.output, "someoutput")
		mock_popen.assert_not_called()

	@mock.patch("subprocess.Popen")
	def test_from_result_failure_preserves_output_verbatim(self, mock_popen):
		"""A non-zero return code yields FAILURE, and the caller's output is preserved verbatim.

		Regression for the output-corruption bug: the synthetic Error added on the FAILURE
		path must NOT be appended onto self.output (add_result must be called output=False).
		"""
		runner = command.from_result("somecmd", "the real stdout", 1)

		self.assertEqual(runner.status, "FAILURE")
		self.assertEqual(runner.toDict()["status"], "FAILURE")
		# Exact match — no ANSI Error repr appended.
		self.assertEqual(runner.output, "the real stdout")
		self.assertEqual(runner.toDict()["output"], "the real stdout")
		mock_popen.assert_not_called()

"""A failing driver (persistence) hook must never hide a run's own results."""
import unittest
from unittest.mock import MagicMock, patch

import requests

from secator.hooks import api
from secator.output_types import Error


def _gateway_error(*args, **kwargs):
	"""The remote endpoint is unavailable and answers with a non-JSON error page."""
	r = MagicMock()
	r.status_code = 502
	r.ok = False
	r.text = '<html><head><title>502 Bad Gateway</title></head></html>'
	r.json.side_effect = requests.exceptions.JSONDecodeError('Expecting value', r.text, 0)
	return r


def _api_down():
	"""Patch the api driver so every request hits an unavailable endpoint."""
	return [
		patch.object(api, 'API_URL', 'https://api.example.com/api'),
		patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws')),
		patch.object(api.requests, 'request', side_effect=_gateway_error),
		patch.object(api.time, 'sleep'),
	]


class _Patched(unittest.TestCase):

	def setUp(self):
		for p in _api_down():
			p.start()
			self.addCleanup(p.stop)

	@staticmethod
	def _context():
		return {'workspace_id': 'a' * 24, 'workspace_name': 'ws', 'drivers': ['api']}


class TestDriverHookFailureOnCommand(_Patched):

	def _run_echo(self, text):
		from secator.runners import Task
		from secator.tasks.command import command as CommandTask
		runner = CommandTask([f'echo {text}'], hooks=api.HOOKS.get(Task, {}), context=self._context(), print_cmd=False)
		runner.run()
		return runner

	def test_command_output_survives_and_failure_is_one_warning(self):
		runner = self._run_echo('hello-from-command')
		self.assertIn('hello-from-command', runner.output)
		# No traceback flooding the command output.
		self.assertNotIn('Traceback', runner.output)
		# on_init / on_start / on_end all fail with the same error: reported once, as a warning.
		self.assertEqual(runner.output.count('Driver hook "secator.hooks.api.update_runner" failed'), 1)
		self.assertIn('WRN', runner.output)
		self.assertIn('HTTP 502', runner.output)

	def test_status_reflects_the_command_not_the_persistence_failure(self):
		runner = self._run_echo('ok')
		self.assertEqual(runner.status, 'SUCCESS')
		self.assertFalse([e for e in runner._own_errors if isinstance(e, Error)])

	def test_raise_on_error_still_raises(self):
		from secator.runners import Task
		from secator.tasks.command import command as CommandTask
		with self.assertRaises(api.ApiRequestError):
			CommandTask(['echo x'], hooks=api.HOOKS.get(Task, {}), context=self._context(), raise_on_error=True)


class TestDriverHookFailureOnAiShell(_Patched):

	def test_ai_receives_shell_output_when_api_hook_fails(self):
		from secator.ai.actions import ActionContext
		from secator.ai.tools.run_shell import RunShell
		from secator.output_types import Ai
		ctx = ActionContext(targets=[], model='m', context=self._context(), sync=True)
		items = list(RunShell().run({'command': 'echo hello-from-shell', 'description': 'echo'}, ctx))
		outputs = [i for i in items if isinstance(i, Ai) and i.ai_type == 'shell_output']
		self.assertEqual(len(outputs), 1)
		self.assertIn('hello-from-shell', outputs[0].content)
		# The persistence failure is reported next to the output, once, without a traceback.
		self.assertIn('Driver hook "secator.hooks.api.update_runner" failed', outputs[0].content)
		self.assertNotIn('Traceback', outputs[0].content)
		self.assertFalse([i for i in items if isinstance(i, Error)])


class TestHookFailureMessages(unittest.TestCase):

	def test_markup_in_exception_text_does_not_break_the_report(self):
		from secator.runners import Task
		from secator.tasks.command import command as CommandTask
		runner = CommandTask(['echo x'], context={'drivers': []}, print_cmd=False)
		runner._report_driver_hook_failure('secator.hooks.api.update_runner', 'on_end', Exception('bad [/] tag [bold]'))
		self.assertIn('bad [/] tag [bold]', runner.output)
		self.assertIsNotNone(Task)

	def test_other_hook_failure_fails_the_run_without_a_traceback_in_output(self):
		from secator.tasks.command import command as CommandTask

		def broken(self):
			raise RuntimeError('store write failed')
		hooks = {'on_end': [broken]}
		runner = CommandTask(['echo hello-from-command'], hooks=hooks, context={'drivers': []}, print_cmd=False)
		runner.run()
		self.assertIn('hello-from-command', runner.output)
		self.assertIn('store write failed', runner.output)
		self.assertNotIn('Traceback', runner.output)
		self.assertEqual(runner.status, 'FAILURE')

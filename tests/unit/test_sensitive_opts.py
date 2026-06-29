import unittest
import unittest.mock

from secator.runners import Command
from secator.runners._base import REDACTED_OPT_VALUE
from secator.runners.task import Task
from secator.template import TemplateLoader


class SensitiveCmd(Command):
	"""Ad-hoc command exposing one sensitive opt (token) and one plain opt (level)."""
	cmd = 'sensitivecmd'
	opts = {
		'token': {'type': str, 'sensitive': True, 'help': 'auth token'},
		'level': {'type': int, 'help': 'verbosity'},
	}


class PlainCmd(Command):
	"""Control command with no sensitive opts — must be completely unaffected."""
	cmd = 'plaincmd'
	opts = {
		'level': {'type': int, 'help': 'verbosity'},
	}


class TestSensitiveCommandOpts(unittest.TestCase):
	def setUp(self):
		self.maxDiff = None

	def _build(self, cls, **opts):
		return cls('example.com', sync=True, print_cmd=False, run=False, **opts)

	def test_executed_cmd_keeps_secret(self):
		"""The real command (run by the subprocess) must contain the true value."""
		t = self._build(SensitiveCmd, token='SECRET123', level=5)
		self.assertIn('SECRET123', t.cmd)
		self.assertIn('-token SECRET123', t.cmd)

	def test_redacted_cmd_masks_secret(self):
		"""cmd_redacted (used for toDict/printing) masks only the sensitive value."""
		t = self._build(SensitiveCmd, token='SECRET123', level=5)
		self.assertTrue(t._has_sensitive_cmd_opts)
		self.assertNotIn('SECRET123', t.cmd_redacted)
		self.assertIn(f'-token {REDACTED_OPT_VALUE}', t.cmd_redacted)
		self.assertIn('-level 5', t.cmd_redacted)  # non-sensitive opt untouched

	def test_todict_cmd_and_run_opts_redacted(self):
		"""Persisted/serialized state (toDict) leaks neither via cmd nor run_opts."""
		t = self._build(SensitiveCmd, token='SECRET123', level=5)
		d = t.toDict()
		self.assertNotIn('SECRET123', d['cmd'])
		self.assertEqual(d['run_opts'].get('token'), REDACTED_OPT_VALUE)
		self.assertEqual(d['run_opts'].get('level'), 5)

	def test_sensitive_opt_names(self):
		t = self._build(SensitiveCmd, token='SECRET123', level=5)
		self.assertEqual(t.sensitive_opt_names, {'token'})

	def test_plain_cmd_unaffected(self):
		"""A command with no sensitive opts: cmd_redacted == cmd, flag off, nothing masked."""
		t = self._build(PlainCmd, level=5)
		self.assertFalse(t._has_sensitive_cmd_opts)
		self.assertEqual(t.cmd, t.cmd_redacted)
		self.assertEqual(t.sensitive_opt_names, set())
		self.assertEqual(t.toDict()['run_opts'].get('level'), 5)

	def test_empty_sensitive_value_not_masked(self):
		"""An unset/empty sensitive opt is left as-is in run_opts (no secret -> no false mask)."""
		t = self._build(SensitiveCmd, token='', level=5)
		self.assertEqual(t.toDict()['run_opts'].get('token'), '')

	def test_print_command_masks_secret(self):
		"""print_command() (the user-visible logging path) must not emit the real secret."""
		t = SensitiveCmd('example.com', token='SECRET123', level=5, sync=True, print_cmd=True, run=False)
		with unittest.mock.patch.object(t, '_print') as mock_print:
			t.print_command()
		printed = ' '.join(str(c.args[0]) for c in mock_print.call_args_list)
		self.assertNotIn('SECRET123', printed)
		self.assertIn('REDACTED', printed)  # substring: rich-escaping may render it as \[REDACTED\]

	def test_dry_run_info_masks_secret(self):
		"""The dry-run emission path (yields Info(message=cmd)) must use the redacted command."""
		t = SensitiveCmd('example.com', token='SECRET123', level=5, sync=True, dry_run=True, print_cmd=False)
		messages = ' '.join(str(getattr(item, 'message', '')) for item in t)
		self.assertNotIn('SECRET123', messages)
		self.assertIn(REDACTED_OPT_VALUE, messages)

	def test_redact_cmd_options_masks_nested_default(self):
		"""Debug echo of cmd_options must mask both the value and a secret-bearing `default`."""
		cmd_options = {
			'token': {'name': '-token', 'value': 'SECRET123',
					  'conf': {'sensitive': True, 'default': 'PLATFORM_DEFAULT'}},
			'level': {'name': '-level', 'value': 5, 'conf': {}},
		}
		out = Command._redact_cmd_options(cmd_options)
		self.assertEqual(out['token']['value'], REDACTED_OPT_VALUE)
		self.assertEqual(out['token']['conf']['default'], REDACTED_OPT_VALUE)
		self.assertEqual(out['level'], cmd_options['level'])  # untouched


class TestSensitiveRunnerOpts(unittest.TestCase):
	"""The redaction must also apply at the composite-runner level (Task/Workflow/Scan),
	which carries no opts of its own and resolves sensitivity from its config tree."""

	def test_task_runner_redacts_ai_api_key(self):
		cfg = TemplateLoader(input={'name': 'ai', 'type': 'task'})
		r = Task(cfg, inputs=['hi'], run_opts={'api_key': 'SECRET123', 'model': 'x'})
		self.assertEqual(r.sensitive_opt_names, {'api_key'})
		d = r.toDict()
		self.assertEqual(d['run_opts'].get('api_key'), REDACTED_OPT_VALUE)
		self.assertEqual(d['run_opts'].get('model'), 'x')

	def test_serialized_config_does_not_leak_sensitive_default(self):
		"""An option's `default` can be a platform secret (ai.api_key defaults to the
		configured key). It must not survive into toDict()['config'] / ['opts']."""
		import json
		from secator.tasks.ai import ai
		with unittest.mock.patch.dict(ai.opts['api_key'], {'default': 'PLATFORM_SECRET_XYZ'}):
			cfg = TemplateLoader(input={'name': 'ai', 'type': 'task'})
			r = Task(cfg, inputs=['hi'], run_opts={'api_key': 'USER_SECRET_ABC'})
			d = r.toDict()
		blob = json.dumps(d, default=str)
		self.assertNotIn('PLATFORM_SECRET_XYZ', blob)
		self.assertNotIn('USER_SECRET_ABC', blob)


if __name__ == '__main__':
	unittest.main()

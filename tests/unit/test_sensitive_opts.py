import logging
import unittest

from secator.runners import Command
from secator.runners._base import REDACTED_OPT_VALUE
from secator.runners.task import Task
from secator.template import TemplateLoader
from secator.utils import setup_logging

level = logging.ERROR
setup_logging(level)


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


if __name__ == '__main__':
	unittest.main()

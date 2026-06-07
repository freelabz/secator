"""Unit tests for the `secator query` command and its dispatch helpers."""

import unittest
from unittest import mock
from click.testing import CliRunner


class TestLooksLikeQueryExpr(unittest.TestCase):

	def _check(self, value):
		from secator.cli import _looks_like_query_expr
		return _looks_like_query_expr(value)

	def test_expressions_are_detected(self):
		exprs = [
			"vulnerability.severity == 'high'",
			"vulnerability.severity_nb < 2",
			"port.port > 1000",
			"vulnerability.name ~= 'SQL'",
			"a == 1 && b == 2",
			"a == 1 || b == 2",
			"vulnerability.severity == 'high' and vulnerability.confidence == 'high'",
			"severity in ['high', 'critical']",
			"extra_data.published",
		]
		for expr in exprs:
			with self.subTest(expr=expr):
				self.assertTrue(self._check(expr))

	def test_natural_language_is_not_detected(self):
		phrases = [
			"Analyze my workspace data",
			"critical_vulns",
			"show me the most exploitable hosts",
			"",
		]
		for phrase in phrases:
			with self.subTest(phrase=phrase):
				self.assertFalse(self._check(phrase))


class TestRunAiChat(unittest.TestCase):

	def test_run_ai_chat_invokes_ai_task_command(self):
		from secator.cli import cli

		runner = CliRunner()
		# Patch the registered `ai` task command's callback so no LLM runs.
		ai_cmd = cli.commands['task'].commands['ai']
		with mock.patch.object(ai_cmd, 'callback') as mock_cb:
			result = runner.invoke(cli, ['query', '-ws', 'myws', 'Analyze my workspace data'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		self.assertTrue(mock_cb.called)
		_, kwargs = mock_cb.call_args
		self.assertEqual(kwargs.get('prompt'), 'Analyze my workspace data')
		self.assertEqual(kwargs.get('mode'), 'chat')
		self.assertEqual(kwargs.get('workspace'), 'myws')

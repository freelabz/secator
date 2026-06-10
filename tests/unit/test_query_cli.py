"""Unit tests for the `secator query` command and its dispatch helpers."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

WS = 'query_ws'
CRIT = {
	'_type': 'vulnerability', 'name': 'SQLi', 'severity': 'critical',
	'matched_at': 'http://x/login', 'is_false_positive': False,
	'_context': {'workspace_id': WS, 'workspace_duplicate': False},
}
MED = {
	'_type': 'vulnerability', 'name': 'XSS', 'severity': 'medium',
	'matched_at': 'http://x/search', 'is_false_positive': False,
	'_context': {'workspace_id': WS, 'workspace_duplicate': False},
}


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
			# bare output type names
			"url",
			"vulnerability",
			"domain",
			"port",
		]
		for expr in exprs:
			with self.subTest(expr=expr):
				self.assertTrue(self._check(expr))

	def test_natural_language_is_not_detected(self):
		phrases = [
			"Analyze my workspace data",
			"critical_vulns",
			"show me the most exploitable hosts",
			# Plain English containing 'in'/'and'/'or' must not be read as a query expression.
			"What's in my workspace ?",
			"subdomains and ips",
			"show me urls or vulnerabilities",
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
		mock_cb.assert_called_once()
		_, kwargs = mock_cb.call_args
		self.assertEqual(kwargs.get('prompt'), 'Analyze my workspace data')
		self.assertEqual(kwargs.get('mode'), 'chat')
		self.assertEqual(kwargs.get('workspace'), 'myws')


class TestQueryDispatch(unittest.TestCase):

	def setUp(self):
		self.cli_runner = CliRunner()
		self.temp_dir = tempfile.mkdtemp()
		task_dir = Path(self.temp_dir) / WS / 'tasks' / '1'
		task_dir.mkdir(parents=True)
		with open(task_dir / 'report.json', 'w') as f:
			json.dump({'info': {'name': 't'}, 'results': {'vulnerability': [CRIT.copy(), MED.copy()]}}, f)

	def tearDown(self):
		shutil.rmtree(self.temp_dir)

	def _invoke(self, args):
		from secator.cli import cli
		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		with mock.patch('secator.query.json.CONFIG') as mock_cfg, \
			mock.patch('secator.report.Report.send', capture_send):
			mock_cfg.dirs.reports = Path(self.temp_dir)
			result = self.cli_runner.invoke(cli, args)
		return result, captured

	def test_named_query(self):
		from secator.config import CONFIG
		with mock.patch.dict(CONFIG.queries, {'crit': "vulnerability.severity == 'critical'"}, clear=False):
			result, captured = self._invoke(['query', 'crit', '-ws', WS, '--driver', 'local'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		vulns = captured.get('results', {}).get('vulnerability', [])
		self.assertEqual(sorted(v['name'] for v in vulns), ['SQLi'])

	def test_raw_expression(self):
		result, captured = self._invoke(
			['query', "vulnerability.severity == 'medium'", '-ws', WS, '--driver', 'local'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		vulns = captured.get('results', {}).get('vulnerability', [])
		self.assertEqual(sorted(v['name'] for v in vulns), ['XSS'])

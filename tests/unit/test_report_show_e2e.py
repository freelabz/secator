# tests/unit/test_report_show_e2e.py

"""End-to-end CLI tests for `secator r show -q <QUERY>` with all query backends."""

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from click.testing import CliRunner


def _strip_ansi(text):
	return re.sub(r'\x1b(?:\[[0-9;]*m|\][^\x1b]*\x1b\\)', '', text)


WORKSPACE = 'e2e_ws'

CRITICAL_VULN = {
	'_type': 'vulnerability',
	'name': 'SQL Injection',
	'severity': 'critical',
	'matched_at': 'http://example.com/login',
	'is_false_positive': False,
	'_context': {'workspace_id': WORKSPACE, 'workspace_duplicate': False},
}
MEDIUM_VULN = {
	'_type': 'vulnerability',
	'name': 'XSS',
	'severity': 'medium',
	'matched_at': 'http://example.com/search',
	'is_false_positive': False,
	'_context': {'workspace_id': WORKSPACE, 'workspace_duplicate': False},
}
TARGET = {
	'_type': 'target',
	'name': 'example.com',
	'type': 'domain',
	'_context': {'workspace_id': WORKSPACE, 'workspace_duplicate': False},
}
AI = {
	'_type': 'ai',
	'content': 'thinking about the target',
	'ai_type': 'prompt',
	'_context': {'workspace_id': WORKSPACE, 'workspace_duplicate': False},
}

# Shared query matrix across all backends.
# Columns: (query_expr, server_docs, expected_count, expected_names)
#   query_expr   - string passed to -q, or None for no query
#   server_docs  - docs the external backend (MongoDB/API) returns; local backend always filters itself
#   expected_count  - number of vulnerability results expected
#   expected_names  - sorted names of those results
QUERY_CASES = [
	(None,                                                                          [CRITICAL_VULN, MEDIUM_VULN], 2, ['SQL Injection', 'XSS']),
	("vulnerability.severity == 'critical'",                                        [CRITICAL_VULN],              1, ['SQL Injection']),
	("vulnerability.severity == 'medium'",                                          [MEDIUM_VULN],                1, ['XSS']),
	("vulnerability.severity == 'low'",                                             [],                           0, []),
	("vulnerability.name ~= 'SQL'",                                                 [CRITICAL_VULN],              1, ['SQL Injection']),
	("vulnerability.severity == 'critical' && vulnerability.name ~= 'SQL'",         [CRITICAL_VULN],              1, ['SQL Injection']),
	("vulnerability.severity == 'critical' || vulnerability.severity == 'medium'",  [CRITICAL_VULN, MEDIUM_VULN], 2, ['SQL Injection', 'XSS']),
]


class TestReportShowLocalBackend(unittest.TestCase):
	"""End-to-end CLI tests for `secator r show -q` with the local (JSON) backend."""

	def setUp(self):
		self.cli_runner = CliRunner()
		self.temp_dir = tempfile.mkdtemp()

		# Create workspace report structure: <temp>/<workspace>/tasks/1/report.json
		task_dir = Path(self.temp_dir) / WORKSPACE / 'tasks' / '1'
		task_dir.mkdir(parents=True)
		with open(task_dir / 'report.json', 'w') as f:
			json.dump({
				'info': {'name': 'test'},
				'results': {'vulnerability': [CRITICAL_VULN.copy(), MEDIUM_VULN.copy()]},
			}, f)

	def tearDown(self):
		shutil.rmtree(self.temp_dir)

	def _invoke(self, query_expr, extra_args=None):
		from secator.cli import cli

		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		args = ['r', 'show', '-w', WORKSPACE, '--driver', 'local']
		if query_expr:
			args += ['-q', query_expr]
		if extra_args:
			args += extra_args

		with mock.patch('secator.query.json.CONFIG') as mock_cfg, \
				mock.patch('secator.report.Report.send', capture_send):
			mock_cfg.dirs.reports = Path(self.temp_dir)
			result = self.cli_runner.invoke(cli, args)

		return result, captured

	def test_query_matrix(self):
		for query_expr, _server_docs, expected_count, expected_names in QUERY_CASES:
			with self.subTest(query=query_expr):
				result, captured = self._invoke(query_expr)
				self.assertIsNone(result.exception, str(result.exception))
				self.assertEqual(result.exit_code, 0)
				vulns = captured.get('results', {}).get('vulnerability', [])
				self.assertEqual(len(vulns), expected_count)
				self.assertEqual(sorted(v['name'] for v in vulns), sorted(expected_names))

	def _invoke_with_paths(self, report_query):
		"""Invoke `r show <report_query>` (positional path filter) and return the result."""
		from secator.cli import cli

		args = ['r', 'show', '-w', WORKSPACE, '--driver', 'local']
		if report_query:
			args.append(report_query)

		with mock.patch('secator.query.json.CONFIG') as mock_cfg, \
				mock.patch('secator.report.Report.send', lambda report_self: None):
			mock_cfg.dirs.reports = Path(self.temp_dir)
			result = self.cli_runner.invoke(cli, args)
		return result

	def test_info_line_shows_searched_paths(self):
		"""The summary line echoes the searched runner paths when a report_query is passed."""
		result = self._invoke_with_paths('tasks/1')
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		self.assertIn('searched: tasks/1', _strip_ansi(result.output))

	def test_info_line_no_searched_without_query(self):
		"""Without a report_query, the summary line omits the 'searched' suffix."""
		result = self._invoke_with_paths(None)
		self.assertEqual(result.exit_code, 0)
		self.assertIn('results in workspace', result.output)
		self.assertNotIn('searched:', result.output)

	def _write_report_with_verbose_types(self):
		task_dir = Path(self.temp_dir) / WORKSPACE / 'tasks' / '1'
		with open(task_dir / 'report.json', 'w') as f:
			json.dump({
				'info': {'name': 'test'},
				'results': {
					'vulnerability': [CRITICAL_VULN.copy()],
					'target': [TARGET.copy()],
					'ai': [AI.copy()],
				},
			}, f)

	def test_verbose_types_excluded_without_query(self):
		"""`r show` with no query hides verbose target and ai results."""
		self._write_report_with_verbose_types()
		result, captured = self._invoke(None)
		self.assertEqual(result.exit_code, 0)
		self.assertEqual(len(captured.get('results', {}).get('vulnerability', [])), 1)
		self.assertEqual(captured.get('results', {}).get('target', []), [])
		self.assertEqual(captured.get('results', {}).get('ai', []), [])

	def test_targets_shown_with_explicit_query(self):
		"""`r show -q target` displays target results (and still hides ai)."""
		self._write_report_with_verbose_types()
		result, captured = self._invoke('target')
		self.assertEqual(result.exit_code, 0)
		targets = captured.get('results', {}).get('target', [])
		self.assertEqual(len(targets), 1)
		self.assertEqual(targets[0]['name'], 'example.com')
		self.assertEqual(captured.get('results', {}).get('vulnerability', []), [])
		self.assertEqual(captured.get('results', {}).get('ai', []), [])

	def test_ai_shown_with_explicit_query(self):
		"""`r show -q ai` displays ai results (and still hides targets)."""
		self._write_report_with_verbose_types()
		result, captured = self._invoke('ai')
		self.assertEqual(result.exit_code, 0)
		ai_items = captured.get('results', {}).get('ai', [])
		self.assertEqual(len(ai_items), 1)
		self.assertEqual(captured.get('results', {}).get('vulnerability', []), [])
		self.assertEqual(captured.get('results', {}).get('target', []), [])

	def test_limit_option(self):
		"""--limit / -l restricts the number of results returned."""
		result, captured = self._invoke(None, extra_args=['--limit', '1'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		vulns = captured.get('results', {}).get('vulnerability', [])
		self.assertEqual(len(vulns), 1)

	def test_limit_short_form(self):
		"""Short form -l also restricts the number of results returned."""
		result, captured = self._invoke(None, extra_args=['-l', '1'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		vulns = captured.get('results', {}).get('vulnerability', [])
		self.assertEqual(len(vulns), 1)


class TestReportShowMongoDBBackend(unittest.TestCase):
	"""End-to-end CLI tests for `secator r show -q` with the MongoDB backend."""

	def _make_mongo_mock(self, docs):
		doc_list = [d.copy() for d in docs]
		mock_cursor = mock.MagicMock()
		mock_cursor.__iter__ = mock.MagicMock(return_value=iter(doc_list))
		mock_cursor.limit.return_value = mock_cursor
		mock_collection = mock.MagicMock()
		mock_collection.find.return_value = mock_cursor
		mock_db = mock.MagicMock()
		mock_db.findings = mock_collection
		mock_client = mock.MagicMock()
		mock_client.main = mock_db
		return mock_client, mock_collection

	def _invoke(self, query_expr, server_docs):
		from secator.cli import cli
		from secator.query.mongodb import MongoDBBackend

		mock_client, mock_collection = self._make_mongo_mock(server_docs)
		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		args = ['r', 'show', '--driver', 'mongodb', '-w', WORKSPACE]
		if query_expr:
			args += ['-q', query_expr]

		with mock.patch.object(MongoDBBackend, '_get_client', return_value=mock_client), \
				mock.patch('secator.report.Report.send', capture_send):
			result = CliRunner().invoke(cli, args)

		return result, captured, mock_collection

	def test_query_matrix(self):
		for query_expr, server_docs, expected_count, expected_names in QUERY_CASES:
			with self.subTest(query=query_expr):
				result, captured, _ = self._invoke(query_expr, server_docs)
				self.assertIsNone(result.exception, str(result.exception))
				self.assertEqual(result.exit_code, 0)
				vulns = captured.get('results', {}).get('vulnerability', [])
				self.assertEqual(len(vulns), expected_count)
				self.assertEqual(sorted(v['name'] for v in vulns), sorted(expected_names))

	def test_query_sends_correct_mongo_query(self):
		"""Verify the MongoDB backend receives the correctly translated and merged query."""
		_, _, mock_coll = self._invoke("vulnerability.severity == 'critical'", [CRITICAL_VULN])
		call_args = mock_coll.find.call_args
		self.assertIsNotNone(call_args)
		query_sent = call_args[0][0]
		self.assertEqual(query_sent.get('_type'), 'vulnerability')
		self.assertEqual(query_sent.get('severity'), 'critical')
		self.assertEqual(query_sent.get('_context.workspace_id'), WORKSPACE)
		self.assertEqual(query_sent.get('is_false_positive'), False)

	def test_mongodb_unavailable_exits_cleanly(self):
		"""If MongoDB is unavailable the command exits cleanly with empty results."""
		from secator.cli import cli
		from secator.query.mongodb import MongoDBBackend

		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		with mock.patch.object(MongoDBBackend, '_get_client', side_effect=Exception('connection refused')), \
				mock.patch('secator.report.Report.send', capture_send):
			result = CliRunner().invoke(cli, ['r', 'show', '--driver', 'mongodb', '-w', WORKSPACE])

		self.assertEqual(result.exit_code, 0)
		self.assertEqual(captured.get('results', {}).get('vulnerability', []), [])


class TestReportShowApiBackend(unittest.TestCase):
	"""End-to-end CLI tests for `secator r show -q` with the API backend."""

	def _invoke(self, query_expr, api_response):
		from secator.cli import cli
		from secator.hooks.api import resolve_workspace

		# Workspace name->id resolution is cached; reset so it re-resolves under the mock.
		resolve_workspace.cache_clear()

		captured = {}
		captured_request = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		def mock_request(method, url, data=None, **kwargs):
			import json as _json
			# The api driver resolves the workspace name to its id first (GET /workspaces).
			if method == 'GET' and 'workspace' in url:
				resp = mock.MagicMock()
				resp.json.return_value = [{'name': WORKSPACE, '_id': WORKSPACE}]
				resp.raise_for_status = mock.MagicMock()
				return resp
			captured_request['method'] = method
			captured_request['url'] = url
			captured_request['body'] = _json.loads(data) if data else {}
			response = mock.MagicMock()
			response.json.return_value = api_response
			response.raise_for_status = mock.MagicMock()
			return response

		args = ['r', 'show', '--driver', 'api', '-w', WORKSPACE]
		if query_expr:
			args += ['-q', query_expr]

		with mock.patch('requests.request', side_effect=mock_request), \
				mock.patch('secator.report.Report.send', capture_send):
			result = CliRunner().invoke(cli, args)

		return result, captured, captured_request

	def test_query_matrix(self):
		for query_expr, server_docs, expected_count, expected_names in QUERY_CASES:
			with self.subTest(query=query_expr):
				result, captured, _ = self._invoke(query_expr, server_docs)
				self.assertIsNone(result.exception, str(result.exception))
				self.assertEqual(result.exit_code, 0)
				vulns = captured.get('results', {}).get('vulnerability', [])
				self.assertEqual(len(vulns), expected_count)
				self.assertEqual(sorted(v['name'] for v in vulns), sorted(expected_names))

	def test_query_sends_correct_api_body(self):
		"""Verify the API backend POSTs the correctly translated and merged query."""
		_, _, req = self._invoke("vulnerability.severity == 'critical'", [CRITICAL_VULN])
		self.assertEqual(req.get('method'), 'POST')
		body = req.get('body', {})
		self.assertEqual(body.get('_type'), 'vulnerability')
		self.assertEqual(body.get('severity'), 'critical')
		self.assertEqual(body.get('_context.workspace_id'), WORKSPACE)
		self.assertEqual(body.get('is_false_positive'), False)
		self.assertEqual(body.get('_tagged'), True)

	def test_api_handles_items_format(self):
		"""API backend handles {'items': [...]} paginated response format."""
		_, captured, _ = self._invoke(None, {'items': [CRITICAL_VULN]})
		vulns = captured.get('results', {}).get('vulnerability', [])
		self.assertEqual(len(vulns), 1)

	def test_api_unavailable_exits_cleanly(self):
		"""If the API is unreachable the command exits cleanly with empty results."""
		from secator.cli import cli

		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		with mock.patch('requests.request', side_effect=Exception('connection refused')), \
				mock.patch('secator.report.Report.send', capture_send):
			result = CliRunner().invoke(cli, ['r', 'show', '--driver', 'api', '-w', WORKSPACE])

		self.assertEqual(result.exit_code, 0)
		self.assertEqual(captured.get('results', {}).get('vulnerability', []), [])


class TestReportListCurrentWorkspace(unittest.TestCase):
	"""`secator r list` shows the current workspace, honoring the -ws option."""

	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()
		# A real report file so paths is non-empty and .stat() works
		task_dir = Path(self.temp_dir) / 'tasks' / '1'
		task_dir.mkdir(parents=True)
		self.report_path = task_dir / 'report.json'
		self.report_path.write_text('{}')

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _run_list(self, workspace_opt, default_ws):
		import click
		from secator.cli import report_list, console

		info = {'type': 'tasks', 'id': '1', 'workspace': workspace_opt or default_ws}
		report_info = {'name': 't', 'targets': [], 'run_opts': {}, 'status': 'completed',
					   'start_time': None, 'end_time': None, 'elapsed_human': ''}
		vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

		ctx = click.Context(report_list)
		ctx.obj = {'piped_output': False}
		# `report_list.callback` is the @click.pass_context wrapper: it pulls the context from
		# click's stack (not from an explicit arg), so we push it via `with ctx:`.
		with ctx, \
				mock.patch('secator.cli.list_reports', return_value=[self.report_path]), \
				mock.patch('secator.cli.get_info_from_report_path', return_value=info), \
				mock.patch('secator.cli._load_report_data', return_value=(report_info, vuln_counts)), \
				mock.patch('secator.cli.CONFIG') as cfg, \
				console.capture() as cap:
			cfg.workspace.default = default_ws
			report_list.callback(
				workspace=workspace_opt, runner_type=None, time_delta=None, driver='local', show_all=False,
				interesting=False, status=None, show_children=False,
			)
		# Strip ANSI codes then flatten whitespace so assertions work on plain text
		return ' '.join(_strip_ansi(cap.get()).split())

	def test_uses_ws_option_when_passed(self):
		out = self._run_list(workspace_opt='vulnweb', default_ws='defws')
		self.assertIn('Current workspace', out)
		self.assertIn('vulnweb', out)
		self.assertNotIn('defws', out)
		# Switch hint always shown as a reminder, even when -ws was provided
		self.assertIn('-ws <workspace_name>', out)
		self.assertIn('to switch', out)

	def test_all_workspaces_message_without_ws(self):
		out = self._run_list(workspace_opt=None, default_ws='defws')
		# Without -ws, all workspaces are listed, so don't claim a single current workspace
		self.assertNotIn('Current workspace', out)
		self.assertIn('All workspaces selected', out)
		self.assertIn('-ws <workspace_name>', out)
		self.assertIn('to filter on a workspace', out)


class TestReportListInteresting(unittest.TestCase):
	"""`secator r list --interesting/-i` only lists reports that have vulnerabilities."""

	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()
		# Report WITH a real-severity vulnerability (shows in the Vulnerabilities column), status SUCCESS
		self.with_vuln = Path(self.temp_dir) / 'tasks' / '1' / 'report.json'
		self.with_vuln.parent.mkdir(parents=True)
		self.with_vuln.write_text(json.dumps({
			'info': {'status': 'SUCCESS'},
			'results': {'vulnerability': [{'_type': 'vulnerability', 'name': 'x', 'severity': 'high'}]},
		}))
		# Report WITHOUT any vulnerability, status FAILURE
		self.no_vuln = Path(self.temp_dir) / 'tasks' / '2' / 'report.json'
		self.no_vuln.parent.mkdir(parents=True)
		self.no_vuln.write_text(json.dumps({'info': {'status': 'FAILURE'}, 'results': {'url': [{'_type': 'url'}]}}))
		# Report with ONLY unknown/empty-severity vulns (renders as '-', must be filtered out by -i), status SUCCESS
		self.unknown_sev = Path(self.temp_dir) / 'tasks' / '3' / 'report.json'
		self.unknown_sev.parent.mkdir(parents=True)
		self.unknown_sev.write_text(json.dumps({
			'info': {'status': 'SUCCESS'},
			'results': {'vulnerability': [
				{'_type': 'vulnerability', 'name': 'CVE-X', 'severity': 'unknown'},
				{'_type': 'vulnerability', 'name': 'CVE-Y', 'severity': ''},
			]},
		}))

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _invoke(self, args):
		from secator.cli import cli
		# Pin --driver local so the filesystem branch is used regardless of the ambient
		# drivers.defaults config. Assertions check the runner id (e.g. 'tasks/1'), which is
		# plain text in the table — unlike the full path, which only appears via a file://
		# hyperlink that rich renders only when the console is detected as a terminal.
		# COLUMNS keeps the table wide so the id isn't wrapped across lines.
		with mock.patch('secator.cli.list_reports', return_value=[self.with_vuln, self.no_vuln, self.unknown_sev]):
			return CliRunner().invoke(cli, ['r', 'list', '--driver', 'local'] + args, env={'COLUMNS': '400'})

	def test_interesting_filters_to_vuln_reports(self):
		result = self._invoke(['-i'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('tasks/1', result.output)
		self.assertNotIn('tasks/2', result.output)
		# Unknown/empty-severity vulns render as '-' and are not interesting
		self.assertNotIn('tasks/3', result.output)

	def test_long_flag_equivalent(self):
		result = self._invoke(['--interesting'])
		self.assertIn('tasks/1', result.output)
		self.assertNotIn('tasks/2', result.output)
		self.assertNotIn('tasks/3', result.output)

	def test_without_interesting_shows_all(self):
		result = self._invoke([])
		self.assertIn('tasks/1', result.output)
		self.assertIn('tasks/2', result.output)
		self.assertIn('tasks/3', result.output)

	def test_status_filter(self):
		result = self._invoke(['--status', 'FAILURE'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('tasks/2', result.output)
		self.assertNotIn('tasks/1', result.output)
		self.assertNotIn('tasks/3', result.output)

	def test_status_filter_case_insensitive(self):
		# lower-case, UPPER-case and Title-case must all behave identically
		for variant in ('success', 'SUCCESS', 'Success'):
			result = self._invoke(['--status', variant])
			self.assertIn('tasks/1', result.output, variant)
			self.assertIn('tasks/3', result.output, variant)
			self.assertNotIn('tasks/2', result.output, variant)
		# Title-case on a different status value
		result = self._invoke(['--status', 'Failure'])
		self.assertIn('tasks/2', result.output)
		self.assertNotIn('tasks/1', result.output)

	def test_status_and_interesting_combined(self):
		# Only the SUCCESS report that also has real-severity vulns survives both filters
		result = self._invoke(['-i', '--status', 'SUCCESS'])
		self.assertIn('tasks/1', result.output)
		self.assertNotIn('tasks/3', result.output)
		self.assertNotIn('tasks/2', result.output)

	def test_status_partial_regex_match(self):
		# 'FAIL' is a regex search, so it matches FAILURE
		result = self._invoke(['--status', 'FAIL'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('tasks/2', result.output)
		self.assertNotIn('tasks/1', result.output)

	def test_status_alternation_regex(self):
		# '(SUCCESS|FAILURE)' matches both statuses
		result = self._invoke(['--status', '(SUCCESS|FAILURE)'])
		self.assertIn('tasks/1', result.output)
		self.assertIn('tasks/2', result.output)
		self.assertIn('tasks/3', result.output)

	def test_status_no_match(self):
		# A valid regex matching no status yields no reports (no crash, no warning)
		result = self._invoke(['--status', 'BOGUS'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('No reports found', result.output)

	def test_status_invalid_regex_errors(self):
		# An invalid regex is reported as an error and lists nothing
		result = self._invoke(['--status', '(unclosed'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('Invalid --status regex', result.output)


if __name__ == '__main__':
	unittest.main()

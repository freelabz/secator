# tests/unit/test_report_show_e2e.py

"""End-to-end CLI tests for `secator r show -q <QUERY>` with all query backends."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

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

	def _invoke(self, query_expr):
		from secator.cli import cli

		captured = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		args = ['r', 'show', '-w', WORKSPACE, '--driver', 'local']
		if query_expr:
			args += ['-q', query_expr]

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

		captured = {}
		captured_request = {}

		def capture_send(report_self):
			captured['results'] = report_self.data['results']

		def mock_request(method, url, data=None, **kwargs):
			import json as _json
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

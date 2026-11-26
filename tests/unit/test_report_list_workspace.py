# tests/unit/test_report_list_workspace.py

"""`secator r list` lists the current workspace's reports by default, and every workspace's
reports with --all-workspaces, on every query backend (local, sqlite, mongodb, api)."""

import json
import re
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from secator.config import CONFIG

WS_ID = 'a' * 24
OTHER_WS_ID = 'b' * 24


def _strip_ansi(text):
	return re.sub(r'\x1b(?:\[[0-9;]*m|\][^\x1b]*\x1b\\)', '', text)


def _invoke(args, current='ws1'):
	from secator.cli import cli
	with mock.patch.object(CONFIG.workspaces, 'current', current):
		result = CliRunner().invoke(cli, ['r', 'list'] + args, env={'COLUMNS': '400'})
	return result, ' '.join(_strip_ansi(result.output).split())


class ReportListAssertions:
	"""Shared CLI assertions: 'alpha' runs in ws1 (the current workspace), 'beta' in ws2.

	Each backend stores 'alpha' first (and in the first workspace) but 'beta' started
	EARLIER, so the natural store order is newest first and only a chronological sort
	puts 'beta' before 'alpha'."""

	driver = None

	def test_defaults_to_current_workspace(self):
		result, out = _invoke(['--driver', self.driver])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('alpha', out)
		self.assertNotIn('beta', out)
		self.assertIn('Current workspace: ws1', out)
		# One workspace only: no Workspace column
		self.assertNotIn('Workspace ┃', out)

	def test_workspace_option_targets_another_workspace(self):
		result, out = _invoke(['--driver', self.driver, '-ws', 'ws2'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('beta', out)
		self.assertNotIn('alpha', out)
		self.assertIn('Current workspace: ws2', out)

	def test_all_workspaces_lists_every_workspace_with_column(self):
		result, out = _invoke(['--driver', self.driver, '--all-workspaces'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('alpha', out)
		self.assertIn('beta', out)
		self.assertIn('Workspace', out)
		self.assertIn('ws1', out)
		self.assertIn('ws2', out)
		self.assertIn('All workspaces selected', out)

	def test_most_recent_last(self):
		result, out = _invoke(['--driver', self.driver, '--all-workspaces'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertLess(out.index('beta'), out.index('alpha'))

	def _root_names(self, **kwargs):
		return [r['name'] for r in self._backend().list_runners(has_parent=False, **kwargs)]

	def test_backend_order_asc_is_default(self):
		self.assertEqual(self._root_names(), ['beta', 'alpha'])
		self.assertEqual(self._root_names(order='asc'), ['beta', 'alpha'])

	def test_backend_order_desc_most_recent_first(self):
		self.assertEqual(self._root_names(order='desc'), ['alpha', 'beta'])

	def test_backend_order_desc_through_query_engine(self):
		from secator.query import QueryEngine
		engine = QueryEngine('', context={})
		with mock.patch.object(engine, 'backend', self._backend()):
			names = [r['name'] for r in engine.list_runners(has_parent=False, order='desc')]
		self.assertEqual(names, ['alpha', 'beta'])


class TestReportListLocal(ReportListAssertions, unittest.TestCase):
	"""Local reports live at <reports>/<workspace>/<type>/<id>/report.json."""

	driver = 'local'

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		for ws, name, start in (('ws1', 'alpha', '2026-01-02T00:00:00'), ('ws2', 'beta', '2026-01-01T00:00:00')):
			d = self.tmp / ws / 'tasks' / '0'
			d.mkdir(parents=True)
			info = {'name': name, 'status': 'SUCCESS', 'start_time': start}
			(d / 'report.json').write_text(json.dumps({'info': info, 'results': {}}))
		patcher = mock.patch.object(CONFIG.dirs, 'reports', self.tmp)
		patcher.start()
		self.addCleanup(patcher.stop)

	def tearDown(self):
		shutil.rmtree(self.tmp, ignore_errors=True)

	def _backend(self):
		from secator.query.json import JsonBackend
		return JsonBackend('')

	def test_workspace_and_all_workspaces_conflict(self):
		result, out = _invoke(['--driver', 'local', '-ws', 'ws2', '--all-workspaces'])
		self.assertEqual(result.exit_code, 1)
		self.assertIn('not both', out)

	def test_no_current_workspace_uses_default(self):
		# Runners file reports under 'default' when no workspace is set; list the same one.
		d = self.tmp / 'default' / 'tasks' / '0'
		d.mkdir(parents=True)
		(d / 'report.json').write_text(json.dumps({'info': {'name': 'gamma'}, 'results': {}}))
		result, out = _invoke(['--driver', 'local'], current='')
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('gamma', out)
		self.assertNotIn('alpha', out)
		self.assertIn('Current workspace: default', out)


class TestReportListSqlite(ReportListAssertions, unittest.TestCase):
	"""Sqlite runner rows mirror context.workspace_id into a column; the blob carries the name."""

	driver = 'sqlite'

	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		self.sqlite_mod = sqlite_mod
		self.tmp = tempfile.mkdtemp()
		self._orig_path = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.tmp) / 'test.db')
		sqlite_mod._conns.clear()
		conn = sqlite_mod.get_sqlite_conn()
		rows = [
			# (table, id, workspace_id column, doc)
			('tasks', 't1', WS_ID, {'name': 'alpha', 'has_parent': False, 'start_time': '2026-01-02T00:00:00',
				'context': {'task_id': 't1', 'workspace_id': WS_ID, 'workspace_name': 'ws1'}}),
			('scans', 's1', 'ws2', {'name': 'beta', 'start_time': '2026-01-01T00:00:00',
				'context': {'scan_id': 's1', 'workspace_id': 'ws2', 'workspace_name': 'ws2'}}),
			('tasks', 't2', WS_ID, {'name': 'child', 'has_parent': True, 'start_time': '2026-01-03T00:00:00',
				'context': {'task_id': 't2', 'workspace_id': WS_ID, 'workspace_name': 'ws1'}}),
		]
		for table, rid, ws, doc in rows:
			conn.execute(f'INSERT INTO {table} (id, workspace_id, data) VALUES (?, ?, ?)', (rid, ws, json.dumps(doc)))
		findings = [
			('v1', WS_ID, 't1', 'critical', False),
			('v2', WS_ID, 't1', 'high', False),
			('v3', WS_ID, 't1', 'info', False),
			('v4', WS_ID, 't1', 'low', True),
			('v5', WS_ID, 't2', 'low', False),
			('v6', 'ws2', 's1', 'medium', False),
		]
		for uuid, ws, runner_id, severity, is_false_positive in findings:
			doc = {
				'_uuid': uuid, '_type': 'vulnerability', 'severity': severity,
				'is_false_positive': is_false_positive,
				'_context': {'workspace_id': ws, 'task_id' if runner_id.startswith('t') else 'scan_id': runner_id},
			}
			conn.execute(
				'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) '
				'VALUES (?, ?, ?, ?, 0, ?)',
				(uuid, 'vulnerability', ws, int(is_false_positive), json.dumps(doc)),
			)
		conn.commit()

	def tearDown(self):
		for conn in self.sqlite_mod._conns.values():
			conn.close()
		self.sqlite_mod._conns.clear()
		CONFIG.addons.sqlite.path = self._orig_path
		shutil.rmtree(self.tmp, ignore_errors=True)

	def _backend(self):
		from secator.query.sqlite import SqliteBackend
		return SqliteBackend('')

	def test_list_runners_by_name_or_id(self):
		b = self._backend()
		by_name = {r['name'] for r in b.list_runners(workspace_id='ws1')}
		by_id = {r['name'] for r in b.list_runners(workspace_id=WS_ID)}
		self.assertEqual(by_name, {'alpha', 'child'})
		self.assertEqual(by_id, {'alpha', 'child'})

	def test_list_runners_all_and_filters(self):
		b = self._backend()
		self.assertEqual({r['name'] for r in b.list_runners()}, {'alpha', 'beta', 'child'})
		self.assertEqual({r['name'] for r in b.list_runners(has_parent=False)}, {'alpha', 'beta'})
		self.assertEqual({r['name'] for r in b.list_runners(has_parent=True)}, {'child'})
		scans = b.list_runners(runner_type='scan')
		self.assertEqual([r['name'] for r in scans], ['beta'])
		self.assertEqual(scans[0]['_id_str'], 'scans/s1')
		self.assertEqual(scans[0]['_workspace'], 'ws2')
		self.assertEqual(b.list_runners(runner_type='bogus'), [])

	def test_report_list_shows_scoped_vulnerability_counts(self):
		result, out = _invoke(['--driver', 'sqlite'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('1C|1H', out)
		self.assertNotIn('1M', out)

	def test_all_workspaces_shows_each_workspace_vulnerability_counts(self):
		result, out = _invoke(['--driver', 'sqlite', '--all-workspaces'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('1C|1H', out)
		self.assertIn('1M', out)


class TestReportListMongoDB(ReportListAssertions, unittest.TestCase):
	"""Mongo runner docs carry context.workspace_id and context.workspace_name."""

	driver = 'mongodb'

	def setUp(self):
		import pytest
		pytest.importorskip('mongomock')
		import mongomock
		client = mongomock.MongoClient()
		client.main.tasks.insert_one({'name': 'alpha', 'has_parent': False, 'status': 'SUCCESS',
			'start_time': datetime(2026, 1, 2),
			'context': {'task_id': '64b000000000000000000001', 'workspace_id': WS_ID, 'workspace_name': 'ws1'}})
		client.main.scans.insert_one({'name': 'beta', 'has_parent': False, 'status': 'SUCCESS',
			'start_time': datetime(2026, 1, 1),
			'context': {'scan_id': '64b000000000000000000002', 'workspace_id': OTHER_WS_ID, 'workspace_name': 'ws2'}})
		from bson.objectid import ObjectId
		client.main.findings.insert_many([
			{'_type': 'vulnerability', 'severity': 'critical',
				'_context': {'workspace_id': WS_ID, 'task_id': ObjectId('64b000000000000000000001')}},
			{'_type': 'vulnerability', 'severity': 'high',
				'_context': {'workspace_id': WS_ID, 'task_id': '64b000000000000000000001'}},
			{'_type': 'vulnerability', 'severity': 'medium',
				'_context': {'workspace_id': OTHER_WS_ID, 'scan_id': '64b000000000000000000002'}},
		])
		patcher = mock.patch('secator.query.mongodb.MongoDBBackend._get_client', return_value=client)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _backend(self):
		from secator.query.mongodb import MongoDBBackend
		return MongoDBBackend('')

	def test_report_list_aggregates_mongodb_vulnerability_counts(self):
		result, out = _invoke(['--driver', 'mongodb'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('1C|1H', out)

	def test_all_workspaces_shows_each_mongodb_vulnerability_count(self):
		result, out = _invoke(['--driver', 'mongodb', '--all-workspaces'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('1C|1H', out)
		self.assertIn('1M', out)


class TestReportListApi(unittest.TestCase):
	"""The api backend filters by workspace id, so the current workspace name is resolved first."""

	def _invoke(self, args, resolve=None):
		calls = []

		def fake_request(method, endpoint, *a, **kw):
			calls.append(endpoint)
			if 'findings/_search' in endpoint:
				return []
			# Newest first, as a remote endpoint may return them.
			return [
				{'name': 'alpha', 'status': 'SUCCESS', '_type': 'task', '_id': 'x1',
					'start_time': '2026-01-02T00:00:00Z', 'context': {'workspace_name': 'ws1'}},
				{'name': 'beta', 'status': 'SUCCESS', '_type': 'task', '_id': 'x2',
					'start_time': '2026-01-01T00:00:00Z', 'context': {'workspace_name': 'ws1'}},
			]

		resolve = resolve or mock.Mock(return_value=(WS_ID, 'ws1'))
		request_patch = mock.patch('secator.query.api.ApiBackend._make_request', side_effect=fake_request)
		resolve_patch = mock.patch('secator.hooks.api.resolve_workspace', resolve)
		with request_patch, resolve_patch:
			result, out = _invoke(['--driver', 'api'] + args)
		return result, out, calls, resolve

	def test_defaults_to_current_workspace_id(self):
		result, out, calls, resolve = self._invoke([])
		self.assertEqual(result.exit_code, 0, result.output)
		resolve.assert_called_once_with('ws1')
		self.assertEqual(len([call for call in calls if 'runners' in call]), 1)
		self.assertIn(f'workspace_id={WS_ID}', calls[0])
		self.assertIn('Current workspace: ws1', out)

	def test_all_workspaces_sends_no_workspace_filter(self):
		result, out, calls, resolve = self._invoke(['--all-workspaces'])
		self.assertEqual(result.exit_code, 0, result.output)
		# Listing is unfiltered; the API workspace name is resolved later for finding counts.
		resolve.assert_called_once_with('ws1')
		self.assertNotIn('workspace_id=', calls[0])
		self.assertNotIn('workspace_name=', calls[0])
		self.assertIn('Workspace', out)
		self.assertIn('ws1', out)

	def test_vulnerability_counts_use_resolved_workspace_id(self):
		from secator.cli import cli
		calls = []

		def fake_request(method, endpoint, data=None):
			calls.append((method, endpoint, data))
			if 'runners' in endpoint:
				return [{'name': 'alpha', 'status': 'SUCCESS', '_type': 'task', '_id': 't1',
					'context': {'workspace_name': 'ws1'}}]
			if 'findings/_search' in endpoint:
				return [{'_id': 'v1', '_type': 'vulnerability', 'severity': 'high',
					'_context': {'workspace_id': WS_ID, 'task_id': 't1'}}]
			return []

		resolve = mock.Mock(return_value=(WS_ID, 'ws1'))
		with mock.patch.object(CONFIG.workspaces, 'current', 'ws1'):
			with mock.patch('secator.query.api.ApiBackend._make_request', side_effect=fake_request):
				with mock.patch('secator.hooks.api.resolve_workspace', resolve):
					result = CliRunner().invoke(
						cli, ['r', 'list', '--driver', 'api'], env={'COLUMNS': '400'})

		out = ' '.join(_strip_ansi(result.output).split())
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('1H', out)
		resolve.assert_called_once_with('ws1')
		finding_queries = [data for _, endpoint, data in calls if 'findings/_search' in endpoint]
		self.assertTrue(finding_queries)
		self.assertIn(WS_ID, str(finding_queries[0]))

	def test_most_recent_last_regardless_of_endpoint_order(self):
		result, out, _, _ = self._invoke([])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertLess(out.index('beta'), out.index('alpha'))

	def _backend_names(self, endpoint_rows, **kwargs):
		from secator.query.api import ApiBackend
		with mock.patch('secator.query.api.ApiBackend._make_request', return_value=endpoint_rows):
			return [r['name'] for r in ApiBackend(WS_ID).list_runners(**kwargs)]

	def test_backend_both_orders_regardless_of_endpoint_order(self):
		old = {'name': 'beta', 'start_time': '2026-01-01T00:00:00Z'}
		new = {'name': 'alpha', 'start_time': '2026-01-02T00:00:00Z'}
		for rows in ([new, old], [old, new]):
			self.assertEqual(self._backend_names(rows), ['beta', 'alpha'])
			self.assertEqual(self._backend_names(rows, order='asc'), ['beta', 'alpha'])
			self.assertEqual(self._backend_names(rows, order='desc'), ['alpha', 'beta'])

	def test_unresolvable_workspace_errors_with_hint(self):
		resolve = mock.Mock(side_effect=Exception('Workspace "ws1" not found in remote API.'))
		result, out, calls, _ = self._invoke([], resolve=resolve)
		self.assertEqual(result.exit_code, 1)
		self.assertEqual(calls, [])
		self.assertIn('not found', out)
		self.assertIn('--all-workspaces', out)

	def test_vulnerability_counts_use_one_paginated_search_for_all_runner_ids(self):
		from secator.query.api import ApiBackend
		findings = [
			{'_id': 'v1', '_type': 'vulnerability', 'severity': 'critical',
				'_context': {'workspace_id': WS_ID, 'task_id': 't1'}},
			{'_id': 'v2', '_type': 'vulnerability', 'severity': 'high',
				'_context': {'workspace_id': WS_ID, 'task_id': 't1', 'workflow_id': 'w1'}},
			{'_id': 'v3', '_type': 'vulnerability', 'severity': 'low',
				'_context': {'workspace_id': WS_ID, 'task_id': 't2'}},
		]
		calls = []

		def fake_request(method, endpoint, data=None):
			calls.append((method, endpoint, data))
			if len(calls) == 1:
				return {'items': findings}
			return {'items': []}

		with mock.patch.object(ApiBackend, '_make_request', side_effect=fake_request):
			counts = ApiBackend(WS_ID).vuln_counts_by_runner({
				'task': ['t1', 't2'], 'workflow': ['w1'],
			})

		self.assertEqual(counts, {
			'task': {'t1': {'critical': 1, 'high': 1}, 't2': {'low': 1}},
			'workflow': {'w1': {'high': 1}},
		})
		self.assertEqual(len(calls), 2)  # one result page and one terminal empty page
		query = calls[0][2]
		self.assertEqual(query['_type'], 'vulnerability')
		self.assertEqual(query['$or'], [
			{'_context.task_id': {'$in': ['t1', 't2']}},
			{'_context.workflow_id': {'$in': ['w1']}},
		])


class TestSortRunnersChronologically(unittest.TestCase):
	"""The shared ordering helper every backend's list_runners goes through."""

	def test_mixed_timestamp_types_oldest_first(self):
		from secator.query._base import sort_runners_chronologically
		runners = [
			{'name': 'c', 'start_time': '2026-01-03T00:00:00Z'},
			{'name': 'a', 'start_time': datetime(2026, 1, 1).timestamp()},
			{'name': 'b', 'start_time': datetime(2026, 1, 2)},
			{'name': 'end-only', 'end_time': '2026-01-04T00:00:00'},
			{'name': 'unknown'},
		]
		names = [r['name'] for r in sort_runners_chronologically(runners)]
		self.assertEqual(names, ['unknown', 'a', 'b', 'c', 'end-only'])

	def test_fallback_used_when_no_timestamp(self):
		from secator.query._base import sort_runners_chronologically
		runners = [{'name': 'new', 'm': 20.0}, {'name': 'old', 'm': 10.0}]
		names = [r['name'] for r in sort_runners_chronologically(runners, fallback=lambda r: r['m'])]
		self.assertEqual(names, ['old', 'new'])
		names = [r['name'] for r in sort_runners_chronologically(runners, fallback=lambda r: r['m'], order='desc')]
		self.assertEqual(names, ['new', 'old'])

	def test_desc_most_recent_first_unknown_last(self):
		from secator.query._base import sort_runners_chronologically
		runners = [
			{'name': 'unknown'},
			{'name': 'a', 'start_time': '2026-01-01T00:00:00Z'},
			{'name': 'c', 'start_time': '2026-01-03T00:00:00Z'},
			{'name': 'b', 'start_time': '2026-01-02T00:00:00Z'},
		]
		names = [r['name'] for r in sort_runners_chronologically(runners, order='desc')]
		self.assertEqual(names, ['c', 'b', 'a', 'unknown'])

	def test_ties_keep_backend_order_in_both_orders(self):
		from secator.query._base import sort_runners_chronologically
		ts = '2026-01-01T00:00:00Z'
		runners = [{'name': 'first', 'start_time': ts}, {'name': 'second', 'start_time': ts}]
		for order in ('asc', 'desc'):
			names = [r['name'] for r in sort_runners_chronologically(runners, order=order)]
			self.assertEqual(names, ['first', 'second'], order)

	def test_invalid_order_raises(self):
		from secator.query import QueryEngine
		from secator.query._base import sort_runners_chronologically
		with self.assertRaises(ValueError):
			sort_runners_chronologically([], order='newest')
		engine = QueryEngine('', context={})
		with mock.patch.object(engine, 'backend') as backend, self.assertRaises(ValueError):
			engine.list_runners(order='newest')
		backend.list_runners.assert_not_called()

	def test_invalid_order_raises_on_every_backend(self):
		# Raised before each backend's broad error handling, not swallowed into [].
		from secator.query.api import ApiBackend
		from secator.query.json import JsonBackend
		from secator.query.mongodb import MongoDBBackend
		from secator.query.sqlite import SqliteBackend
		for cls in (JsonBackend, SqliteBackend, MongoDBBackend, ApiBackend):
			with self.assertRaises(ValueError, msg=cls.__name__):
				cls('').list_runners(order='newest')

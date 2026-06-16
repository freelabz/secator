# tests/unit/test_query.py

import unittest


class TestQueryBackendBase(unittest.TestCase):
	def _create_test_backend(self, workspace_id='ws123'):
		"""Helper to create a concrete test backend."""
		from secator.query._base import QueryBackend

		class TestBackend(QueryBackend):
			name = 'test'

			def __init__(self, workspace_id, config=None):
				super().__init__(workspace_id, config)
				self.last_count_query = None

			def _execute_search(self, query, limit, exclude_fields=None):
				return []

			def _execute_count(self, query):
				self.last_count_query = query
				return 0

			def _execute_update(self, query, update):
				return 0

		return TestBackend(workspace_id=workspace_id)

	def test_base_query_includes_workspace_id(self):
		from secator.query._base import QueryBackend

		# Can't instantiate abstract class, so test via concrete implementation
		# For now just test the module imports
		self.assertTrue(hasattr(QueryBackend, 'PROTECTED_FIELDS'))
		self.assertIn('_context.workspace_id', QueryBackend.PROTECTED_FIELDS)

	def test_merge_query_enforces_base(self):
		backend = self._create_test_backend(workspace_id='ws123')

		# Try to override protected field
		user_query = {'_type': 'vulnerability', '_context.workspace_id': 'malicious_id'}

		merged = backend._merge_query(user_query)

		# Protected field should be enforced
		self.assertEqual(merged['_context.workspace_id'], 'ws123')
		self.assertEqual(merged['_type'], 'vulnerability')
		self.assertEqual(merged['is_false_positive'], {'$ne': True})

	def test_merge_query_preserves_user_fields(self):
		backend = self._create_test_backend(workspace_id='ws123')

		user_query = {'_type': 'url', 'severity': {'$in': ['critical', 'high']}, 'url': {'$contains': 'login'}}

		merged = backend._merge_query(user_query)

		self.assertEqual(merged['_type'], 'url')
		self.assertEqual(merged['severity'], {'$in': ['critical', 'high']})
		self.assertEqual(merged['url'], {'$contains': 'login'})

	def test_count_enforces_base_query(self):
		"""Verify count() applies base query protection like search()."""
		backend = self._create_test_backend(workspace_id='ws123')

		# Try to bypass workspace isolation in count
		malicious_query = {
			'_type': 'vulnerability',
			'_context.workspace_id': 'other_workspace',
			# '_context.workspace_duplicate': True,
		}

		backend.count(malicious_query)

		# Verify the query passed to _execute_count has protected fields enforced
		self.assertIsNotNone(backend.last_count_query)
		self.assertEqual(backend.last_count_query['_context.workspace_id'], 'ws123')
		# self.assertEqual(backend.last_count_query['_context.workspace_duplicate'], False)
		self.assertEqual(backend.last_count_query['is_false_positive'], {'$ne': True})
		# User field should still be preserved
		self.assertEqual(backend.last_count_query['_type'], 'vulnerability')


class TestJsonBackend(unittest.TestCase):
	def setUp(self):
		import tempfile
		import json
		from pathlib import Path
		from secator.query.json import JsonBackend

		self.temp_dir = tempfile.mkdtemp()
		self.workspace_id = 'test_workspace'
		self.task_id = '0'
		self.workspace_dir = Path(self.temp_dir) / self.workspace_id / 'tasks' / self.task_id
		self.workspace_dir.mkdir(parents=True)
		self.backend = JsonBackend(workspace_id=self.workspace_id, config={'reports_dir': self.temp_dir})

		# Create test report.json
		self.test_data = {
			'info': {'name': 'test'},
			'results': {
				'vulnerability': [
					{
						'_type': 'vulnerability',
						'name': 'SQL Injection',
						'severity': 'critical',
						'matched_at': 'http://example.com/login',
						'is_false_positive': False,
						'_context': {'workspace_id': self.workspace_id, 'workspace_duplicate': False},
					},
					{
						'_type': 'vulnerability',
						'name': 'XSS',
						'severity': 'medium',
						'matched_at': 'http://example.com/search',
						'is_false_positive': False,
						'_context': {'workspace_id': self.workspace_id, 'workspace_duplicate': False},
					},
				],
				'url': [
					{
						'_type': 'url',
						'url': 'http://example.com/login',
						'status_code': 200,
						'is_false_positive': False,
						'_context': {
							'workspace_id': self.workspace_id,
							'workspace_duplicate': False,
						},
					}
				],
			},
		}

		with open(self.workspace_dir / 'report.json', 'w') as f:
			json.dump(self.test_data, f)

	def tearDown(self):
		import shutil

		shutil.rmtree(self.temp_dir)

	def test_json_backend_search_by_type(self):
		from secator.query.json import JsonBackend

		backend = JsonBackend(workspace_id=self.workspace_id, config={'reports_dir': self.temp_dir})

		results = backend.search({'_type': 'vulnerability'})

		self.assertEqual(len(results), 2)
		self.assertTrue(all(r['_type'] == 'vulnerability' for r in results))

	def test_json_backend_search_with_operator(self):
		from secator.query.json import JsonBackend

		backend = JsonBackend(workspace_id=self.workspace_id, config={'reports_dir': self.temp_dir})

		results = backend.search({'_type': 'vulnerability', 'severity': {'$in': ['critical', 'high']}})

		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['name'], 'SQL Injection')

	def test_json_backend_search_contains(self):
		from secator.query.json import JsonBackend

		backend = JsonBackend(workspace_id=self.workspace_id, config={'reports_dir': self.temp_dir})

		results = backend.search({'_type': 'vulnerability', 'matched_at': {'$contains': 'login'}})

		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['name'], 'SQL Injection')

	def test_json_backend_count(self):
		from secator.query.json import JsonBackend

		backend = JsonBackend(workspace_id=self.workspace_id, config={'reports_dir': self.temp_dir})

		count = backend.count({'_type': 'vulnerability'})
		self.assertEqual(count, 2)

	def test_json_backend_injects_context_from_path(self):
		"""Findings from tasks/{id}/report.json should have _context.task_id injected."""
		results = self.backend.search({'_context.task_id': self.task_id})
		assert len(results) > 0
		for result in results:
			assert result.get('_context', {}).get('task_id') == self.task_id

	def test_json_backend_or_query(self):
		"""$or query should match items satisfying any sub-condition."""
		all_results = self.backend.search({})
		all_types = {r.get('_type') for r in all_results}
		if len(all_types) < 2:
			return  # skip if only one type in fixture

		types_list = sorted(all_types)
		selected = {types_list[0], types_list[1]}
		results = self.backend.search({'$or': [{'_type': types_list[0]}, {'_type': types_list[1]}]})
		result_types = {r.get('_type') for r in results}
		assert result_types, 'expected at least one result from $or query'
		assert result_types.issubset(selected), f'unexpected types leaked: {result_types - selected}'
		assert result_types == selected, f'missing branch of $or: {selected - result_types}'

	def test_json_backend_or_with_additional_filter(self):
		"""$or combined with top-level field filters must respect both."""
		# Get a known type from the fixture
		all_results = self.backend.search({})
		all_types = list({r.get('_type') for r in all_results})
		if not all_types:
			return
		known_type = all_types[0]
		# Query: match known_type OR task_id='nonexistent', but also require a field that doesn't exist
		results = self.backend.search({'$or': [{'_type': known_type}], 'definitely_nonexistent_field_xyz': 'impossible_value'})
		# The AND of ($or matches) AND (field doesn't match) = no results
		assert len(results) == 0

	def test_json_backend_and_query(self):
		"""$and query should require all sub-conditions."""
		all_results = self.backend.search({})
		if not all_results:
			return
		first_type = all_results[0].get('_type')
		# $and with matching conditions = results
		results = self.backend.search({'$and': [{'_type': first_type}, {'_type': first_type}]})
		assert len(results) > 0
		# $and with contradictory conditions = no results
		results = self.backend.search({'$and': [{'_type': first_type}, {'_type': '__impossible__'}]})
		assert len(results) == 0


class TestQueryOperators(unittest.TestCase):
	def test_get_nested_field(self):
		from secator.query.json import get_nested_field

		item = {'_context': {'workspace_id': 'ws123', 'nested': {'deep': 'value'}}, 'name': 'test'}

		self.assertEqual(get_nested_field(item, 'name'), 'test')
		self.assertEqual(get_nested_field(item, '_context.workspace_id'), 'ws123')
		self.assertEqual(get_nested_field(item, '_context.nested.deep'), 'value')
		self.assertIsNone(get_nested_field(item, 'nonexistent'))

	def test_match_query_direct_match(self):
		from secator.query.json import match_query

		item = {'_type': 'url', 'status_code': 200}

		self.assertTrue(match_query(item, {'_type': 'url'}))
		self.assertTrue(match_query(item, {'status_code': 200}))
		self.assertFalse(match_query(item, {'_type': 'vulnerability'}))

	def test_match_query_operators(self):
		from secator.query.json import match_query

		item = {'severity': 'critical', 'cvss_score': 9.5, 'url': 'http://example.com/login'}

		# $in
		self.assertTrue(match_query(item, {'severity': {'$in': ['critical', 'high']}}))
		self.assertFalse(match_query(item, {'severity': {'$in': ['low', 'medium']}}))

		# $contains
		self.assertTrue(match_query(item, {'url': {'$contains': 'login'}}))
		self.assertFalse(match_query(item, {'url': {'$contains': 'admin'}}))

		# $gt, $gte, $lt, $lte
		self.assertTrue(match_query(item, {'cvss_score': {'$gt': 9.0}}))
		self.assertTrue(match_query(item, {'cvss_score': {'$gte': 9.5}}))
		self.assertFalse(match_query(item, {'cvss_score': {'$lt': 9.0}}))

		# $regex
		self.assertTrue(match_query(item, {'url': {'$regex': r'example\.com'}}))
		self.assertFalse(match_query(item, {'url': {'$regex': r'other\.com'}}))

		# $regex with pattern starting with * — leading * is stripped, remaining pattern matches
		self.assertTrue(match_query(item, {'url': {'$regex': '*example'}}))

		# $regex with numeric pattern — should convert to string, not raise TypeError
		item_with_id = {'id': 'CVE-2026-12345', 'score': 9}
		self.assertFalse(match_query(item_with_id, {'score': {'$regex': 7}}))


class TestQueryUtils(unittest.TestCase):
	def test_regex_value_stays_string(self):
		"""~= operator must not coerce the RHS to int/float (re.search needs a string)."""
		from secator.query.utils import python_expr_to_mongo

		result = python_expr_to_mongo('vulnerability.id ~= 123')
		self.assertEqual(result, {'_type': 'vulnerability', 'id': {'$regex': '123'}})
		self.assertIsInstance(result['id']['$regex'], str)

	def test_regex_value_with_glob_start(self):
		"""~= operator with a leading wildcard should produce the raw string, not raise."""
		from secator.query.utils import python_expr_to_mongo

		result = python_expr_to_mongo("vulnerability.id ~= '*CVE-2026-28780'")
		self.assertEqual(result['id'], {'$regex': '*CVE-2026-28780'})

	def test_numeric_comparison_still_converts(self):
		"""Non-regex operators should still coerce numeric RHS values."""
		from secator.query.utils import python_expr_to_mongo

		result = python_expr_to_mongo('vulnerability.cvss_score > 7')
		self.assertEqual(result['cvss_score'], {'$gt': 7})
		self.assertIsInstance(result['cvss_score']['$gt'], int)


class TestMongoDBBackend(unittest.TestCase):
	def test_mongodb_backend_instantiation(self):
		from secator.query.mongodb import MongoDBBackend

		backend = MongoDBBackend(workspace_id='ws123')
		self.assertEqual(backend.workspace_id, 'ws123')
		self.assertEqual(backend.name, 'mongodb')


class TestApiBackend(unittest.TestCase):
	def test_api_backend_instantiation(self):
		from secator.query.api import ApiBackend

		backend = ApiBackend(workspace_id='ws123')
		self.assertEqual(backend.workspace_id, 'ws123')
		self.assertEqual(backend.name, 'api')

	def test_api_backend_base_query_includes_tagged(self):
		from secator.query.api import ApiBackend

		backend = ApiBackend(workspace_id='ws123')
		base = backend.get_base_query()

		# self.assertEqual(base['_tagged'], True)
		self.assertEqual(base['_context.workspace_id'], 'ws123')


class TestQueryEngine(unittest.TestCase):
	def test_query_engine_selects_json_by_default(self):
		from secator.query import QueryEngine
		from secator.query.json import JsonBackend

		engine = QueryEngine(workspace_id='ws123', context={})
		self.assertIsInstance(engine.backend, JsonBackend)

	def test_query_engine_selects_api(self):
		from secator.query import QueryEngine
		from secator.query.api import ApiBackend

		engine = QueryEngine(workspace_id='ws123', context={'drivers': ['api']})
		self.assertIsInstance(engine.backend, ApiBackend)

	def test_query_engine_selects_mongodb(self):
		from secator.query import QueryEngine
		from secator.query.mongodb import MongoDBBackend

		engine = QueryEngine(workspace_id='ws123', context={'drivers': ['mongodb']})
		self.assertIsInstance(engine.backend, MongoDBBackend)

	def test_query_engine_prefers_mongodb_over_api(self):
		from secator.query import QueryEngine
		from secator.query.mongodb import MongoDBBackend

		# Backend follows driver priority (DRIVER_PRIORITY): the authoritative DB
		# (mongodb) prevails over the relay (api) regardless of list order.
		engine = QueryEngine(workspace_id='ws123', context={'drivers': ['api', 'mongodb']})
		self.assertIsInstance(engine.backend, MongoDBBackend)

	def test_query_engine_search_dedupe_removes_duplicates(self):
		"""QueryEngine.search(dedupe=True) should remove duplicate findings."""
		from secator.query import QueryEngine

		duplicate_finding = {
			'_type': 'vulnerability',
			'name': 'CVE-2021-1234',
			'severity': 'high',
			'_context': {'workspace_id': 'test_ws', 'workspace_duplicate': False},
			'is_false_positive': False,
		}
		engine = QueryEngine('test_ws', context={'results': [duplicate_finding, duplicate_finding.copy()]})
		results = engine.search({}, dedupe=True)
		assert len(results) == 1

	def test_query_engine_search_no_dedupe_keeps_duplicates(self):
		"""QueryEngine.search(dedupe=False) should keep all findings."""
		from secator.query import QueryEngine

		duplicate_finding = {
			'_type': 'vulnerability',
			'name': 'CVE-2021-1234',
			'_context': {'workspace_id': 'test_ws', 'workspace_duplicate': False},
			'is_false_positive': False,
		}
		engine = QueryEngine('test_ws', context={'results': [duplicate_finding, duplicate_finding.copy()]})
		results = engine.search({}, dedupe=False)
		assert len(results) == 2

	def test_query_engine_selects_sqlite(self):
		from secator.query import QueryEngine
		from secator.query.sqlite import SqliteBackend

		engine = QueryEngine(workspace_id='ws123', context={'drivers': ['sqlite']})
		self.assertIsInstance(engine.backend, SqliteBackend)

	def test_query_engine_prefers_mongodb_over_sqlite(self):
		from secator.query import QueryEngine
		from secator.query.mongodb import MongoDBBackend

		# Driver priority (DRIVER_PRIORITY) ranks mongodb before sqlite, so mongodb
		# is selected regardless of list order.
		engine = QueryEngine(workspace_id='ws123', context={'drivers': ['sqlite', 'mongodb']})
		self.assertIsInstance(engine.backend, MongoDBBackend)


class TestQueryEngineUpdate(unittest.TestCase):
	"""Tests for QueryEngine.update method."""

	def test_json_backend_update(self):
		from secator.query.json import JsonBackend
		backend = JsonBackend('test', results=[
			{'_type': 'ai', 'ai_type': 'follow_up', 'session_id': 's1', 'status': 'pending'},
			{'_type': 'url', 'url': 'http://a.com'},
		])
		backend.update(
			{'_type': 'ai', 'session_id': 's1', 'status': 'pending'},
			{'$set': {'status': 'timed_out'}}
		)
		results = backend.search({'_type': 'ai', 'session_id': 's1'})
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['status'], 'timed_out')

	def test_json_backend_update_no_match(self):
		from secator.query.json import JsonBackend
		backend = JsonBackend('test', results=[
			{'_type': 'url', 'url': 'http://a.com'},
		])
		# Should not raise
		backend.update(
			{'_type': 'ai', 'session_id': 's1'},
			{'$set': {'status': 'timed_out'}}
		)

	def test_query_engine_update_delegates(self):
		from secator.query import QueryEngine
		from unittest.mock import MagicMock
		engine = QueryEngine('ws1', context={})
		engine.backend = MagicMock()
		engine.update({'_type': 'ai'}, {'$set': {'status': 'done'}})
		engine.backend.update.assert_called_once_with(
			{'_type': 'ai'}, {'$set': {'status': 'done'}}
		)


class TestSqliteBackend(unittest.TestCase):
	def setUp(self):
		import tempfile
		import json
		from pathlib import Path
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG

		self.sqlite_mod = sqlite_mod
		self.temp_dir = tempfile.mkdtemp()
		self.db_path = str(Path(self.temp_dir) / 'test.db')
		self._orig_path = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = self.db_path
		sqlite_mod._conns.clear()
		self.ws = 'ws1'
		conn = sqlite_mod.get_sqlite_conn()
		rows = [
			('u1', 'vulnerability', self.ws, 0, {'_type': 'vulnerability', 'name': 'SQLi',
				'severity': 'critical', 'matched_at': 'http://x/login', 'is_false_positive': False,
				'_context': {'workspace_id': self.ws, 'workspace_duplicate': False}}),
			('u2', 'vulnerability', self.ws, 0, {'_type': 'vulnerability', 'name': 'XSS',
				'severity': 'medium', 'matched_at': 'http://x/search', 'is_false_positive': False,
				'_context': {'workspace_id': self.ws, 'workspace_duplicate': False}}),
			('u3', 'url', self.ws, 0, {'_type': 'url', 'url': 'http://x/login',
				'is_false_positive': False, '_context': {'workspace_id': self.ws, 'workspace_duplicate': False}}),
		]
		for uuid_, type_, ws, fp, data in rows:
			conn.execute(
				"INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) "
				"VALUES (?, ?, ?, ?, 0, ?)",
				(uuid_, type_, ws, fp, json.dumps(data)))
		conn.commit()

	def tearDown(self):
		import shutil
		from secator.config import CONFIG
		for conn in self.sqlite_mod._conns.values():
			conn.close()
		self.sqlite_mod._conns.clear()
		CONFIG.addons.sqlite.path = self._orig_path
		shutil.rmtree(self.temp_dir)

	def _backend(self):
		from secator.query.sqlite import SqliteBackend
		return SqliteBackend(workspace_id=self.ws)

	def test_search_by_type(self):
		results = self._backend().search({'_type': 'vulnerability'})
		self.assertEqual(len(results), 2)
		self.assertTrue(all(r['_type'] == 'vulnerability' for r in results))

	def test_search_with_in_operator(self):
		results = self._backend().search({'_type': 'vulnerability', 'severity': {'$in': ['critical', 'high']}})
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['name'], 'SQLi')

	def test_search_contains(self):
		results = self._backend().search({'matched_at': {'$contains': 'login'}})
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['name'], 'SQLi')

	def test_search_regex(self):
		results = self._backend().search({'matched_at': {'$regex': r'/search'}})
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0]['name'], 'XSS')

	def test_count(self):
		self.assertEqual(self._backend().count({'_type': 'vulnerability'}), 2)

	def test_base_query_enforces_workspace(self):
		results = self._backend().search({})
		self.assertTrue(all(r['_context']['workspace_id'] == self.ws for r in results))

	def test_limit(self):
		results = self._backend().search({}, limit=1)
		self.assertEqual(len(results), 1)

	def test_exclude_fields(self):
		results = self._backend().search({'_type': 'url'}, exclude_fields=['url'])
		self.assertNotIn('url', results[0])

	def test_update(self):
		backend = self._backend()
		n = backend.update({'_type': 'url'}, {'$set': {'status_code': 404}})
		self.assertEqual(n, 1)
		results = backend.search({'_type': 'url'})
		self.assertEqual(results[0]['status_code'], 404)

	def test_update_multiple_fields(self):
		backend = self._backend()
		n = backend.update({'_type': 'url'}, {'$set': {'status_code': 200, 'title': 'Home'}})
		self.assertEqual(n, 1)
		results = backend.search({'_type': 'url'})
		self.assertEqual(results[0]['status_code'], 200)
		self.assertEqual(results[0]['title'], 'Home')

	def test_update_rejects_malicious_field_name(self):
		backend = self._backend()
		with self.assertRaises(ValueError):
			backend.update({'_type': 'url'}, {'$set': {"x', type = 'pwned' --": 1}})
		# Confirm no row was corrupted: the url row still has type 'url'.
		results = backend.search({'_type': 'url'})
		self.assertEqual(len(results), 1)


class TestSqliteWiring(unittest.TestCase):
	def test_sqlite_in_available_drivers(self):
		from secator.loader import get_available_drivers
		self.assertIn('sqlite', get_available_drivers())

	def test_sqlite_addon_config_exists(self):
		from secator.config import CONFIG
		self.assertFalse(CONFIG.addons.sqlite.enabled)
		self.assertEqual(CONFIG.addons.sqlite.busy_timeout_ms, 5000)
		self.assertEqual(CONFIG.addons.sqlite.max_items, -1)
		self.assertIsInstance(CONFIG.addons.sqlite.duplicate_main_copy_fields, list)


class TestSqliteTranslator(unittest.TestCase):
	def _where(self, query):
		from secator.query.sqlite import _build_where
		return _build_where(query)

	def test_equality(self):
		sql, params = self._where({'_type': 'url'})
		self.assertEqual(sql, "type = ?")
		self.assertEqual(params, ['url'])

	def test_plain_field_uses_json_extract(self):
		sql, params = self._where({'name': 'foo'})
		self.assertEqual(sql, "json_extract(data, '$.name') = ?")
		self.assertEqual(params, ['foo'])

	def test_mirrored_workspace_id(self):
		sql, params = self._where({'_context.workspace_id': 'ws1'})
		self.assertEqual(sql, "workspace_id = ?")
		self.assertEqual(params, ['ws1'])

	def test_comparison_ops(self):
		sql, params = self._where({'cvss_score': {'$gte': 9.0}})
		self.assertEqual(sql, "json_extract(data, '$.cvss_score') >= ?")
		self.assertEqual(params, [9.0])

	def test_in_op(self):
		sql, params = self._where({'severity': {'$in': ['critical', 'high']}})
		self.assertEqual(sql, "json_extract(data, '$.severity') IN (?, ?)")
		self.assertEqual(params, ['critical', 'high'])

	def test_contains_op(self):
		sql, params = self._where({'url': {'$contains': 'login'}})
		self.assertEqual(sql, "json_extract(data, '$.url') LIKE '%' || ? || '%'")
		self.assertEqual(params, ['login'])

	def test_regex_op(self):
		sql, params = self._where({'url': {'$regex': r'example\.com'}})
		self.assertEqual(sql, "json_extract(data, '$.url') REGEXP ?")
		self.assertEqual(params, [r'example\.com'])

	def test_and(self):
		sql, params = self._where({'$and': [{'_type': 'url'}, {'name': 'x'}]})
		self.assertEqual(sql, "(type = ? AND json_extract(data, '$.name') = ?)")
		self.assertEqual(params, ['url', 'x'])

	def test_or(self):
		sql, params = self._where({'$or': [{'_type': 'url'}, {'_type': 'port'}]})
		self.assertEqual(sql, "(type = ? OR type = ?)")
		self.assertEqual(params, ['url', 'port'])

	def test_empty(self):
		sql, params = self._where({})
		self.assertEqual(sql, "")
		self.assertEqual(params, [])

	def test_in_empty_list(self):
		sql, params = self._where({'severity': {'$in': []}})
		self.assertEqual(sql, "0")
		self.assertEqual(params, [])

	def test_or_empty_list(self):
		sql, params = self._where({'$or': []})
		self.assertEqual(sql, "0")
		self.assertEqual(params, [])

	def test_and_empty_list(self):
		sql, params = self._where({'$and': []})
		self.assertEqual(sql, "1=1")
		self.assertEqual(params, [])

	def test_dotted_field_allowed(self):
		sql, params = self._where({'foo.bar': 'baz'})
		self.assertEqual(sql, "json_extract(data, '$.foo.bar') = ?")
		self.assertEqual(params, ['baz'])

	def test_invalid_field_name_rejected(self):
		from secator.query.sqlite import _build_where
		with self.assertRaises(ValueError):
			_build_where({"x') UNION SELECT 1 --": 'v'})

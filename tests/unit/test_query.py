# tests/unit/test_query.py

import unittest


class TestQueryBackendBase(unittest.TestCase):

    def _create_test_backend(self, workspace_id='ws123'):
        """Helper to create a concrete test backend."""
        from secator.query._base import QueryBackend

        class TestBackend(QueryBackend):
            name = "test"

            def __init__(self, workspace_id, config=None):
                super().__init__(workspace_id, config)
                self.last_count_query = None

            def _execute_search(self, query, limit, exclude_fields=None):
                return []

            def _execute_count(self, query):
                self.last_count_query = query
                return 0

        return TestBackend(workspace_id=workspace_id)

    def test_base_query_includes_workspace_id(self):
        from secator.query._base import QueryBackend
        # Can't instantiate abstract class, so test via concrete implementation
        # For now just test the module imports
        self.assertTrue(hasattr(QueryBackend, 'PROTECTED_FIELDS'))
        self.assertIn('_context.workspace_id', QueryBackend.PROTECTED_FIELDS)

    def test_default_limit_constant(self):
        from secator.query._base import QueryBackend
        self.assertEqual(QueryBackend.DEFAULT_LIMIT, 100)

    def test_merge_query_enforces_base(self):
        backend = self._create_test_backend(workspace_id='ws123')

        # Try to override protected field
        user_query = {
            '_type': 'vulnerability',
            '_context.workspace_id': 'malicious_id'
        }

        merged = backend._merge_query(user_query)

        # Protected field should be enforced
        self.assertEqual(merged['_context.workspace_id'], 'ws123')
        self.assertEqual(merged['_type'], 'vulnerability')
        self.assertEqual(merged['is_false_positive'], False)

    def test_merge_query_preserves_user_fields(self):
        backend = self._create_test_backend(workspace_id='ws123')

        user_query = {
            '_type': 'url',
            'severity': {'$in': ['critical', 'high']},
            'url': {'$contains': 'login'}
        }

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
            '_context.workspace_duplicate': True
        }

        backend.count(malicious_query)

        # Verify the query passed to _execute_count has protected fields enforced
        self.assertIsNotNone(backend.last_count_query)
        self.assertEqual(backend.last_count_query['_context.workspace_id'], 'ws123')
        self.assertEqual(backend.last_count_query['_context.workspace_duplicate'], False)
        self.assertEqual(backend.last_count_query['is_false_positive'], False)
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
        self.backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        # Create test report.json
        self.test_data = {
            "info": {"name": "test"},
            "results": {
                "vulnerability": [
                    {
                        "_type": "vulnerability",
                        "name": "SQL Injection",
                        "severity": "critical",
                        "matched_at": "http://example.com/login",
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    },
                    {
                        "_type": "vulnerability",
                        "name": "XSS",
                        "severity": "medium",
                        "matched_at": "http://example.com/search",
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    }
                ],
                "url": [
                    {
                        "_type": "url",
                        "url": "http://example.com/login",
                        "status_code": 200,
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    }
                ]
            }
        }

        with open(self.workspace_dir / 'report.json', 'w') as f:
            json.dump(self.test_data, f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_json_backend_search_by_type(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({'_type': 'vulnerability'})

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['_type'] == 'vulnerability' for r in results))

    def test_json_backend_search_with_operator(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({
            '_type': 'vulnerability',
            'severity': {'$in': ['critical', 'high']}
        })

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'SQL Injection')

    def test_json_backend_search_contains(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({
            '_type': 'vulnerability',
            'matched_at': {'$contains': 'login'}
        })

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'SQL Injection')

    def test_json_backend_count(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

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

        types_list = list(all_types)
        results = self.backend.search({'$or': [{'_type': types_list[0]}, {'_type': types_list[1]}]})
        result_types = {r.get('_type') for r in results}
        assert types_list[0] in result_types or types_list[1] in result_types

    def test_json_backend_or_with_additional_filter(self):
        """$or combined with top-level field filters must respect both."""
        # Get a known type from the fixture
        all_results = self.backend.search({})
        all_types = list({r.get('_type') for r in all_results})
        if not all_types:
            return
        known_type = all_types[0]
        # Query: match known_type OR task_id='nonexistent', but also require a field that doesn't exist
        results = self.backend.search({
            '$or': [{'_type': known_type}],
            'definitely_nonexistent_field_xyz': 'impossible_value'
        })
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

        item = {
            '_context': {
                'workspace_id': 'ws123',
                'nested': {'deep': 'value'}
            },
            'name': 'test'
        }

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


class TestMongoDBBackend(unittest.TestCase):

    def test_mongodb_backend_instantiation(self):
        from secator.query.mongodb import MongoDBBackend

        backend = MongoDBBackend(workspace_id='ws123')
        self.assertEqual(backend.workspace_id, 'ws123')
        self.assertEqual(backend.name, 'mongodb')

    def test_mongodb_backend_base_query_includes_tagged(self):
        from secator.query.mongodb import MongoDBBackend

        backend = MongoDBBackend(workspace_id='ws123')
        base = backend.get_base_query()

        self.assertEqual(base['_tagged'], True)
        self.assertEqual(base['_context.workspace_id'], 'ws123')


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

        self.assertEqual(base['_tagged'], True)
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

    def test_query_engine_mongodb_takes_priority(self):
        from secator.query import QueryEngine
        from secator.query.mongodb import MongoDBBackend

        # When both are available, MongoDB takes priority
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
            'is_false_positive': False
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
            'is_false_positive': False
        }
        engine = QueryEngine('test_ws', context={'results': [duplicate_finding, duplicate_finding.copy()]})
        results = engine.search({}, dedupe=False)
        assert len(results) == 2

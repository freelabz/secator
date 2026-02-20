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

            def _execute_search(self, query, limit):
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

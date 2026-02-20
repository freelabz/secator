# tests/unit/test_query.py

import unittest


class TestQueryBackendBase(unittest.TestCase):

    def test_base_query_includes_workspace_id(self):
        from secator.query._base import QueryBackend
        # Can't instantiate abstract class, so test via concrete implementation
        # For now just test the module imports
        self.assertTrue(hasattr(QueryBackend, 'PROTECTED_FIELDS'))
        self.assertIn('_context.workspace_id', QueryBackend.PROTECTED_FIELDS)

    def test_merge_query_enforces_base(self):
        from secator.query._base import QueryBackend

        class TestBackend(QueryBackend):
            name = "test"

            def _execute_search(self, query, limit):
                return []

            def count(self, query):
                return 0

        backend = TestBackend(workspace_id='ws123')

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
        from secator.query._base import QueryBackend

        class TestBackend(QueryBackend):
            name = "test"

            def _execute_search(self, query, limit):
                return []

            def count(self, query):
                return 0

        backend = TestBackend(workspace_id='ws123')

        user_query = {
            '_type': 'url',
            'severity': {'$in': ['critical', 'high']},
            'url': {'$contains': 'login'}
        }

        merged = backend._merge_query(user_query)

        self.assertEqual(merged['_type'], 'url')
        self.assertEqual(merged['severity'], {'$in': ['critical', 'high']})
        self.assertEqual(merged['url'], {'$contains': 'login'})

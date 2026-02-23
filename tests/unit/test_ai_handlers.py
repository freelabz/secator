# tests/unit/test_ai_handlers.py

import unittest
from dataclasses import fields


class TestActionContext(unittest.TestCase):

    def test_action_context_has_workspace_fields(self):
        from secator.tasks.ai import ActionContext

        field_names = [f.name for f in fields(ActionContext)]

        self.assertIn('workspace_id', field_names)
        self.assertIn('workspace_name', field_names)
        self.assertIn('drivers', field_names)

    def test_action_context_workspace_defaults(self):
        from secator.tasks.ai import ActionContext

        ctx = ActionContext(targets=['target.com'], model='gpt-4')

        self.assertIsNone(ctx.workspace_id)
        self.assertIsNone(ctx.workspace_name)
        self.assertEqual(ctx.drivers, [])


class TestOutputTypeMap(unittest.TestCase):

    def test_output_type_map_exists(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        self.assertIsInstance(OUTPUT_TYPE_MAP, dict)

    def test_output_type_map_has_vulnerability(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        self.assertIn('vulnerability', OUTPUT_TYPE_MAP)
        self.assertEqual(OUTPUT_TYPE_MAP['vulnerability'], 'Vulnerability')

    def test_output_type_map_has_all_finding_types(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        expected = ['vulnerability', 'port', 'url', 'subdomain', 'ip', 'exploit', 'tag']
        for t in expected:
            self.assertIn(t, OUTPUT_TYPE_MAP)


class TestHandleQuery(unittest.TestCase):

    def test_handle_query_no_workspace(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            workspace_id=None,
        )
        action = {'action': 'query', 'query': {'_type': 'vulnerability'}}

        results = list(ai_instance._handle_query(action, ctx))

        # Should yield Warning about missing workspace
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('workspace', results[0].message.lower())

    def test_handle_query_success(self):
        from unittest.mock import Mock, patch
        from secator.tasks.ai import ai as AITask, ActionContext

        # Setup mock - patch at source module where QueryEngine is imported from
        with patch('secator.query.QueryEngine') as mock_engine_class:
            mock_engine = Mock()
            mock_engine.search.return_value = [
                {'_type': 'vulnerability', 'name': 'SQLi'},
                {'_type': 'vulnerability', 'name': 'XSS'},
            ]
            mock_engine_class.return_value = mock_engine

            ai_instance = AITask.__new__(AITask)
            ctx = ActionContext(
                targets=['target.com'],
                model='gpt-4',
                workspace_id='ws123',
                workspace_name='test_ws',
                attack_context={},
            )
            action = {
                'action': 'query',
                'query': {'_type': 'vulnerability'},
                'result_key': 'vulns',
            }

            results = list(ai_instance._handle_query(action, ctx))

            # Should yield Info with result count
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]._type, 'info')
            self.assertIn('2', results[0].message)

            # Should store in attack_context
            self.assertIn('vulns', ctx.attack_context)


class TestActionHandlers(unittest.TestCase):

    def test_action_handlers_has_query(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('query', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['query'], '_handle_query')

    def test_action_handlers_has_output_type(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('output_type', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['output_type'], '_handle_output_type')

    def test_action_handlers_has_prompt(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('prompt', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['prompt'], '_handle_prompt')


if __name__ == '__main__':
    unittest.main()

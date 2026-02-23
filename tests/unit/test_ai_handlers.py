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

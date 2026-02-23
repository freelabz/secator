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


if __name__ == '__main__':
    unittest.main()

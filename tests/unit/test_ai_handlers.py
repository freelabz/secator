# tests/unit/test_ai_handlers.py
"""Tests for AI action handlers and context."""

import unittest
from dataclasses import fields


class TestActionContext(unittest.TestCase):
    """Tests for the ActionContext dataclass."""

    def test_action_context_has_required_fields(self):
        from secator.tasks.ai_actions import ActionContext

        field_names = [f.name for f in fields(ActionContext)]

        self.assertIn('targets', field_names)
        self.assertIn('model', field_names)
        self.assertIn('encryptor', field_names)
        self.assertIn('dry_run', field_names)
        self.assertIn('auto_yes', field_names)
        self.assertIn('workspace_id', field_names)
        self.assertIn('attack_context', field_names)

    def test_action_context_defaults(self):
        from secator.tasks.ai_actions import ActionContext

        ctx = ActionContext(targets=['target.com'], model='gpt-4')

        self.assertEqual(ctx.targets, ['target.com'])
        self.assertEqual(ctx.model, 'gpt-4')
        self.assertIsNone(ctx.encryptor)
        self.assertFalse(ctx.dry_run)
        self.assertFalse(ctx.auto_yes)
        self.assertIsNone(ctx.workspace_id)
        self.assertEqual(ctx.attack_context, {})

    def test_action_context_with_all_params(self):
        from secator.tasks.ai_actions import ActionContext
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        ctx = ActionContext(
            targets=['a.com', 'b.com'],
            model='claude-3',
            encryptor=encryptor,
            dry_run=True,
            auto_yes=True,
            workspace_id='ws123',
            attack_context={'key': 'value'}
        )

        self.assertEqual(ctx.targets, ['a.com', 'b.com'])
        self.assertEqual(ctx.model, 'claude-3')
        self.assertIsNotNone(ctx.encryptor)
        self.assertTrue(ctx.dry_run)
        self.assertTrue(ctx.auto_yes)
        self.assertEqual(ctx.workspace_id, 'ws123')
        self.assertEqual(ctx.attack_context, {'key': 'value'})


class TestDispatchAction(unittest.TestCase):
    """Tests for the dispatch_action function."""

    def test_dispatch_unknown_action(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {'action': 'unknown_action_type'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('Unknown action', results[0].message)

    def test_dispatch_done_action(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {'action': 'done', 'reason': 'Test complete'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'ai')
        self.assertIn('Test complete', results[0].content)
        self.assertTrue(ctx.attack_context.get('_should_stop'))

    def test_dispatch_task_dry_run(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'task', 'name': 'nmap', 'targets': ['192.168.1.1']}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('nmap', results[0].message)

    def test_dispatch_workflow_dry_run(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'workflow', 'name': 'host_recon', 'targets': ['example.com']}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('host_recon', results[0].message)

    def test_dispatch_shell_dry_run(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'shell', 'command': 'curl http://example.com'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('curl', results[0].message)

    def test_dispatch_query_no_workspace(self):
        from secator.tasks.ai_actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', workspace_id=None)
        action = {'action': 'query', 'type': 'vulnerability', 'filter': {}}

        results = list(dispatch_action(action, ctx))

        # Should yield AI query message and Warning about no workspace
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1]._type, 'warning')
        self.assertIn('workspace', results[1].message.lower())


class TestAITask(unittest.TestCase):
    """Tests for the ai task class."""

    def test_ai_task_has_required_opts(self):
        from secator.tasks.ai import ai

        required_opts = ['prompt', 'mode', 'model', 'api_base', 'sensitive',
                         'max_iterations', 'temperature', 'dry_run', 'yes', 'verbose']
        for opt in required_opts:
            self.assertIn(opt, ai.opts, f"Missing opt: {opt}")

    def test_ai_task_output_types(self):
        from secator.tasks.ai import ai
        from secator.output_types import Ai, Error, Info, Warning, Vulnerability

        self.assertIn(Ai, ai.output_types)
        self.assertIn(Error, ai.output_types)
        self.assertIn(Info, ai.output_types)
        self.assertIn(Warning, ai.output_types)
        self.assertIn(Vulnerability, ai.output_types)

    def test_ai_task_tags(self):
        from secator.tasks.ai import ai

        self.assertIn('ai', ai.tags)
        self.assertIn('pentest', ai.tags)


class TestParseActions(unittest.TestCase):
    """Tests for the parse_actions function."""

    def test_parse_actions_code_block(self):
        from secator.tasks.ai import parse_actions

        response = '''Here is my analysis:
```json
[{"action": "task", "name": "nmap"}]
```
'''
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]['action'], 'task')
        self.assertEqual(actions[0]['name'], 'nmap')

    def test_parse_actions_raw_json(self):
        from secator.tasks.ai import parse_actions

        response = '''Let me scan the target.
[{"action": "shell", "command": "curl http://example.com"}]
'''
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]['action'], 'shell')

    def test_parse_actions_empty(self):
        from secator.tasks.ai import parse_actions

        response = "This response has no actions."
        actions = parse_actions(response)

        self.assertEqual(actions, [])

    def test_parse_actions_invalid_json(self):
        from secator.tasks.ai import parse_actions

        response = "```json\n[{invalid json}]\n```"
        actions = parse_actions(response)

        self.assertEqual(actions, [])


class TestStripJsonFromResponse(unittest.TestCase):
    """Tests for the strip_json_from_response function."""

    def test_strip_code_block(self):
        from secator.tasks.ai import strip_json_from_response

        text = '''Here is my reasoning.
```json
[{"action": "task"}]
```
And more text.'''
        result = strip_json_from_response(text)

        self.assertNotIn('```', result)
        self.assertNotIn('"action"', result)
        self.assertIn('reasoning', result)
        self.assertIn('more text', result)

    def test_strip_raw_json(self):
        from secator.tasks.ai import strip_json_from_response

        text = 'Some text [{"action": "done"}] more text'
        result = strip_json_from_response(text)

        self.assertNotIn('"action"', result)
        self.assertIn('Some text', result)
        self.assertIn('more text', result)

    def test_strip_empty(self):
        from secator.tasks.ai import strip_json_from_response

        self.assertEqual(strip_json_from_response(""), "")
        self.assertEqual(strip_json_from_response(None), "")


if __name__ == '__main__':
    unittest.main()

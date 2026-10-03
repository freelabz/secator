# tests/unit/test_ai_handlers.py
"""Tests for AI action handlers and context."""

import unittest
from dataclasses import fields

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestActionContext(unittest.TestCase):
    """Tests for the ActionContext dataclass."""

    def test_action_context_has_required_fields(self):
        from secator.ai.actions import ActionContext

        field_names = [f.name for f in fields(ActionContext)]

        self.assertIn('targets', field_names)
        self.assertIn('model', field_names)
        self.assertIn('encryptor', field_names)
        self.assertIn('dry_run', field_names)
        self.assertIn('context', field_names)
        self.assertIn('scope', field_names)
        self.assertIn('results', field_names)

    def test_action_context_defaults(self):
        from secator.ai.actions import ActionContext

        ctx = ActionContext(targets=['target.com'], model='gpt-4')

        self.assertEqual(ctx.targets, ['target.com'])
        self.assertEqual(ctx.model, 'gpt-4')
        self.assertIsNone(ctx.encryptor)
        self.assertFalse(ctx.dry_run)
        self.assertFalse(ctx.verbose)
        self.assertEqual(ctx.context, {})
        self.assertEqual(ctx.scope, 'workspace')
        self.assertIsNone(ctx.results)

    def test_action_context_with_all_params(self):
        from secator.ai.actions import ActionContext
        from secator.ai.encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        ctx = ActionContext(
            targets=['a.com', 'b.com'],
            model='claude-3',
            encryptor=encryptor,
            dry_run=True,
            verbose=True,
            context={'workspace_id': 'ws123'},
            scope='current',
            results=[{'_type': 'url', 'url': 'http://a.com'}],
        )

        self.assertEqual(ctx.targets, ['a.com', 'b.com'])
        self.assertEqual(ctx.model, 'claude-3')
        self.assertIsNotNone(ctx.encryptor)
        self.assertTrue(ctx.dry_run)
        self.assertTrue(ctx.verbose)
        self.assertEqual(ctx.context['workspace_id'], 'ws123')
        self.assertEqual(ctx.scope, 'current')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDispatchAction(unittest.TestCase):
    """Tests for the dispatch_action function."""

    def test_dispatch_unknown_action(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {'action': 'unknown_action_type'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('Unknown action', results[0].message)

    def test_dispatch_follow_up_action(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {'action': 'follow_up', 'reason': 'Test complete'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'ai')
        self.assertIn('Test complete', results[0].content)
        # Default follow-up is single-select.
        self.assertFalse(results[0].multiple)

    def test_dispatch_follow_up_multiple(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'follow_up',
            'reason': 'Pick targets',
            'choices': ['a', 'b', 'c'],
            'multiple': True,
        }
        results = list(dispatch_action(action, ctx))
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].multiple)
        self.assertEqual(results[0].choices, ['a', 'b', 'c'])
        self.assertTrue(results[0].extra_data.get('multiple'))

    def test_dispatch_task_dry_run(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'task', 'name': 'nmap', 'targets': ['192.168.1.1']}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('nmap', results[0].message)

    def test_dispatch_workflow_dry_run(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'workflow', 'name': 'host_recon', 'targets': ['example.com']}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('host_recon', results[0].message)

    def test_dispatch_shell_dry_run(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4', dry_run=True)
        action = {'action': 'shell', 'command': 'curl http://example.com'}

        results = list(dispatch_action(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('DRY RUN', results[0].message)
        self.assertIn('curl', results[0].message)

    def test_dispatch_query_basic(self):
        from secator.ai.actions import ActionContext, dispatch_action

        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {'action': 'query', 'query': {'_type': 'vulnerability'}, 'limit': 10}

        results = list(dispatch_action(action, ctx))

        # Should return results (may be empty or contain findings)
        self.assertIsInstance(results, list)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestAITask(unittest.TestCase):
    """Tests for the ai task class."""

    def test_ai_task_has_required_opts(self):
        from secator.tasks.ai import ai

        required_opts = ['prompt', 'mode', 'model', 'api_base', 'sensitive',
                         'max_iterations', 'temperature', 'dry_run']
        for opt in required_opts:
            self.assertIn(opt, ai.opts, f"Missing opt: {opt}")

    def test_ai_task_output_types(self):
        from secator.tasks.ai import ai
        from secator.output_types import Ai, Vulnerability

        # AI task uses FINDING_TYPES which includes Ai and Vulnerability
        self.assertIn(Ai, ai.output_types)
        self.assertIn(Vulnerability, ai.output_types)

    def test_ai_task_tags(self):
        from secator.tasks.ai import ai

        self.assertIn('ai', ai.tags)
        self.assertIn('pentest', ai.tags)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestChangeModeHandler(unittest.TestCase):
    """_handle_change_mode: model-driven mode switch, with the pinned-chat guard."""

    def _run(self, action, ctx):
        from secator.ai.actions import _handle_change_mode
        return list(_handle_change_mode(action, ctx))

    def _ctx(self, mode, mode_is_auto):
        from secator.ai.actions import ActionContext
        return ActionContext(targets=[], model='m', mode=mode, mode_is_auto=mode_is_auto)

    def test_auto_escalation_signals_mode_changed(self):
        from secator.output_types import Ai
        out = self._run({'action': 'change_mode', 'mode': 'attack'}, self._ctx('chat', True))
        self.assertEqual(len(out), 1)
        self.assertIsInstance(out[0], Ai)
        self.assertEqual(out[0].ai_type, 'mode_changed')
        self.assertEqual(out[0].content, 'attack')

    def test_pinned_chat_cannot_self_escape(self):
        from secator.output_types import Ai, Error
        out = self._run({'action': 'change_mode', 'mode': 'attack'}, self._ctx('chat', False))
        self.assertTrue(out and isinstance(out[0], Error))
        self.assertFalse(any(isinstance(o, Ai) and o.ai_type == 'mode_changed' for o in out))

    def test_pinned_action_mode_can_switch(self):
        from secator.output_types import Ai
        out = self._run({'action': 'change_mode', 'mode': 'exploit'}, self._ctx('attack', False))
        self.assertTrue(any(isinstance(o, Ai) and o.ai_type == 'mode_changed' and o.content == 'exploit'
                            for o in out))

    def test_invalid_target_rejected(self):
        from secator.output_types import Error
        for bad in ('chat', '', 'nonsense'):
            out = self._run({'action': 'change_mode', 'mode': bad}, self._ctx('chat', True))
            self.assertTrue(out and isinstance(out[0], Error), bad)

    def test_cannot_de_escalate(self):
        # change_mode only escalates: exploit -> attack (downgrade) and a no-op
        # same-mode switch are both rejected; escalation still works.
        from secator.output_types import Ai, Error
        out = self._run({'action': 'change_mode', 'mode': 'attack'}, self._ctx('exploit', True))
        self.assertTrue(out and isinstance(out[0], Error))
        self.assertFalse(any(isinstance(o, Ai) and o.ai_type == 'mode_changed' for o in out))
        same = self._run({'action': 'change_mode', 'mode': 'attack'}, self._ctx('attack', True))
        self.assertTrue(same and isinstance(same[0], Error))


if __name__ == '__main__':
    unittest.main()

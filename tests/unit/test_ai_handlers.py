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


class TestHandleOutputType(unittest.TestCase):

    def test_handle_output_type_unknown_type(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'invalid_type',
            'fields': {},
        }

        results = list(ai_instance._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('Unknown', results[0].message)

    def test_handle_output_type_vulnerability(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'vulnerability',
            'fields': {
                'name': 'SQL Injection',
                'severity': 'high',
                'matched_at': 'https://target.com/login',
            },
        }

        results = list(ai_instance._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'vulnerability')
        self.assertEqual(results[0].name, 'SQL Injection')
        self.assertEqual(results[0].severity, 'high')

    def test_handle_output_type_port(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'port',
            'fields': {
                'port': 443,
                'ip': '192.168.1.1',
                'service_name': 'https',
            },
        }

        results = list(ai_instance._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'port')
        self.assertEqual(results[0].port, 443)


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


class TestHandlePrompt(unittest.TestCase):

    def test_handle_prompt_ci_mode_auto_select(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'How to proceed?',
            'options': ['Option A', 'Option B'],
            'default': 'Option A',
        }

        results = list(ai_instance._handle_prompt(action, ctx))

        # Should yield AI prompt and Info about auto-selection
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]._type, 'ai')
        self.assertEqual(results[1]._type, 'info')
        self.assertIn('Auto-selecting', results[1].message)
        self.assertEqual(ctx.attack_context['user_response'], 'Option A')

    def test_handle_prompt_auto_yes_mode(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            auto_yes=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'How to proceed?',
            'options': ['First', 'Second'],
            'default': 'Second',
        }

        results = list(ai_instance._handle_prompt(action, ctx))

        self.assertEqual(ctx.attack_context['user_response'], 'Second')

    def test_handle_prompt_uses_first_option_when_no_default(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'Choose one',
            'options': ['Alpha', 'Beta'],
        }

        results = list(ai_instance._handle_prompt(action, ctx))

        # Should use first option as default
        self.assertEqual(ctx.attack_context['user_response'], 'Alpha')


class TestPromptIterations(unittest.TestCase):

    def test_prompt_iterations_option_exists(self):
        from secator.tasks.ai import ai

        self.assertIn('prompt_iterations', ai.opts)

    def test_prompt_iterations_default_is_none(self):
        from secator.tasks.ai import ai

        self.assertIsNone(ai.opts['prompt_iterations']['default'])


class TestPromptCheckpoint(unittest.TestCase):

    def test_prompt_checkpoint_returns_continue(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        # In CI mode, should auto-select and return "continue"
        results = list(ai_instance._prompt_checkpoint(5, 10, ctx))

        # Should yield AI prompt and Info
        self.assertEqual(len(results), 2)
        self.assertEqual(ctx.attack_context.get('_checkpoint_result'), 'continue')

    def test_prompt_checkpoint_stop_response(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={'user_response': 'Stop and summarize'},
        )

        # Simulate stop selection
        ctx.attack_context['user_response'] = 'Stop and summarize'
        result = ai_instance._parse_checkpoint_response(ctx)

        self.assertEqual(result, 'stop')


class TestPromptContinuation(unittest.TestCase):

    def test_prompt_continuation_ci_mode_returns_stop(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        results = list(ai_instance._prompt_continuation(ctx))

        # In CI mode, default is "Stop and generate report"
        self.assertEqual(len(results), 2)
        self.assertEqual(ctx.attack_context.get('_continuation_result'), 'stop')

    def test_prompt_continuation_continue_response(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={'user_response': 'Continue with more iterations'},
        )

        result = ai_instance._parse_continuation_response(ctx)

        self.assertEqual(result, 'continue')


class TestGetNewInstructions(unittest.TestCase):

    def test_get_new_instructions_ci_mode_returns_empty(self):
        from secator.tasks.ai import ai as AITask, ActionContext

        ai_instance = AITask.__new__(AITask)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        result = ai_instance._get_new_instructions(ctx)

        # In CI mode, can't get user input, return empty
        self.assertEqual(result, "")


if __name__ == '__main__':
    unittest.main()

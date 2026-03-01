# tests/unit/test_ai_intent.py
"""Tests for AI prompts module."""

import unittest


class TestSystemPrompt(unittest.TestCase):
    """Tests for the get_system_prompt function."""

    def test_get_system_prompt_attack(self):
        from secator.tasks.ai_prompts import get_system_prompt

        prompt = get_system_prompt("attack")

        # Should contain action definitions
        self.assertIn("task", prompt)
        self.assertIn("workflow", prompt)
        self.assertIn("shell", prompt)
        self.assertIn("done", prompt)

    def test_get_system_prompt_chat(self):
        from secator.tasks.ai_prompts import get_system_prompt

        prompt = get_system_prompt("chat")

        # Should be simpler for chat mode
        self.assertIn("query", prompt)
        self.assertIn("done", prompt)

    def test_get_system_prompt_unknown_defaults_to_chat(self):
        from secator.tasks.ai_prompts import get_system_prompt

        prompt = get_system_prompt("unknown_mode")

        # Should default to chat mode
        self.assertEqual(prompt, get_system_prompt("chat"))


class TestFormatUserInitial(unittest.TestCase):
    """Tests for the format_user_initial function."""

    def test_format_user_initial(self):
        import json
        from secator.tasks.ai_prompts import format_user_initial

        result = format_user_initial(['target.com'], 'scan for vulnerabilities')
        data = json.loads(result)

        self.assertEqual(data['targets'], ['target.com'])
        self.assertEqual(data['instructions'], 'scan for vulnerabilities')

    def test_format_user_initial_empty_instructions(self):
        import json
        from secator.tasks.ai_prompts import format_user_initial

        result = format_user_initial(['target.com'], '')
        data = json.loads(result)

        self.assertEqual(data['instructions'], 'Conduct security testing.')

    def test_format_user_initial_multiple_targets(self):
        import json
        from secator.tasks.ai_prompts import format_user_initial

        result = format_user_initial(['a.com', 'b.com', 'c.com'], 'test')
        data = json.loads(result)

        self.assertEqual(len(data['targets']), 3)


class TestFormatToolResult(unittest.TestCase):
    """Tests for the format_tool_result function."""

    def test_format_tool_result(self):
        import json
        from secator.tasks.ai_prompts import format_tool_result

        result = format_tool_result('nmap', 'success', 5, ['port1', 'port2'])
        data = json.loads(result)

        self.assertEqual(data['task'], 'nmap')
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['count'], 5)
        self.assertEqual(len(data['results']), 2)

    def test_format_tool_result_full_results(self):
        import json
        from secator.tasks.ai_prompts import format_tool_result

        result = format_tool_result('scan', 'success', 10, [1, 2, 3, 4, 5])
        data = json.loads(result)

        # Should include all results
        self.assertEqual(len(data['results']), 5)


class TestFormatContinue(unittest.TestCase):
    """Tests for the format_continue function."""

    def test_format_continue(self):
        import json
        from secator.tasks.ai_prompts import format_continue

        result = format_continue(3, 10)
        data = json.loads(result)

        self.assertEqual(data['iteration'], 3)
        self.assertEqual(data['max'], 10)
        self.assertEqual(data['instruction'], 'continue')


class TestChatHistory(unittest.TestCase):
    """Tests for the ChatHistory class."""

    def test_chat_history_add_messages(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_system("System prompt")
        history.add_user("User message")
        history.add_assistant("Assistant response")

        messages = history.to_messages()

        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0]['role'], 'system')
        self.assertEqual(messages[1]['role'], 'user')
        self.assertEqual(messages[2]['role'], 'assistant')

    def test_chat_history_to_messages_returns_copy(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user("Test")

        messages = history.to_messages()
        messages.append({'role': 'test', 'content': 'extra'})

        # Original should not be modified
        self.assertEqual(len(history.to_messages()), 1)

    def test_chat_history_clear(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user("Test")
        history.clear()

        self.assertEqual(len(history.to_messages()), 0)


if __name__ == '__main__':
    unittest.main()

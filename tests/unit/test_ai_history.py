# tests/unit/test_ai_history.py
import unittest
from unittest.mock import patch, MagicMock

from secator.ai.history import ChatHistory


class TestChatHistory(unittest.TestCase):

    def test_add_system(self):
        history = ChatHistory()
        history.add_system("You are an assistant.")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "You are an assistant.")

    def test_add_user_json(self):
        history = ChatHistory()
        history.add_user('{"targets":["example.com"]}')

        messages = history.to_messages()
        self.assertEqual(messages[0]["role"], "user")
        self.assertIn("targets", messages[0]["content"])

    def test_add_assistant(self):
        history = ChatHistory()
        history.add_assistant("Analysis here.\n\n```json\n[{\"action\":\"done\"}]\n```")

        messages = history.to_messages()
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertIn("Analysis", messages[0]["content"])

    def test_to_messages_returns_list(self):
        history = ChatHistory()
        history.add_system("sys")
        history.add_user("user")
        history.add_assistant("assistant")

        messages = history.to_messages()
        self.assertIsInstance(messages, list)
        self.assertEqual(len(messages), 3)

    def test_clear(self):
        history = ChatHistory()
        history.add_user("test")
        history.clear()

        self.assertEqual(len(history.to_messages()), 0)

    def test_to_messages_returns_copy(self):
        """Ensure to_messages returns a copy, not the original list."""
        history = ChatHistory()
        history.add_user("test")

        messages = history.to_messages()
        messages.append({"role": "user", "content": "extra"})

        # Original should be unchanged
        self.assertEqual(len(history.to_messages()), 1)


    def test_add_tool(self):
        history = ChatHistory()
        history.add_tool("tool output here")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "tool")
        self.assertEqual(messages[0]["content"], "tool output here")

    def test_est_tokens_empty(self):
        history = ChatHistory()
        self.assertEqual(history.est_tokens(), 0)

    def test_est_tokens(self):
        history = ChatHistory()
        # 40 chars -> ~10 tokens (40 // 4)
        history.add_user("a" * 40)
        self.assertEqual(history.est_tokens(), 10)

    def test_est_tokens_multiple_messages(self):
        history = ChatHistory()
        history.add_system("a" * 20)   # 5 tokens
        history.add_user("b" * 80)     # 20 tokens
        self.assertEqual(history.est_tokens(), 25)

    def test_maybe_summarize_below_threshold(self):
        history = ChatHistory()
        history.add_system("system prompt")
        history.add_user("short message")

        summarized, old_tokens, new_tokens = history.maybe_summarize(
            "test-model", threshold=30000)

        self.assertFalse(summarized)
        self.assertEqual(old_tokens, new_tokens)
        # Messages unchanged
        self.assertEqual(len(history.to_messages()), 2)

    @patch('secator.ai.utils.call_llm')
    def test_maybe_summarize_above_threshold(self, mock_call_llm):
        mock_call_llm.return_value = {"content": "Summary of session.", "usage": None}

        history = ChatHistory()
        history.add_system("system prompt")
        # Add enough content to exceed a low threshold
        for i in range(20):
            history.add_user("x" * 200)
            history.add_assistant("y" * 200)

        summarized, old_tokens, new_tokens = history.maybe_summarize(
            "test-model", threshold=100)

        self.assertTrue(summarized)
        self.assertGreater(old_tokens, 100)
        self.assertLess(new_tokens, old_tokens)
        mock_call_llm.assert_called_once()

    @patch('secator.ai.utils.call_llm')
    def test_summarize_preserves_system_prompt(self, mock_call_llm):
        mock_call_llm.return_value = {"content": "Compact summary.", "usage": None}

        history = ChatHistory()
        history.add_system("You are an AI pentester.")
        for i in range(10):
            history.add_user("x" * 200)
            history.add_assistant("y" * 200)

        history.maybe_summarize("test-model", threshold=100)

        messages = history.to_messages()
        # System prompt preserved as first message
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "You are an AI pentester.")
        # Summary is the second message
        self.assertEqual(messages[1]["role"], "user")
        self.assertIn("Summary", messages[1]["content"])

    def test_summarize_with_llm_few_messages(self):
        """Summarization skipped when <= 2 messages."""
        history = ChatHistory()
        history.add_system("system")
        history.add_user("user")

        original_messages = history.to_messages()
        history._summarize_with_llm("test-model", threshold=0)

        # Messages should be unchanged (skipped)
        self.assertEqual(history.to_messages(), original_messages)


if __name__ == '__main__':
    unittest.main()

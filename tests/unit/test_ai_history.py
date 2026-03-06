# tests/unit/test_ai_history.py
import unittest
from unittest.mock import patch

from secator.ai.history import ChatHistory


class TestChatHistory(unittest.TestCase):

    def test_add_system(self):
        history = ChatHistory()
        history.add_system("You are an assistant.")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "You are an assistant.")

    def test_set_system_replaces_existing(self):
        history = ChatHistory()
        history.add_system("old prompt")
        history.add_user("user msg")
        history.set_system("new prompt")

        messages = history.to_messages()
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "new prompt")

    def test_set_system_inserts_when_missing(self):
        history = ChatHistory()
        history.add_user("user msg")
        history.set_system("inserted prompt")

        messages = history.to_messages()
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "inserted prompt")
        self.assertEqual(messages[1]["role"], "user")

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
        # First user message preserved as second message
        self.assertEqual(messages[1]["role"], "user")
        self.assertEqual(messages[1]["content"], "x" * 200)
        # Summary is the third message
        self.assertEqual(messages[2]["role"], "user")
        self.assertIn("Summary", messages[2]["content"])

    def test_trim_drops_oldest_messages(self):
        """Trim drops messages to fit under token limit."""
        history = ChatHistory()
        history.add_system("s" * 40)
        history.add_user("u" * 40)
        for i in range(10):
            history.add_user(f"msg{i} " + "x" * 200)

        original_count = len(history.messages)
        trimmed = history.trim(max_tokens=100)

        # Some messages should have been dropped
        self.assertLess(len(trimmed), original_count)
        self.assertEqual(len(history.messages), len(trimmed))
        # System prompt preserved (litellm preserves system messages)
        self.assertEqual(history.messages[0]["role"], "system")
        self.assertEqual(history.messages[0]["content"], "s" * 40)

    def test_to_messages_with_max_tokens_total(self):
        """to_messages with max_tokens_total trims messages."""
        history = ChatHistory()
        history.add_system("s" * 40)
        history.add_user("u" * 40)
        for i in range(20):
            history.add_user("x" * 400)

        original_count = len(history.messages)
        self.assertEqual(original_count, 22)

        messages = history.to_messages(max_tokens_total=500)

        # Some messages should have been dropped
        self.assertLess(len(messages), original_count)
        # System prompt preserved (litellm preserves system messages)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "s" * 40)

    def test_to_messages_no_truncation_when_under_limit(self):
        """to_messages with max_tokens_total does nothing when under limit."""
        history = ChatHistory()
        history.add_system("short")
        history.add_user("msg")

        messages = history.to_messages(max_tokens_total=500)
        self.assertEqual(len(messages), 2)

    def test_to_messages_no_truncation_when_zero(self):
        """to_messages without max_tokens_total does not truncate."""
        history = ChatHistory()
        history.add_system("s" * 40)
        history.add_user("u" * 40)
        for i in range(20):
            history.add_user("x" * 400)

        messages = history.to_messages()
        # All messages returned (no truncation)
        self.assertEqual(len(messages), 22)

    def test_summarize_with_llm_few_messages(self):
        """Summarization skipped when <= 2 messages."""
        history = ChatHistory()
        history.add_system("system")
        history.add_user("user")

        original_messages = history.to_messages()
        history._summarize_with_llm("test-model", threshold=0)

        # Messages should be unchanged (skipped)
        self.assertEqual(history.to_messages(), original_messages)


    @patch('secator.ai.history.litellm')
    def test_count_tokens_uses_litellm(self, mock_litellm):
        """count_tokens uses litellm.token_counter for accurate counting."""
        mock_litellm.token_counter.return_value = 42

        history = ChatHistory()
        history.add_user("test message")

        tokens = history.count_tokens("gpt-4")

        mock_litellm.token_counter.assert_called_once()
        self.assertEqual(tokens, 42)

    @patch('secator.ai.history.litellm')
    def test_count_tokens_caches_result(self, mock_litellm):
        """count_tokens caches result and reuses on second call."""
        mock_litellm.token_counter.return_value = 100

        history = ChatHistory()
        history.add_user("test message")

        # First call - should hit litellm
        tokens1 = history.count_tokens("gpt-4")
        # Second call - should use cache
        tokens2 = history.count_tokens("gpt-4")

        # litellm called only once due to caching
        self.assertEqual(mock_litellm.token_counter.call_count, 1)
        self.assertEqual(tokens1, 100)
        self.assertEqual(tokens2, 100)

    @patch('secator.ai.history.litellm')
    def test_count_tokens_invalidates_cache_on_model_change(self, mock_litellm):
        """count_tokens recounts when model changes."""
        mock_litellm.token_counter.side_effect = [100, 120]

        history = ChatHistory()
        history.add_user("test message")

        tokens1 = history.count_tokens("gpt-4")
        tokens2 = history.count_tokens("claude-3")  # Different model

        self.assertEqual(mock_litellm.token_counter.call_count, 2)
        self.assertEqual(tokens1, 100)
        self.assertEqual(tokens2, 120)

    def test_count_tokens_requires_model(self):
        """count_tokens raises ValueError when no model provided."""
        history = ChatHistory()
        history.add_user("test")

        with self.assertRaises(ValueError) as ctx:
            history.count_tokens()
        self.assertIn("Model required", str(ctx.exception))

    @patch('secator.ai.history.litellm')
    def test_count_tokens_uses_instance_model(self, mock_litellm):
        """count_tokens uses self.model when no model argument provided."""
        mock_litellm.token_counter.return_value = 50

        history = ChatHistory()
        history.model = "gpt-4"
        history.add_user("test")

        tokens = history.count_tokens()  # No model argument

        mock_litellm.token_counter.assert_called_once()
        self.assertEqual(tokens, 50)

    @patch('secator.ai.history.litellm')
    def test_set_system_invalidates_token_cache(self, mock_litellm):
        """set_system invalidates cached token count for system message."""
        mock_litellm.token_counter.return_value = 50

        history = ChatHistory()
        history.add_system("old prompt")

        # Count tokens - this caches the count
        history.count_tokens("gpt-4")
        self.assertEqual(mock_litellm.token_counter.call_count, 1)

        # Change system prompt
        history.set_system("new longer prompt")

        # Count again - should recount since cache invalidated
        history.count_tokens("gpt-4")
        self.assertEqual(mock_litellm.token_counter.call_count, 2)


if __name__ == '__main__':
    unittest.main()

# tests/unit/test_ai_history.py
import tempfile
import unittest
from pathlib import Path
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

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_maybe_summarize_below_threshold(self, mock_litellm, mock_get_ctx):
        """maybe_summarize returns False when under percentage threshold."""
        mock_get_ctx.return_value = 100000
        mock_litellm.token_counter.return_value = 1000  # Well under 85%

        history = ChatHistory()
        history.add_system("system prompt")
        history.add_user("short message")

        summarized, old_tokens, new_tokens = history.maybe_summarize("test-model")

        self.assertFalse(summarized)
        self.assertEqual(old_tokens, new_tokens)
        # Messages unchanged
        self.assertEqual(len(history.to_messages()), 2)

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.utils.call_llm')
    @patch('secator.ai.history.litellm')
    def test_maybe_summarize_above_threshold(self, mock_litellm, mock_call_llm, mock_get_ctx):
        """maybe_summarize triggers compaction when over percentage threshold."""
        mock_get_ctx.return_value = 100000
        # Usable = 100000 - 8192 = 91808
        # 85% threshold = 78037 tokens
        # Return 2000 tokens per message (41 messages = 82000 total, over 85%)
        # After compaction, 3 messages = 6000 total
        mock_litellm.token_counter.return_value = 2000
        mock_call_llm.return_value = {"content": "Summary of session.", "usage": None}

        history = ChatHistory()
        history.add_system("system prompt")
        # Add enough content to exceed threshold
        for i in range(20):
            history.add_user("x" * 200)
            history.add_assistant("y" * 200)

        summarized, old_tokens, new_tokens = history.maybe_summarize("test-model")

        self.assertTrue(summarized)
        self.assertGreater(old_tokens, new_tokens)
        mock_call_llm.assert_called_once()

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.utils.call_llm')
    @patch('secator.ai.history.litellm')
    def test_summarize_preserves_system_prompt(self, mock_litellm, mock_call_llm, mock_get_ctx):
        """Summarization preserves system prompt and first user message."""
        mock_get_ctx.return_value = 100000
        # Return 4000 tokens per message (21 messages = 84000 total, over 85%)
        # After compaction, 3 messages = 12000 total
        mock_litellm.token_counter.return_value = 4000
        mock_call_llm.return_value = {"content": "Compact summary.", "usage": None}

        history = ChatHistory()
        history.add_system("You are an AI pentester.")
        for i in range(10):
            history.add_user("x" * 200)
            history.add_assistant("y" * 200)

        history.maybe_summarize("test-model")

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
        history._summarize_with_llm("test-model")

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

    @patch('secator.ai.history.litellm')
    def test_get_context_window_returns_model_limit(self, mock_litellm):
        """get_context_window returns model's max input tokens."""
        from secator.ai.history import get_context_window

        mock_litellm.get_model_info.return_value = {"max_input_tokens": 128000}

        result = get_context_window("gpt-4")

        mock_litellm.get_model_info.assert_called_once_with("gpt-4")
        self.assertEqual(result, 128000)

    @patch('secator.ai.history.litellm')
    def test_get_context_window_fallback_on_error(self, mock_litellm):
        """get_context_window returns default on error."""
        from secator.ai.history import get_context_window

        mock_litellm.get_model_info.side_effect = Exception("API error")

        result = get_context_window("unknown-model")

        self.assertEqual(result, 128000)  # Default fallback

    def test_constants_defined(self):
        """Verify constants are defined."""
        from secator.ai.history import OUTPUT_TOKEN_RESERVATION, COMPACTION_THRESHOLD_PCT

        self.assertEqual(OUTPUT_TOKEN_RESERVATION, 8192)
        self.assertEqual(COMPACTION_THRESHOLD_PCT, 85)

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_get_available_tokens(self, mock_litellm, mock_get_ctx):
        """get_available_tokens returns usable - used tokens."""
        mock_get_ctx.return_value = 128000
        mock_litellm.token_counter.return_value = 1000

        history = ChatHistory()
        history.add_user("test")

        available = history.get_available_tokens("gpt-4")

        # 128000 - 8192 (reservation) - 1000 (used) = 118808
        self.assertEqual(available, 118808)

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_should_compact_below_threshold(self, mock_litellm, mock_get_ctx):
        """should_compact returns False when under threshold."""
        mock_get_ctx.return_value = 100000
        mock_litellm.token_counter.return_value = 1000  # 1% used

        history = ChatHistory()
        history.add_user("test")

        self.assertFalse(history.should_compact("gpt-4"))

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_should_compact_above_threshold(self, mock_litellm, mock_get_ctx):
        """should_compact returns True when over threshold."""
        mock_get_ctx.return_value = 100000
        # Usable = 100000 - 8192 = 91808
        # 85% of 91808 = 78037
        mock_litellm.token_counter.return_value = 80000  # Over 85%

        history = ChatHistory()
        history.add_user("test")

        self.assertTrue(history.should_compact("gpt-4"))

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_get_action_budget_caps_at_max(self, mock_litellm, mock_get_ctx):
        """get_action_budget caps at MAX_ACTION_TOKENS when plenty available."""
        mock_get_ctx.return_value = 200000
        mock_litellm.token_counter.return_value = 1000  # Very little used

        history = ChatHistory()
        history.add_user("test")

        budget = history.get_action_budget("gpt-4")

        # Should cap at 10000 even though much more is available
        self.assertEqual(budget, 10000)

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_get_action_budget_uses_half_available(self, mock_litellm, mock_get_ctx):
        """get_action_budget uses 50% of available when constrained."""
        mock_get_ctx.return_value = 50000
        # Usable = 50000 - 8192 = 41808
        # Used = 35000
        # Available = 41808 - 35000 = 6808
        # Half = 3404
        mock_litellm.token_counter.return_value = 35000

        history = ChatHistory()
        history.add_user("test")

        budget = history.get_action_budget("gpt-4")

        # Should be 50% of available (3404), less than max (10000)
        self.assertEqual(budget, 3404)


    @patch('secator.ai.history.litellm')
    def test_truncate_to_tokens_no_truncation_needed(self, mock_litellm):
        """truncate_to_tokens returns content unchanged when under budget."""
        from secator.ai.history import truncate_to_tokens

        mock_litellm.token_counter.return_value = 100

        result = truncate_to_tokens("short content", 500, "gpt-4")

        self.assertEqual(result, "short content")

    @patch('secator.ai.history.litellm')
    def test_truncate_to_tokens_truncates_with_marker(self, mock_litellm):
        """truncate_to_tokens truncates and adds [TRUNCATED] marker."""
        from secator.ai.history import truncate_to_tokens

        mock_litellm.token_counter.return_value = 1000
        content = "x" * 4000  # Long content

        result = truncate_to_tokens(content, 100, "gpt-4")

        self.assertIn("[TRUNCATED]", result)
        self.assertLess(len(result), len(content))

    @patch('secator.ai.history.litellm')
    def test_truncate_to_tokens_with_fallback_path(self, mock_litellm):
        """truncate_to_tokens includes existing file path in hint."""
        from secator.ai.history import truncate_to_tokens

        mock_litellm.token_counter.return_value = 1000

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"test": true}')
            fallback_path = Path(f.name)

        try:
            result = truncate_to_tokens("x" * 4000, 100, "gpt-4", fallback_path=fallback_path)

            self.assertIn("[TRUNCATED]", result)
            self.assertIn(str(fallback_path), result)
            self.assertIn("grep", result)  # Shell command hint
        finally:
            fallback_path.unlink()

    @patch('secator.ai.history.litellm')
    def test_truncate_to_tokens_saves_shell_output(self, mock_litellm):
        """truncate_to_tokens saves shell output to .outputs directory."""
        from secator.ai.history import truncate_to_tokens

        mock_litellm.token_counter.return_value = 1000
        content = "shell output " * 500

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)

            result = truncate_to_tokens(
                content, 100, "gpt-4",
                output_dir=output_dir,
                result_name="shell"
            )

            self.assertIn("[TRUNCATED]", result)
            self.assertIn("saved to:", result)

            # Verify file was created
            saved_files = list(output_dir.glob("shell_*.txt"))
            self.assertEqual(len(saved_files), 1)
            self.assertEqual(saved_files[0].read_text(), content)


    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.utils.call_llm')
    @patch('secator.ai.history.litellm')
    def test_maybe_summarize_uses_percentage_threshold(self, mock_litellm, mock_call_llm, mock_get_ctx):
        """maybe_summarize uses percentage-based threshold, not fixed tokens."""
        mock_get_ctx.return_value = 100000
        # Usable = 100000 - 8192 = 91808
        # 85% threshold = 78037 tokens
        mock_litellm.token_counter.return_value = 80000  # Over 85%
        mock_call_llm.return_value = {"content": "Summary.", "usage": None}

        history = ChatHistory()
        history.add_system("system")
        history.add_user("user1")
        history.add_assistant("response1")

        summarized, old_tokens, new_tokens = history.maybe_summarize("gpt-4")

        self.assertTrue(summarized)
        mock_call_llm.assert_called_once()

    @patch('secator.ai.history.get_context_window')
    @patch('secator.ai.history.litellm')
    def test_maybe_summarize_no_threshold_param(self, mock_litellm, mock_get_ctx):
        """maybe_summarize no longer accepts threshold parameter."""
        mock_get_ctx.return_value = 100000
        mock_litellm.token_counter.return_value = 1000

        history = ChatHistory()
        history.add_system("system")

        # Should work without threshold param
        summarized, _, _ = history.maybe_summarize("gpt-4")

        self.assertFalse(summarized)


if __name__ == '__main__':
    unittest.main()

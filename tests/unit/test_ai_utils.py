# tests/unit/test_ai_utils.py
"""Tests for AI utility functions - LLM init, calling, and parsing helpers."""

import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestInitLLM(unittest.TestCase):
    """Tests for the init_llm singleton function."""

    def setUp(self):
        import secator.ai.utils as utils_mod
        self._original = utils_mod._llm_initialized
        utils_mod._llm_initialized = False

    def tearDown(self):
        import secator.ai.utils as utils_mod
        utils_mod._llm_initialized = self._original

    def test_init_llm_sets_api_key(self):
        import litellm
        from secator.ai.utils import init_llm

        old_key = getattr(litellm, 'api_key', None)
        try:
            init_llm(api_key="test-key-123")
            self.assertEqual(litellm.api_key, "test-key-123")
        finally:
            litellm.api_key = old_key

    def test_init_llm_singleton(self):
        """Second call should not re-register callbacks."""
        import litellm
        import secator.ai.utils as utils_mod
        from secator.ai.utils import init_llm

        old_key = getattr(litellm, 'api_key', None)
        old_callbacks = litellm.callbacks[:]
        try:
            init_llm(api_key="key1")
            self.assertTrue(utils_mod._llm_initialized)
            cb_count = len(litellm.callbacks)

            # Second call should set api_key but not add more callbacks
            init_llm(api_key="key2")
            self.assertEqual(litellm.api_key, "key2")
            self.assertEqual(len(litellm.callbacks), cb_count)
        finally:
            litellm.api_key = old_key
            litellm.callbacks = old_callbacks


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestCallLLM(unittest.TestCase):
    """Tests for the call_llm function."""

    @patch('litellm.completion')
    @patch('litellm.completion_cost')
    def test_call_llm_basic(self, mock_cost, mock_completion):
        """Basic LLM call returns content and usage."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Test response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage.total_tokens = 150
        mock_completion.return_value = mock_response
        mock_cost.return_value = 0.003

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model",
            temperature=0.5
        )

        self.assertEqual(result["content"], "Test response")
        self.assertEqual(result["usage"]["tokens"], 150)
        self.assertEqual(result["usage"]["cost"], 0.003)
        self.assertEqual(result["tool_calls"], [])
        mock_completion.assert_called_once()

    @patch('litellm.token_counter')
    @patch('litellm.completion')
    def test_call_llm_no_usage_estimates_tokens(self, mock_completion, mock_token_counter):
        """M5: response without usage still yields a non-zero estimated token count."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage = None
        mock_completion.return_value = mock_response
        # prompt (messages=...) then completion (text=...)
        mock_token_counter.side_effect = [42, 8]

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model"
        )

        self.assertEqual(result["content"], "Response")
        self.assertIsNotNone(result["usage"])
        self.assertEqual(result["usage"]["tokens"], 50)
        self.assertEqual(result["usage"]["prompt_tokens"], 42)
        self.assertEqual(result["usage"]["completion_tokens"], 8)
        self.assertIsNone(result["usage"]["cost"])
        self.assertEqual(result["tool_calls"], [])

    @patch('litellm.completion')
    @patch('litellm.completion_cost')
    def test_call_llm_cost_error(self, mock_cost, mock_completion):
        """Cost calculation error results in None cost."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage.total_tokens = 100
        mock_completion.return_value = mock_response
        mock_cost.side_effect = Exception("Unknown model")

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model"
        )

        self.assertEqual(result["usage"]["tokens"], 100)
        self.assertIsNone(result["usage"]["cost"])

    @patch('litellm.completion')
    def test_call_llm_passes_api_base(self, mock_completion):
        """API base URL is passed to litellm."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "ok"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage = None
        mock_completion.return_value = mock_response

        from secator.ai.utils import call_llm
        call_llm(
            [{"role": "user", "content": "hi"}],
            "test-model",
            api_base="http://localhost:8000"
        )

        mock_completion.assert_called_once_with(
            model="test-model",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.7,
            api_base="http://localhost:8000",
        )

    @patch('litellm.completion')
    @patch('litellm.completion_cost')
    def test_call_llm_with_tools_returns_tool_calls(self, mock_cost, mock_completion):
        """Tools are passed to litellm.completion and tool_calls are parsed from response."""
        # Build mock tool_call
        mock_tc = MagicMock()
        mock_tc.id = "call_abc123"
        mock_tc.function.name = "run_scan"
        mock_tc.function.arguments = '{"target": "example.com", "ports": "80,443"}'

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None
        mock_response.choices[0].message.tool_calls = [mock_tc]
        mock_response.usage.total_tokens = 50
        mock_completion.return_value = mock_response
        mock_cost.return_value = 0.001

        tools = [{"type": "function", "function": {"name": "run_scan", "parameters": {}}}]

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "scan example.com"}],
            "test-model",
            tools=tools,
        )

        # Verify tools were passed to litellm.completion
        call_kwargs = mock_completion.call_args[1]
        self.assertEqual(call_kwargs["tools"], tools)

        # Verify content is empty string when None
        self.assertEqual(result["content"], "")

        # Verify tool_calls returned from response
        self.assertEqual(len(result["tool_calls"]), 1)
        tc = result["tool_calls"][0]
        self.assertEqual(tc.id, "call_abc123")
        self.assertEqual(tc.function.name, "run_scan")
        self.assertEqual(tc.function.arguments, '{"target": "example.com", "ports": "80,443"}')

    @patch('litellm.completion')
    def test_call_llm_without_tools_returns_empty_tool_calls(self, mock_completion):
        """Response with no tool_calls returns empty list."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Just a text response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage = None
        mock_completion.return_value = mock_response

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model",
        )

        self.assertEqual(result["tool_calls"], [])
        self.assertEqual(result["content"], "Just a text response")

    @patch('litellm.completion')
    def test_call_llm_tool_call_with_malformed_json(self, mock_completion):
        """Tool call with invalid JSON arguments falls back to empty dict."""
        mock_tc = MagicMock()
        mock_tc.id = "call_bad"
        mock_tc.function.name = "broken_tool"
        mock_tc.function.arguments = "{not valid json"

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = ""
        mock_response.choices[0].message.tool_calls = [mock_tc]
        mock_response.usage = None
        mock_completion.return_value = mock_response

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "test"}],
            "test-model",
        )

        self.assertEqual(len(result["tool_calls"]), 1)
        tc = result["tool_calls"][0]
        self.assertEqual(tc.id, "call_bad")
        self.assertEqual(tc.function.name, "broken_tool")
        self.assertEqual(tc.function.arguments, "{not valid json")

    @patch('time.sleep')
    @patch('litellm.completion')
    def test_call_llm_non_orphan_400_fails_fast(self, mock_completion, mock_sleep):
        """M4: a plain (non-orphan) 400 is raised immediately, NOT retried 3x."""
        import litellm
        from secator.ai.utils import call_llm

        err = litellm.BadRequestError(
            message="litellm.BadRequestError: context_length_exceeded",
            model="test-model", llm_provider="anthropic",
        )
        mock_completion.side_effect = err

        with self.assertRaises(litellm.BadRequestError):
            call_llm([{"role": "user", "content": "hi"}], "test-model", max_retries=3)

        self.assertEqual(mock_completion.call_count, 1)  # no 3x spin
        mock_sleep.assert_not_called()

    @patch('time.sleep')
    @patch('litellm.completion')
    def test_call_llm_orphan_400_repairs_and_retries(self, mock_completion, mock_sleep):
        """M4: the orphan tool_use 400 still triggers repair-and-retry (no fail-fast)."""
        import litellm
        from secator.ai.utils import call_llm

        ok_response = MagicMock()
        ok_response.choices = [MagicMock(message=MagicMock(content="ok", tool_calls=None))]
        ok_response.usage = None

        err = litellm.BadRequestError(
            message="AnthropicException - tool_use ids were found without tool_result blocks",
            model="claude", llm_provider="anthropic",
        )

        calls = []

        def side_effect(**kwargs):
            if not calls:  # first call: inject orphan, then raise the orphan 400
                kwargs["messages"].insert(0, {
                    "role": "assistant", "content": None,
                    "tool_calls": [{"id": "toolu_late", "type": "function",
                                    "function": {"name": "f", "arguments": "{}"}}],
                })
                calls.append(1)
                raise err
            return ok_response

        mock_completion.side_effect = side_effect
        result = call_llm([{"role": "user", "content": "hi"}], "claude", max_retries=3)

        self.assertEqual(result["content"], "ok")
        self.assertEqual(mock_completion.call_count, 2)  # repaired then succeeded
        mock_sleep.assert_not_called()  # repair skips the backoff

    @patch('time.sleep')
    @patch('litellm.completion')
    def test_call_llm_duplicate_tool_result_400_repairs_and_retries(self, mock_completion, mock_sleep):
        """A 'multiple tool_result blocks with id' 400 is now deduped and retried,
        instead of failing fast as non-retryable."""
        import litellm
        from secator.ai.utils import call_llm

        ok_response = MagicMock()
        ok_response.choices = [MagicMock(message=MagicMock(content="ok", tool_calls=None))]
        ok_response.usage = None

        err = litellm.BadRequestError(
            message=("messages.24.content.3: each tool_use must have a single result. "
                     "Found multiple tool_result blocks with id: toolu_dup"),
            model="claude", llm_provider="anthropic",
        )
        calls = []

        def side_effect(**kwargs):
            if not calls:  # first call: inject an assistant + duplicate tool_results, then raise
                kwargs["messages"][:0] = [
                    {"role": "assistant", "content": None,
                     "tool_calls": [{"id": "toolu_dup", "type": "function",
                                     "function": {"name": "f", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "toolu_dup", "name": "f", "content": "r1"},
                    {"role": "tool", "tool_call_id": "toolu_dup", "name": "f", "content": "r2"},
                ]
                calls.append(1)
                raise err
            return ok_response

        mock_completion.side_effect = side_effect
        result = call_llm([{"role": "user", "content": "hi"}], "claude", max_retries=3)

        self.assertEqual(result["content"], "ok")
        self.assertEqual(mock_completion.call_count, 2)  # deduped then succeeded
        mock_sleep.assert_not_called()

    @patch('time.sleep')
    @patch('litellm.completion')
    @patch('litellm.completion_cost')
    def test_call_llm_transient_error_still_retries(self, mock_cost, mock_completion, mock_sleep):
        """M4: genuinely-transient errors (429/500) still retry then succeed."""
        import litellm
        from secator.ai.utils import call_llm

        ok_response = MagicMock()
        ok_response.choices = [MagicMock()]
        ok_response.choices[0].message.content = "ok"
        ok_response.choices[0].message.tool_calls = None
        ok_response.usage.total_tokens = 10
        mock_cost.return_value = 0.0

        err = litellm.RateLimitError(
            message="rate limited", model="test-model", llm_provider="anthropic",
        )
        mock_completion.side_effect = [err, ok_response]

        result = call_llm([{"role": "user", "content": "hi"}], "test-model", max_retries=3)

        self.assertEqual(result["content"], "ok")
        self.assertEqual(mock_completion.call_count, 2)  # transient retry honored
        mock_sleep.assert_called_once()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestPromptUserAllChoices(unittest.TestCase):
    """Tests for the 'All of the above' option in prompt_user."""

    @patch('secator.rich.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_not_shown_with_single_choice(self, mock_menu_class):
        """All of the above should not appear with only 1 choice."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")  # Select first option
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Single choice"])

        # Check options passed to InteractiveMenu
        call_args = mock_menu_class.call_args
        options = call_args[0][1]  # Second positional arg is options list
        labels = [opt["label"] for opt in options]

        self.assertNotIn("All of the above", labels)

    @patch('secator.rich.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_shown_with_multiple_choices(self, mock_menu_class):
        """All of the above should appear with 2+ choices."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Choice A", "Choice B"])

        call_args = mock_menu_class.call_args
        options = call_args[0][1]
        labels = [opt["label"] for opt in options]

        self.assertIn("All of the above", labels)

    @patch('secator.rich.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_position_after_llm_choices(self, mock_menu_class):
        """All of the above should appear after LLM choices, before defaults."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Choice A", "Choice B", "Choice C"])

        call_args = mock_menu_class.call_args
        options = call_args[0][1]
        labels = [opt["label"] for opt in options]

        # Expected order: Choice A, Choice B, Choice C, All of the above, Continue, Summarize, Exit
        all_idx = labels.index("All of the above")
        self.assertEqual(all_idx, 3)  # After 3 LLM choices

    @patch('secator.rich.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_formats_message_correctly(self, mock_menu_class):
        """Selecting All of the above should format all choices into numbered list."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        choices = ["Scan for ports", "Enumerate subdomains"]

        mock_menu = MagicMock()
        # Simulate selecting "All of the above" (index 2 with 2 choices)
        mock_menu.show.return_value = (2, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        result = prompt_user(history, choices=choices, max_iterations=10)

        expected = "Do all of the following: 1) Scan for ports, 2) Enumerate subdomains"
        self.assertEqual(result["answer"], expected)

    @patch('secator.rich.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_with_extra_instructions(self, mock_menu_class):
        """Extra user input should be appended to the message."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        choices = ["Choice A", "Choice B"]

        mock_menu = MagicMock()
        mock_menu.show.return_value = (2, "focus on main domain")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        result = prompt_user(history, choices=choices)

        expected = "Do all of the following: 1) Choice A, 2) Choice B. Additional instructions: focus on main domain"
        self.assertEqual(result["answer"], expected)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRepairOrphanToolUses(unittest.TestCase):
    """Tests for _repair_orphan_tool_uses — safety net for Anthropic API."""

    def _assistant_with_tool_calls(self, *ids):
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": tc_id, "type": "function", "function": {"name": "follow_up", "arguments": "{}"}}
                for tc_id in ids
            ],
        }

    def test_no_op_when_all_tool_results_present(self):
        from secator.ai.utils import _repair_orphan_tool_uses
        messages = [
            self._assistant_with_tool_calls("toolu_1"),
            {"role": "tool", "tool_call_id": "toolu_1", "name": "follow_up", "content": "ok"},
            {"role": "user", "content": "next"},
        ]
        before = [dict(m) for m in messages]
        inserted = _repair_orphan_tool_uses(messages)
        self.assertEqual(inserted, 0)
        self.assertEqual(messages, before)

    def test_inserts_synthetic_result_for_orphan(self):
        from secator.ai.utils import _repair_orphan_tool_uses
        messages = [
            self._assistant_with_tool_calls("toolu_orphan"),
            {"role": "user", "content": "Continue to chat"},
        ]
        inserted = _repair_orphan_tool_uses(messages)
        self.assertEqual(inserted, 1)
        self.assertEqual(messages[1]["role"], "tool")
        self.assertEqual(messages[1]["tool_call_id"], "toolu_orphan")
        self.assertEqual(messages[2]["content"], "Continue to chat")

    def test_inserts_only_missing_when_partial(self):
        from secator.ai.utils import _repair_orphan_tool_uses
        messages = [
            self._assistant_with_tool_calls("toolu_a", "toolu_b"),
            {"role": "tool", "tool_call_id": "toolu_a", "name": "follow_up", "content": "ok"},
            {"role": "user", "content": "next"},
        ]
        inserted = _repair_orphan_tool_uses(messages)
        self.assertEqual(inserted, 1)
        tool_ids = [m.get("tool_call_id") for m in messages if m.get("role") == "tool"]
        self.assertIn("toolu_a", tool_ids)
        self.assertIn("toolu_b", tool_ids)

    def test_idempotent(self):
        from secator.ai.utils import _repair_orphan_tool_uses
        messages = [
            self._assistant_with_tool_calls("toolu_orphan"),
            {"role": "user", "content": "Continue"},
        ]
        _repair_orphan_tool_uses(messages)
        count_after_first = len(messages)
        second = _repair_orphan_tool_uses(messages)
        self.assertEqual(second, 0)
        self.assertEqual(len(messages), count_after_first)

    def test_call_llm_preemptively_repairs_orphan_tool_use(self):
        """call_llm should repair orphan tool_use blocks before the first API call."""
        from secator.ai.utils import call_llm

        ok_response = MagicMock()
        ok_response.choices = [MagicMock(message=MagicMock(content="ok", tool_calls=None))]
        ok_response.usage = None

        messages = [
            self._assistant_with_tool_calls("toolu_orphan"),
            {"role": "user", "content": "Continue"},
        ]

        with patch('litellm.completion', return_value=ok_response) as mock_completion:
            result = call_llm(messages, "claude")

        self.assertEqual(result["content"], "ok")
        self.assertEqual(mock_completion.call_count, 1)
        sent_messages = mock_completion.call_args.kwargs["messages"]
        tool_msgs = [m for m in sent_messages if m.get("role") == "tool"]
        self.assertEqual(len(tool_msgs), 1)
        self.assertEqual(tool_msgs[0]["tool_call_id"], "toolu_orphan")

    def test_call_llm_retries_with_repair_on_error(self):
        """If Anthropic rejects with orphan tool_use error, call_llm repairs and retries without sleep."""
        import litellm
        from secator.ai.utils import call_llm

        ok_response = MagicMock()
        ok_response.choices = [MagicMock(message=MagicMock(content="ok", tool_calls=None))]
        ok_response.usage = None

        err = litellm.BadRequestError(
            message="AnthropicException - tool_use ids were found without tool_result blocks",
            model="claude", llm_provider="anthropic",
        )

        # Messages start clean (so pre-emptive repair is a no-op), but we mutate
        # them between calls so the retry-branch repair has work to do.
        messages = [{"role": "user", "content": "hi"}]
        sleep_calls = []

        def completion_side_effect(**kwargs):
            if not sleep_calls:  # first call: inject orphan, then raise
                kwargs["messages"].insert(0, self._assistant_with_tool_calls("toolu_late"))
                sleep_calls.append(1)
                raise err
            return ok_response

        with patch('litellm.completion', side_effect=completion_side_effect), \
                patch('time.sleep') as mock_sleep:
            result = call_llm(messages, "claude", max_retries=3)

        self.assertEqual(result["content"], "ok")
        mock_sleep.assert_not_called()  # repair branch should skip the backoff sleep


class TestDedupeToolResults(unittest.TestCase):
    """Providers reject >1 tool_result per tool_use id ('multiple tool_result blocks
    with id X') — a non-retryable 400. Duplicates arise from batch results grouped
    out of order or history trim/compaction; drop the extras, keep the first."""

    def test_drops_consecutive_duplicate_same_id(self):
        from secator.ai.utils import _dedupe_tool_results
        messages = [
            {"role": "assistant", "content": None,
             "tool_calls": [{"id": "x", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "x", "name": "f", "content": "first"},
            {"role": "tool", "tool_call_id": "y", "name": "f", "content": "other"},
            {"role": "tool", "tool_call_id": "x", "name": "f", "content": "DUP"},
            {"role": "user", "content": "next"},
        ]
        removed = _dedupe_tool_results(messages)
        self.assertEqual(removed, 1)
        tool_ids = [m["tool_call_id"] for m in messages if m.get("role") == "tool"]
        self.assertEqual(tool_ids, ["x", "y"])  # first x kept, dup dropped, y intact
        # the kept x is the FIRST result
        self.assertEqual(next(m for m in messages if m.get("tool_call_id") == "x")["content"], "first")

    def test_no_op_when_unique(self):
        from secator.ai.utils import _dedupe_tool_results
        messages = [
            {"role": "tool", "tool_call_id": "a", "content": "1"},
            {"role": "tool", "tool_call_id": "b", "content": "2"},
        ]
        before = [dict(m) for m in messages]
        self.assertEqual(_dedupe_tool_results(messages), 0)
        self.assertEqual(messages, before)

    def test_dedupe_scoped_per_consecutive_run(self):
        """The same id in two SEPARATE tool runs (own assistant each) is not a dup."""
        from secator.ai.utils import _dedupe_tool_results
        messages = [
            {"role": "tool", "tool_call_id": "x", "content": "r1"},
            {"role": "assistant", "content": "thinking"},
            {"role": "tool", "tool_call_id": "x", "content": "r2"},
        ]
        self.assertEqual(_dedupe_tool_results(messages), 0)  # separated by a non-tool msg

    def test_repair_dedupes_duplicate_tool_results(self):
        """_repair_orphan_tool_uses now removes duplicates as part of its pass."""
        from secator.ai.utils import _repair_orphan_tool_uses
        messages = [
            {"role": "assistant", "content": None,
             "tool_calls": [{"id": "x", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "x", "name": "f", "content": "first"},
            {"role": "tool", "tool_call_id": "x", "name": "f", "content": "DUP"},
            {"role": "user", "content": "next"},
        ]
        changed = _repair_orphan_tool_uses(messages)
        self.assertGreaterEqual(changed, 1)
        tool_ids = [m["tool_call_id"] for m in messages if m.get("role") == "tool"]
        self.assertEqual(tool_ids, ["x"])  # exactly one result for x


if __name__ == '__main__':
    unittest.main()

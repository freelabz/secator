# tests/unit/test_ai_utils.py
"""Tests for AI utility functions - LLM init, calling, and parsing helpers."""

import unittest
from unittest.mock import patch, MagicMock


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

    @patch('litellm.completion')
    def test_call_llm_no_usage(self, mock_completion):
        """Response without usage data."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.usage = None
        mock_completion.return_value = mock_response

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model"
        )

        self.assertEqual(result["content"], "Response")
        self.assertIsNone(result["usage"])
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

        # Verify tool_calls parsed correctly
        self.assertEqual(len(result["tool_calls"]), 1)
        tc = result["tool_calls"][0]
        self.assertEqual(tc["id"], "call_abc123")
        self.assertEqual(tc["name"], "run_scan")
        self.assertEqual(tc["arguments"], {"target": "example.com", "ports": "80,443"})

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
        self.assertEqual(tc["id"], "call_bad")
        self.assertEqual(tc["name"], "broken_tool")
        self.assertEqual(tc["arguments"], {})


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

        # Check the message added to history
        last_msg = history.messages[-1]
        expected = "Do all of the following: 1) Scan for ports, 2) Enumerate subdomains"
        self.assertEqual(last_msg["content"], expected)
        self.assertEqual(result[0], expected)

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

        last_msg = history.messages[-1]
        expected = "Do all of the following: 1) Choice A, 2) Choice B. Additional instructions: focus on main domain"
        self.assertEqual(last_msg["content"], expected)
        self.assertEqual(result[0], expected)


if __name__ == '__main__':
    unittest.main()

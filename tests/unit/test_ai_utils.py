# tests/unit/test_ai_utils.py
"""Tests for AI utility functions - LLM init, calling, and parsing helpers."""

import unittest
from unittest.mock import patch, MagicMock

from secator.ai.utils import _find_matching_bracket, parse_actions


class TestFindMatchingBracket(unittest.TestCase):
    """Tests for the _find_matching_bracket helper."""

    def test_simple_brackets(self):
        text = "[abc]"
        self.assertEqual(_find_matching_bracket(text, 0, '[', ']'), 5)

    def test_nested_brackets(self):
        text = "[[inner]]"
        self.assertEqual(_find_matching_bracket(text, 0, '[', ']'), 9)

    def test_curly_braces(self):
        text = '{"key": {"nested": true}}'
        self.assertEqual(_find_matching_bracket(text, 0, '{', '}'), 25)

    def test_no_match(self):
        text = "[unclosed"
        self.assertEqual(_find_matching_bracket(text, 0, '[', ']'), 0)

    def test_offset_start(self):
        text = 'prefix [content]'
        self.assertEqual(_find_matching_bracket(text, 7, '[', ']'), 16)

    def test_deeply_nested(self):
        text = '[[[x]]]'
        self.assertEqual(_find_matching_bracket(text, 0, '[', ']'), 7)


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
        mock_completion.assert_called_once()

    @patch('litellm.completion')
    def test_call_llm_no_usage(self, mock_completion):
        """Response without usage data."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage = None
        mock_completion.return_value = mock_response

        from secator.ai.utils import call_llm
        result = call_llm(
            [{"role": "user", "content": "hello"}],
            "test-model"
        )

        self.assertEqual(result["content"], "Response")
        self.assertIsNone(result["usage"])

    @patch('litellm.completion')
    @patch('litellm.completion_cost')
    def test_call_llm_cost_error(self, mock_cost, mock_completion):
        """Cost calculation error results in None cost."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
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


class TestParseActions(unittest.TestCase):
    """Tests for parse_actions - all LLM response formats."""

    def test_json_array_in_code_block(self):
        """Standard format: ```json [...] ```"""
        response = 'Some reasoning.\n\n```json\n[{"action":"task","name":"nmap","targets":["example.com"]}]\n```'
        actions = parse_actions(response)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "task")
        self.assertEqual(actions[0]["name"], "nmap")

    def test_code_block_multiple_actions(self):
        response = '```json\n[{"action":"shell","command":"echo hi"},{"action":"done","reason":"ok"}]\n```'
        actions = parse_actions(response)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["action"], "shell")
        self.assertEqual(actions[1]["action"], "done")

    def test_raw_json_array(self):
        """JSON array without code block."""
        response = 'Reasoning text.\n\n[{"action":"task","name":"httpx","targets":["example.com"],"opts":{}}]'
        actions = parse_actions(response)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["name"], "httpx")

    def test_raw_json_array_multiline(self):
        response = ('Reasoning.\n\n[{"action":"task","name":"nmap","targets":["example.com"]},\n'
                     '{"action":"done","reason":"finished"}]')
        actions = parse_actions(response)
        self.assertEqual(len(actions), 2)

    def test_individual_json_objects_bullet_list(self):
        """LLM outputs individual JSON objects as bullet points (not wrapped in array)."""
        response = (
            '1. Install wafw00f\n2. Conduct scans\n\nActions\n\n'
            '• task: {"action":"task","name":"wafw00f","targets":["vulnweb.com"],"opts":{}}\n'
            '• task: {"action":"task","name":"nmap","targets":["vulnweb.com"],"opts":{"ports":"1-1000"}}\n'
            '• done: {"action":"done","reason":"Continuing."}\n'
        )
        actions = parse_actions(response)
        self.assertEqual(len(actions), 3)
        self.assertEqual(actions[0]["name"], "wafw00f")
        self.assertEqual(actions[1]["name"], "nmap")
        self.assertEqual(actions[2]["action"], "done")

    def test_individual_json_objects_newline_separated(self):
        """JSON objects on separate lines without any prefix."""
        response = (
            'Analysis complete.\n\n'
            '{"action":"shell","command":"curl -s http://example.com"}\n'
            '{"action":"done","reason":"done"}\n'
        )
        actions = parse_actions(response)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["action"], "shell")
        self.assertEqual(actions[1]["action"], "done")

    def test_single_json_object(self):
        """Only one action, not in an array."""
        response = 'Quick check.\n\n{"action":"done","reason":"nothing to do"}'
        actions = parse_actions(response)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["reason"], "nothing to do")

    def test_nested_targets_not_confused_for_action_array(self):
        """Targets array like ["vulnweb.com"] should not be returned as actions."""
        response = (
            'Running scan.\n\n'
            '• {"action":"task","name":"nmap","targets":["vulnweb.com"],"opts":{}}\n'
        )
        actions = parse_actions(response)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], dict)
        self.assertEqual(actions[0]["action"], "task")

    def test_code_block_with_non_action_array(self):
        """Code block containing a non-action array should not match."""
        response = '```json\n["vulnweb.com", "example.com"]\n```'
        actions = parse_actions(response)
        self.assertEqual(actions, [])

    def test_no_actions_in_response(self):
        """Plain text response with no JSON."""
        response = 'I will analyze the target and provide recommendations.'
        actions = parse_actions(response)
        self.assertEqual(actions, [])

    def test_empty_response(self):
        actions = parse_actions('')
        self.assertEqual(actions, [])

    def test_actions_with_nested_opts(self):
        """Actions with complex nested opts."""
        response = '[{"action":"task","name":"nuclei","targets":["example.com"],"opts":{"template_id":"cves","severity":"critical,high"}}]'
        actions = parse_actions(response)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["opts"]["severity"], "critical,high")

    def test_mixed_text_and_code_block(self):
        """Realistic LLM output: reasoning + code block."""
        response = (
            '## Port Scanning\n\n'
            'Found web services. Running vulnerability scan.\n\n'
            '```json\n'
            '[{"action":"task","name":"nuclei","targets":["example.com"],"opts":{"template_id":"cves"}},'
            '{"action":"query","query":{"_type":"vulnerability"},"limit":10}]\n'
            '```\n'
        )
        actions = parse_actions(response)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["action"], "task")
        self.assertEqual(actions[1]["action"], "query")

    def test_invalid_json_returns_empty(self):
        """Malformed JSON should not crash."""
        response = '```json\n[{"action":"task", broken json}]\n```'
        actions = parse_actions(response)
        self.assertEqual(actions, [])

    def test_markdown_numbered_json_objects(self):
        """LLM outputs numbered JSON objects in markdown."""
        response = (
            'Plan:\n\n'
            '1. {"action":"shell","command":"whoami"}\n'
            '2. {"action":"task","name":"httpx","targets":["example.com"],"opts":{}}\n'
            '3. {"action":"done","reason":"recon complete"}\n'
        )
        actions = parse_actions(response)
        self.assertEqual(len(actions), 3)
        self.assertEqual(actions[0]["command"], "whoami")
        self.assertEqual(actions[1]["name"], "httpx")
        self.assertEqual(actions[2]["reason"], "recon complete")


if __name__ == '__main__':
    unittest.main()

"""Tests for AI task subagent opts."""
import unittest
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestAiTaskOpts(unittest.TestCase):
    """Tests for context, subagent, and max_workers opts."""

    def test_context_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("context", ai.opts)
        self.assertTrue(ai.opts["context"].get("internal", False))

    def test_subagent_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("subagent", ai.opts)
        self.assertTrue(ai.opts["subagent"].get("is_flag", False))
        self.assertTrue(ai.opts["subagent"].get("internal", False))

    def test_max_workers_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("max_workers", ai.opts)
        self.assertEqual(ai.opts["max_workers"].get("default"), 3)
        self.assertTrue(ai.opts["max_workers"].get("internal", False))

    def test_mode_opt_help_lists_all_modes(self):
        """D2: the mode opt help documents every real mode (derived from MODES)."""
        from secator.tasks.ai import ai
        from secator.ai.prompts import MODES
        help_text = ai.opts["mode"]["help"]
        for mode in MODES:
            self.assertIn(mode, help_text)
        self.assertIn("exploit", help_text)  # the previously-omitted one


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDetectMode(unittest.TestCase):
    """D2: _detect_mode must honor an LLM 'exploit' classification (was discarded)."""

    def _make_task(self, prompt):
        """Bare ai instance with just the attributes _detect_mode reads."""
        from secator.tasks.ai import ai
        t = ai.__new__(ai)
        t.mode = ""            # no explicit mode -> detection runs
        t.prompt = prompt
        t.intent_model = "test-intent-model"
        t.api_base = None
        t.api_key = None
        t.backend = MagicMock()
        t.is_subagent = False
        t.max_iterations = 10
        t._account_usage = MagicMock()
        return t

    def _run_detect(self, prompt, llm_word):
        """Force the LLM branch (ambiguous prompt) and stub call_llm's verdict."""
        from secator.tasks.ai import ai
        t = self._make_task(prompt)
        with patch("secator.tasks.ai.call_llm", return_value={"content": llm_word, "usage": {}}), \
             patch("secator.tasks.ai.get_system_prompt", return_value="sys"), \
             patch("secator.tasks.ai.build_tool_schemas", return_value=[]), \
             patch.object(ai, "reports_folder", "/tmp/ws"):
            t._detect_mode()
        return t.mode

    def test_llm_exploit_classification_is_honored(self):
        # ambiguous prompt -> defers to LLM; LLM says exploit -> mode is exploit (was 'chat')
        self.assertEqual(self._run_detect("take a look at this thing", "exploit"), "exploit")

    def test_llm_attack_classification_unchanged(self):
        self.assertEqual(self._run_detect("take a look at this thing", "attack"), "attack")

    def test_llm_chat_classification_unchanged(self):
        self.assertEqual(self._run_detect("take a look at this thing", "chat"), "chat")

    def test_llm_unknown_classification_falls_back_to_chat(self):
        self.assertEqual(self._run_detect("take a look at this thing", "banana"), "chat")


if __name__ == '__main__':
    unittest.main()

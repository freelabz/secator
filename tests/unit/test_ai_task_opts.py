"""Tests for AI task subagent opts."""
import unittest


class TestAiTaskOpts(unittest.TestCase):
    """Tests for context, internal, and max_workers opts."""

    def test_context_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("context", ai.opts)
        self.assertTrue(ai.opts["context"].get("internal", False))

    def test_internal_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("internal", ai.opts)
        self.assertTrue(ai.opts["internal"].get("is_flag", False))
        self.assertTrue(ai.opts["internal"].get("internal", False))

    def test_max_workers_opt_exists(self):
        from secator.tasks.ai import ai
        self.assertIn("max_workers", ai.opts)
        self.assertEqual(ai.opts["max_workers"].get("default"), 3)
        self.assertTrue(ai.opts["max_workers"].get("internal", False))


if __name__ == '__main__':
    unittest.main()

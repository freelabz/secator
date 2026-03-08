"""Integration tests for AI subagents and batch execution."""
import unittest
from unittest.mock import patch, MagicMock


class TestSubagentIntegration(unittest.TestCase):
    """Integration tests for subagent spawning."""

    def test_subagent_action_parsing(self):
        """Test that spawning ai task with exploiter mode parses correctly."""
        from secator.ai.utils import parse_actions
        response = '[{"action": "task", "name": "ai", "targets": ["192.168.1.1"], "opts": {"mode": "exploiter", "internal": true, "context": {"vulnerability": {"name": "CVE-2024-1234"}}}}]'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["name"], "ai")
        self.assertEqual(actions[0]["opts"]["mode"], "exploiter")
        self.assertTrue(actions[0]["opts"]["internal"])
        self.assertEqual(actions[0]["opts"]["context"]["vulnerability"]["name"], "CVE-2024-1234")

    def test_subagent_action_with_rich_context(self):
        """Test subagent action with full rich context."""
        from secator.ai.utils import parse_actions
        response = '''[{"action": "task", "name": "ai", "targets": ["10.0.0.1"], "opts": {
            "mode": "exploiter", "internal": true,
            "context": {
                "vulnerability": {"name": "CVE-2024-1234", "type": "path_traversal", "service": "apache", "port": 80},
                "relevant_findings": [{"_type": "port", "port": 80, "service": "http"}],
                "objective": "Verify path traversal and extract /etc/passwd"
            }
        }}]'''
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        ctx = actions[0]["opts"]["context"]
        self.assertEqual(ctx["vulnerability"]["type"], "path_traversal")
        self.assertEqual(len(ctx["relevant_findings"]), 1)
        self.assertIn("Verify", ctx["objective"])


class TestBatchIntegration(unittest.TestCase):
    """Integration tests for batch execution."""

    def test_group_and_batch_flow(self):
        """Test that grouped actions are batched and executed correctly."""
        from secator.tasks.ai import group_actions
        from secator.ai.actions import _run_batch, ActionContext

        # Simulate LLM response with grouped actions
        actions = [
            {"action": "shell", "command": "echo a", "group": "test"},
            {"action": "shell", "command": "echo b", "group": "test"},
            {"action": "shell", "command": "echo c"},
        ]

        grouped = group_actions(actions)

        # Should have: batch of 2, then 1 sequential
        self.assertEqual(len(grouped), 2)
        self.assertIsInstance(grouped[0], list)
        self.assertEqual(len(grouped[0]), 2)
        self.assertIsInstance(grouped[1], dict)

        # Execute batch in dry_run mode
        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True, max_workers=2)
        results = list(_run_batch(grouped[0], ctx))

        from secator.output_types import Info
        # Should have batch Info + 2x dry run Info
        info_count = sum(1 for r in results if isinstance(r, Info) and 'DRY RUN' in str(getattr(r, 'message', '')))
        self.assertEqual(info_count, 2)

    def test_mixed_parallel_and_sequential(self):
        """Test LLM response with both parallel and sequential actions."""
        from secator.tasks.ai import group_actions

        actions = [
            {"action": "task", "name": "nmap", "targets": ["host1"], "group": "recon"},
            {"action": "task", "name": "nmap", "targets": ["host2"], "group": "recon"},
            {"action": "task", "name": "nmap", "targets": ["host3"], "group": "recon"},
            {"action": "task", "name": "nuclei", "targets": ["host1", "host2", "host3"]},
            {"action": "query", "query": {"_type": "vulnerability"}},
        ]

        grouped = group_actions(actions)

        # 3 nmap parallel, then nuclei sequential, then query sequential
        self.assertEqual(len(grouped), 3)
        self.assertIsInstance(grouped[0], list)
        self.assertEqual(len(grouped[0]), 3)
        self.assertIsInstance(grouped[1], dict)
        self.assertEqual(grouped[1]["name"], "nuclei")
        self.assertIsInstance(grouped[2], dict)
        self.assertEqual(grouped[2]["action"], "query")

    def test_group_field_stripped_from_actions(self):
        """Test that group field is removed before execution."""
        from secator.tasks.ai import group_actions

        actions = [
            {"action": "task", "name": "nmap", "targets": ["host1"], "group": "scan"},
        ]

        grouped = group_actions(actions)

        # group field should be removed
        self.assertNotIn("group", grouped[0][0])
        self.assertEqual(grouped[0][0]["name"], "nmap")


if __name__ == '__main__':
    unittest.main()

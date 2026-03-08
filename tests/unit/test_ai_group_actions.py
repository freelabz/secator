"""Tests for group_actions function."""
import unittest


class TestGroupActions(unittest.TestCase):
    """Tests for grouping actions by 'group' field."""

    def test_no_groups_returns_sequential(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "nmap"},
            {"action": "shell", "command": "whoami"},
        ]
        result = group_actions(actions)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], dict)

    def test_same_group_batched(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "nmap", "targets": ["a"], "group": "scan"},
            {"action": "task", "name": "nmap", "targets": ["b"], "group": "scan"},
            {"action": "task", "name": "nmap", "targets": ["c"], "group": "scan"},
        ]
        result = group_actions(actions)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], list)
        self.assertEqual(len(result[0]), 3)

    def test_group_field_removed(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "nmap", "group": "scan"},
        ]
        result = group_actions(actions)
        self.assertNotIn("group", result[0][0])

    def test_mixed_grouped_and_sequential(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "nmap", "targets": ["a"], "group": "scan"},
            {"action": "task", "name": "nmap", "targets": ["b"], "group": "scan"},
            {"action": "task", "name": "nuclei", "targets": ["a"]},
            {"action": "query", "query": {}},
        ]
        result = group_actions(actions)
        self.assertEqual(len(result), 3)
        self.assertIsInstance(result[0], list)
        self.assertEqual(len(result[0]), 2)
        self.assertIsInstance(result[1], dict)
        self.assertIsInstance(result[2], dict)

    def test_sequential_between_groups_flushes(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "a", "group": "g1"},
            {"action": "task", "name": "b"},
            {"action": "task", "name": "c", "group": "g2"},
        ]
        result = group_actions(actions)
        self.assertEqual(len(result), 3)
        self.assertIsInstance(result[0], list)
        self.assertIsInstance(result[1], dict)
        self.assertIsInstance(result[2], list)

    def test_multiple_groups(self):
        from secator.ai.actions import group_actions
        actions = [
            {"action": "task", "name": "a", "group": "g1"},
            {"action": "task", "name": "b", "group": "g2"},
            {"action": "task", "name": "c", "group": "g1"},
            {"action": "task", "name": "d", "group": "g2"},
        ]
        result = group_actions(actions)
        self.assertEqual(len(result), 2)
        self.assertEqual(len(result[0]), 2)
        self.assertEqual(len(result[1]), 2)


if __name__ == '__main__':
    unittest.main()

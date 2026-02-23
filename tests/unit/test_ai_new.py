# tests/unit/test_ai_new.py
import unittest

from secator.tasks.ai_new import ai, parse_actions, strip_json_from_response


class TestAiTask(unittest.TestCase):

    def test_ai_task_has_required_attributes(self):
        self.assertTrue(hasattr(ai, 'opts'))
        self.assertIn('prompt', ai.opts)
        self.assertIn('mode', ai.opts)
        self.assertIn('model', ai.opts)

    def test_parse_actions_single(self):
        response = 'Analysis.\n\n[{"action":"done","reason":"complete"}]'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "done")

    def test_parse_actions_multiple(self):
        response = 'Running scans.\n\n[{"action":"task","name":"nmap"},{"action":"task","name":"httpx"}]'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 2)

    def test_parse_actions_code_block(self):
        response = 'Analysis.\n\n```json\n[{"action":"done"}]\n```'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)

    def test_strip_json_from_response(self):
        response = 'Found login page.\n\n[{"action":"task","name":"nuclei"}]'
        text = strip_json_from_response(response)

        self.assertIn("Found login page", text)
        self.assertNotIn("nuclei", text)

    def test_strip_json_preserves_non_action_brackets(self):
        response = 'List items: [a, b, c]. Action: [{"action":"done"}]'
        text = strip_json_from_response(response)

        self.assertIn("[a, b, c]", text)
        self.assertNotIn("action", text)


if __name__ == '__main__':
    unittest.main()

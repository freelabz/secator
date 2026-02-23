# tests/unit/test_ai_history.py
import unittest

from secator.tasks.ai_history import ChatHistory


class TestChatHistory(unittest.TestCase):

    def test_add_system(self):
        history = ChatHistory()
        history.add_system("You are an assistant.")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "You are an assistant.")

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


if __name__ == '__main__':
    unittest.main()

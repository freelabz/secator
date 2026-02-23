# tests/unit/test_ai_history.py
import unittest


class TestChatHistory(unittest.TestCase):

    def test_add_assistant_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("I will run nmap")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertEqual(messages[0]["content"], "I will run nmap")

    def test_add_tool_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_tool("nmap output: port 80 open")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "tool")
        self.assertEqual(messages[0]["content"], "nmap output: port 80 open")

    def test_add_user_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user("Focus on web vulnerabilities")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        self.assertEqual(messages[0]["content"], "Focus on web vulnerabilities")

    def test_multiple_messages_preserve_order(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("Running nmap")
        history.add_tool("Port 80 open")
        history.add_assistant("Found web server")

        messages = history.to_messages()
        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertEqual(messages[1]["role"], "tool")
        self.assertEqual(messages[2]["role"], "assistant")

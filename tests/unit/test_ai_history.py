# tests/unit/test_ai_history.py
import unittest
from unittest.mock import patch


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


class TestChatHistorySummarization(unittest.TestCase):

    def test_summarize_keeps_last_n_messages(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        # Add 6 messages (3 iterations worth)
        history.add_assistant("Iteration 1 response")
        history.add_tool("Iteration 1 results")
        history.add_assistant("Iteration 2 response")
        history.add_tool("Iteration 2 results")
        history.add_assistant("Iteration 3 response")
        history.add_tool("Iteration 3 results")

        # Mock summarizer that just returns "Summary"
        def mock_summarizer(messages):
            return "Summary of previous iterations"

        history.summarize(summarizer=mock_summarizer, keep_last=4)

        messages = history.to_messages()
        # Should have: 1 summary + 4 kept messages = 5
        self.assertEqual(len(messages), 5)
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("Summary", messages[0]["content"])

    def test_summarize_no_op_when_few_messages(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("Response 1")
        history.add_tool("Results 1")

        def mock_summarizer(messages):
            return "Should not be called"

        history.summarize(summarizer=mock_summarizer, keep_last=4)

        messages = history.to_messages()
        # Should be unchanged - only 2 messages, less than keep_last
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["role"], "assistant")


class TestLLMSummarizer(unittest.TestCase):

    @patch('secator.tasks.ai_history.get_llm_response')
    def test_create_llm_summarizer_calls_llm(self, mock_llm):
        from secator.tasks.ai_history import create_llm_summarizer

        mock_llm.return_value = "Summary: Found 2 vulns"

        summarizer = create_llm_summarizer(model="gpt-4o-mini")
        messages = [
            {"role": "assistant", "content": "Running nmap"},
            {"role": "tool", "content": "Port 80 open"},
        ]

        result = summarizer(messages)

        self.assertEqual(result, "Summary: Found 2 vulns")
        mock_llm.assert_called_once()

    @patch('secator.tasks.ai_history.get_llm_response')
    def test_summarizer_formats_messages_for_prompt(self, mock_llm):
        from secator.tasks.ai_history import create_llm_summarizer

        mock_llm.return_value = "Summary"

        summarizer = create_llm_summarizer(model="gpt-4o-mini")
        messages = [
            {"role": "assistant", "content": "Action 1"},
            {"role": "tool", "content": "Result 1"},
        ]

        summarizer(messages)

        # Check prompt contains the messages
        call_args = mock_llm.call_args
        prompt = call_args.kwargs.get('prompt') or call_args[1].get('prompt') or call_args[0][0]
        self.assertIn("Action 1", prompt)
        self.assertIn("Result 1", prompt)

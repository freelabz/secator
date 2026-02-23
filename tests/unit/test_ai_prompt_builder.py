# tests/unit/test_ai_prompt_builder.py
import unittest


class TestPromptBuilder(unittest.TestCase):

    def test_build_system_prompt(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        system_prompt = builder.build_system_prompt()

        self.assertIn("penetration testing", system_prompt.lower())
        self.assertIn("action", system_prompt.lower())

    def test_build_user_prompt(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        user_prompt = builder.build_user_prompt(
            targets=["192.168.1.1", "example.com"],
            instructions="Focus on web vulnerabilities"
        )

        self.assertIn("192.168.1.1", user_prompt)
        self.assertIn("example.com", user_prompt)
        self.assertIn("Focus on web vulnerabilities", user_prompt)

    def test_build_loop_query(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        query = builder.build_loop_query(iteration=3, max_iterations=10)

        self.assertIn("3", query)
        self.assertIn("10", query)

    def test_build_full_prompt_structure(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from secator.tasks.ai_history import ChatHistory

        builder = PromptBuilder()
        history = ChatHistory()
        history.add_assistant("Running scan")
        history.add_tool("Found port 80")

        prompt = builder.build_full_prompt(
            targets=["target.com"],
            instructions="Test web app",
            history=history,
            iteration=2,
            max_iterations=5
        )

        # Should have all 4 sections
        self.assertIn("system", prompt)
        self.assertIn("user", prompt)
        self.assertIn("history", prompt)
        self.assertIn("query", prompt)

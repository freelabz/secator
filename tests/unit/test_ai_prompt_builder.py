# tests/unit/test_ai_prompt_builder.py
import unittest


class TestPromptBuilder(unittest.TestCase):

    def test_build_system_prompt(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        system_prompt = builder.build_system_prompt()

        self.assertIn("security testing", system_prompt.lower())
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


class TestPromptBuilderEncryption(unittest.TestCase):

    def test_encrypt_prompt_encrypts_all_fields(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from unittest.mock import MagicMock

        # Mock encryptor
        encryptor = MagicMock()
        encryptor.encrypt.side_effect = lambda x: f"ENCRYPTED({x})"

        builder = PromptBuilder()
        prompt = {
            "system": "System prompt",
            "user": "User prompt with target.com",
            "history": [{"role": "assistant", "content": "Found vuln"}],
            "query": "Iteration 1/10"
        }

        encrypted = builder.encrypt_prompt(prompt, encryptor)

        # All string fields should be encrypted
        self.assertIn("ENCRYPTED", encrypted["user"])
        self.assertIn("ENCRYPTED", encrypted["query"])
        # History content should be encrypted
        self.assertIn("ENCRYPTED", encrypted["history"][0]["content"])

    def test_encrypt_prompt_skips_system(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from unittest.mock import MagicMock

        encryptor = MagicMock()
        encryptor.encrypt.side_effect = lambda x: f"ENCRYPTED({x})"

        builder = PromptBuilder()
        prompt = {
            "system": "System prompt - no sensitive data",
            "user": "Target: secret.com",
            "history": [],
            "query": "Query"
        }

        encrypted = builder.encrypt_prompt(prompt, encryptor)

        # System prompt should NOT be encrypted (no sensitive data)
        self.assertEqual(encrypted["system"], "System prompt - no sensitive data")


class TestFormatPromptForLLM(unittest.TestCase):

    def test_format_prompt_for_llm_combines_sections(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        prompt = {
            "system": "You are an agent.",
            "user": "## Targets\n- target.com",
            "history": [
                {"role": "assistant", "content": "Running scan"},
                {"role": "tool", "content": "Port 80 open"}
            ],
            "query": "Iteration 1/10."
        }

        formatted = builder.format_prompt_for_llm(prompt)

        # Should be a single string with all parts
        self.assertIsInstance(formatted, str)
        self.assertIn("You are an agent", formatted)
        self.assertIn("target.com", formatted)
        self.assertIn("Running scan", formatted)
        self.assertIn("Port 80 open", formatted)
        self.assertIn("Iteration 1/10", formatted)

    def test_format_prompt_for_llm_empty_history(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        prompt = {
            "system": "System",
            "user": "User",
            "history": [],
            "query": "Query"
        }

        formatted = builder.format_prompt_for_llm(prompt)

        # Should not have history section header when empty
        self.assertIn("System", formatted)
        self.assertIn("User", formatted)
        self.assertIn("Query", formatted)

# tests/unit/test_ai_prompts.py
import unittest

from secator.tasks.ai_prompts import (
    SYSTEM_ATTACK,
    SYSTEM_CHAT,
    get_system_prompt,
    format_user_initial,
    format_tool_result,
    format_continue,
)


class TestPrompts(unittest.TestCase):

    def test_system_attack_has_actions(self):
        self.assertIn("task", SYSTEM_ATTACK)
        self.assertIn("workflow", SYSTEM_ATTACK)
        self.assertIn("shell", SYSTEM_ATTACK)
        self.assertIn("query", SYSTEM_ATTACK)
        self.assertIn("done", SYSTEM_ATTACK)

    def test_system_chat_has_query(self):
        self.assertIn("query", SYSTEM_CHAT)
        self.assertIn("done", SYSTEM_CHAT)

    def test_get_system_prompt_attack(self):
        prompt = get_system_prompt("attack")
        self.assertIn("task", prompt)
        self.assertIn("TOOLS:", prompt)

    def test_get_system_prompt_chat(self):
        prompt = get_system_prompt("chat")
        self.assertIn("query", prompt)

    def test_format_user_initial(self):
        result = format_user_initial(["example.com"], "scan for vulns")
        self.assertIn("example.com", result)
        self.assertIn("scan for vulns", result)
        # Should be compact JSON (no newlines)
        self.assertNotIn("\n", result)

    def test_format_tool_result(self):
        result = format_tool_result("nmap", "success", 5, [{"port": 80}])
        self.assertIn("nmap", result)
        self.assertIn("success", result)
        # Should be compact JSON
        self.assertNotIn("\n", result)

    def test_format_continue(self):
        result = format_continue(3, 10)
        self.assertIn("3", result)
        self.assertIn("10", result)
        # Should be compact JSON
        self.assertNotIn("\n", result)


if __name__ == '__main__':
    unittest.main()

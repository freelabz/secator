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
        self.assertIn("TASKS:", prompt)

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

    def test_build_tasks_reference_format(self):
        from secator.tasks.ai_prompts import build_tasks_reference
        result = build_tasks_reference()
        # Should be pipe-delimited format
        lines = result.strip().split('\n')
        self.assertTrue(len(lines) > 0)
        # Each line should have name|description|options format
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertEqual(len(parts), 3, f"Expected 3 parts (name|desc|opts), got: {first_line}")

    def test_build_tasks_reference_excludes_ai(self):
        from secator.tasks.ai_prompts import build_tasks_reference
        result = build_tasks_reference()
        # Should not include the Ai task itself
        self.assertNotIn('Ai|', result)
        self.assertNotIn('ai|', result)

    def test_build_workflows_reference_format(self):
        from secator.tasks.ai_prompts import build_workflows_reference
        result = build_workflows_reference()
        # Should have workflow entries (may be empty if no workflows configured)
        if result:
            lines = result.strip().split('\n')
            first_line = lines[0]
            parts = first_line.split('|')
            self.assertGreaterEqual(len(parts), 1, "Should have at least workflow name")

    def test_build_profiles_reference_format(self):
        from secator.tasks.ai_prompts import build_profiles_reference
        result = build_profiles_reference()
        if result:
            lines = result.strip().split('\n')
            first_line = lines[0]
            parts = first_line.split('|')
            self.assertGreaterEqual(len(parts), 1, "Should have at least profile name")

    def test_build_wordlists_reference_format(self):
        from secator.tasks.ai_prompts import build_wordlists_reference
        result = build_wordlists_reference()
        # Should return string (may be empty if no wordlists configured)
        self.assertIsInstance(result, str)

    def test_build_output_types_reference_format(self):
        from secator.tasks.ai_prompts import build_output_types_reference
        result = build_output_types_reference()
        lines = result.strip().split('\n')
        self.assertTrue(len(lines) > 0)
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertEqual(len(parts), 2, f"Expected 2 parts (name|fields), got: {first_line}")

    def test_build_output_types_reference_has_vulnerability(self):
        from secator.tasks.ai_prompts import build_output_types_reference
        result = build_output_types_reference()
        self.assertIn('vulnerability|', result)

    def test_option_formats_has_header(self):
        from secator.tasks.ai_prompts import OPTION_FORMATS
        self.assertIn('header|', OPTION_FORMATS)
        self.assertIn(';;', OPTION_FORMATS)  # Header format hint

    def test_build_library_reference_has_all_sections(self):
        from secator.tasks.ai_prompts import build_library_reference
        result = build_library_reference()
        self.assertIn('TASKS:', result)
        self.assertIn('WORKFLOWS:', result)
        self.assertIn('PROFILES:', result)
        self.assertIn('WORDLISTS:', result)
        self.assertIn('OUTPUT_TYPES:', result)
        self.assertIn('OPTION_FORMATS:', result)

    def test_get_system_prompt_attack_has_library_reference(self):
        from secator.tasks.ai_prompts import get_system_prompt
        prompt = get_system_prompt("attack")
        # Should have all library reference sections
        self.assertIn('TASKS:', prompt)
        self.assertIn('WORKFLOWS:', prompt)
        self.assertIn('PROFILES:', prompt)
        self.assertIn('OUTPUT_TYPES:', prompt)
        self.assertIn('OPTION_FORMATS:', prompt)
        # Should have query operators
        self.assertIn('$in', prompt)
        self.assertIn('$regex', prompt)
        # Should have profiles usage hint
        self.assertIn('profiles', prompt)


if __name__ == '__main__':
    unittest.main()

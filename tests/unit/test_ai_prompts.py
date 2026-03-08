# tests/unit/test_ai_prompts.py
import unittest

from secator.ai.prompts import (
    SYSTEM_ATTACK,
    SYSTEM_CHAT,
    SYSTEM_EXPLOITER,
    MODES,
    get_system_prompt,
    get_mode_config,
    format_user_initial,
    format_tool_result,
    format_continue,
)


class TestPrompts(unittest.TestCase):

    def test_system_attack_has_actions(self):
        self.assertIn("task", SYSTEM_ATTACK.template)
        self.assertIn("workflow", SYSTEM_ATTACK.template)
        self.assertIn("shell", SYSTEM_ATTACK.template)
        self.assertIn("query", SYSTEM_ATTACK.template)
        self.assertIn("follow_up", SYSTEM_ATTACK.template)

    def test_system_chat_has_query(self):
        self.assertIn("query", SYSTEM_CHAT.template)
        self.assertIn("follow_up", SYSTEM_CHAT.template)

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

    def test_format_tool_result_truncates_max_items(self):
        items = [{"port": i} for i in range(200)]
        result = format_tool_result("nmap", "success", 200, items, max_items=50)
        import json
        data = json.loads(result)
        self.assertEqual(len(data["results"]), 50)
        self.assertTrue(data["truncated"])
        self.assertEqual(data["total_count"], 200)

    def test_format_tool_result_no_truncation_under_max_items(self):
        items = [{"port": i} for i in range(10)]
        result = format_tool_result("nmap", "success", 10, items, max_items=100)
        import json
        data = json.loads(result)
        self.assertEqual(len(data["results"]), 10)
        self.assertNotIn("truncated", data)

    def test_format_continue(self):
        result = format_continue(3, 10)
        self.assertIn("3", result)
        self.assertIn("10", result)
        # Should be compact JSON
        self.assertNotIn("\n", result)

    def test_build_tasks_reference_format(self):
        from secator.ai.prompts import build_tasks_reference
        result = build_tasks_reference()
        # Should be pipe-delimited format
        lines = result.strip().split('\n')
        self.assertTrue(len(lines) > 0)
        # Each line should have name|description|options format
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertEqual(len(parts), 3, f"Expected 3 parts (name|desc|opts), got: {first_line}")

    def test_build_tasks_reference_excludes_ai(self):
        from secator.ai.prompts import build_tasks_reference
        result = build_tasks_reference()
        # Should not include the Ai task itself
        self.assertNotIn('Ai|', result)
        self.assertNotIn('ai|', result)

    def test_build_workflows_reference_format(self):
        from secator.ai.prompts import build_workflows_reference
        result = build_workflows_reference()
        # Should have workflow entries (may be empty if no workflows configured)
        if result:
            lines = result.strip().split('\n')
            first_line = lines[0]
            parts = first_line.split('|')
            self.assertGreaterEqual(len(parts), 1, "Should have at least workflow name")

    def test_build_profiles_reference_format(self):
        from secator.ai.prompts import build_profiles_reference
        result = build_profiles_reference()
        if result:
            lines = result.strip().split('\n')
            first_line = lines[0]
            parts = first_line.split('|')
            self.assertGreaterEqual(len(parts), 1, "Should have at least profile name")

    def test_build_wordlists_reference_format(self):
        from secator.ai.prompts import build_wordlists_reference
        result = build_wordlists_reference()
        # Should return string (may be empty if no wordlists configured)
        self.assertIsInstance(result, str)

    def test_build_output_types_reference_format(self):
        from secator.ai.prompts import build_output_types_reference
        result = build_output_types_reference()
        lines = result.strip().split('\n')
        self.assertTrue(len(lines) > 0)
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertEqual(len(parts), 2, f"Expected 2 parts (name|fields), got: {first_line}")

    def test_build_output_types_reference_has_vulnerability(self):
        from secator.ai.prompts import build_output_types_reference
        result = build_output_types_reference()
        self.assertIn('vulnerability|', result)

    def test_option_formats_has_header(self):
        from secator.ai.prompts import OPTION_FORMATS
        self.assertIn('header|', OPTION_FORMATS)
        self.assertIn(';;', OPTION_FORMATS)  # Header format hint

    def test_build_library_reference_has_all_sections(self):
        from secator.ai.prompts import build_library_reference
        result = build_library_reference()
        self.assertIn('TASKS:', result)
        self.assertIn('WORKFLOWS:', result)
        self.assertIn('PROFILES:', result)
        self.assertIn('WORDLISTS:', result)
        self.assertIn('OUTPUT_TYPES:', result)
        self.assertIn('OPTION_FORMATS:', result)

    def test_get_system_prompt_attack_has_library_reference(self):
        from secator.ai.prompts import get_system_prompt
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

    # === MODES dict and SYSTEM_EXPLOITER tests ===

    def test_modes_dict_exists_with_expected_modes(self):
        """Test MODES dict exists with attack, chat, exploiter modes."""
        self.assertIn("attack", MODES)
        self.assertIn("chat", MODES)
        self.assertIn("exploiter", MODES)

    def test_exploiter_mode_config_has_correct_allowed_actions(self):
        """Test exploiter mode config has correct allowed_actions."""
        exploiter_config = MODES["exploiter"]
        expected_actions = ["task", "workflow", "shell", "add_finding"]
        self.assertEqual(exploiter_config["allowed_actions"], expected_actions)

    def test_exploiter_mode_config_has_max_iterations_5(self):
        """Test exploiter mode config has max_iterations=5."""
        exploiter_config = MODES["exploiter"]
        self.assertEqual(exploiter_config["max_iterations"], 5)

    def test_attack_mode_config_has_correct_allowed_actions(self):
        """Test attack mode config has correct allowed_actions."""
        attack_config = MODES["attack"]
        expected_actions = ["task", "workflow", "shell", "query", "follow_up", "add_finding"]
        self.assertEqual(attack_config["allowed_actions"], expected_actions)

    def test_chat_mode_config_has_correct_allowed_actions(self):
        """Test chat mode config has correct allowed_actions."""
        chat_config = MODES["chat"]
        expected_actions = ["query", "follow_up", "add_finding", "shell"]
        self.assertEqual(chat_config["allowed_actions"], expected_actions)

    def test_attack_and_chat_modes_have_no_max_iterations(self):
        """Test attack and chat modes have max_iterations=None."""
        self.assertIsNone(MODES["attack"]["max_iterations"])
        self.assertIsNone(MODES["chat"]["max_iterations"])

    def test_get_mode_config_returns_correct_mode(self):
        """Test get_mode_config returns correct mode config."""
        attack_config = get_mode_config("attack")
        self.assertEqual(attack_config["system_prompt"], SYSTEM_ATTACK)

        chat_config = get_mode_config("chat")
        self.assertEqual(chat_config["system_prompt"], SYSTEM_CHAT)

        exploiter_config = get_mode_config("exploiter")
        self.assertEqual(exploiter_config["system_prompt"], SYSTEM_EXPLOITER)

    def test_get_mode_config_falls_back_to_chat_for_unknown_modes(self):
        """Test get_mode_config falls back to chat for unknown modes."""
        unknown_config = get_mode_config("unknown_mode")
        chat_config = get_mode_config("chat")
        self.assertEqual(unknown_config, chat_config)

    def test_get_system_prompt_works_for_exploiter_mode(self):
        """Test get_system_prompt works for exploiter mode."""
        prompt = get_system_prompt("exploiter")
        self.assertIn("exploitation verification specialist", prompt)
        self.assertIn("proof-of-concept", prompt)

    def test_system_exploiter_has_expected_structure(self):
        """Test SYSTEM_EXPLOITER template has expected sections (no TEMPLATE/EXAMPLES)."""
        self.assertIn("PERSONA", SYSTEM_EXPLOITER.template)
        self.assertIn("ACTION", SYSTEM_EXPLOITER.template)
        self.assertIn("STEPS", SYSTEM_EXPLOITER.template)
        self.assertIn("CONTEXT", SYSTEM_EXPLOITER.template)
        self.assertIn("CONSTRAINTS", SYSTEM_EXPLOITER.template)

    def test_system_exploiter_has_expected_actions(self):
        """Test SYSTEM_EXPLOITER template mentions expected concepts."""
        self.assertIn("tools", SYSTEM_EXPLOITER.template)
        self.assertIn("exploitation", SYSTEM_EXPLOITER.template)
        self.assertIn("proof-of-concept", SYSTEM_EXPLOITER.template)

    def test_get_system_prompt_raises_for_invalid_mode(self):
        """Test get_system_prompt raises ValueError for invalid mode."""
        with self.assertRaises(ValueError):
            get_system_prompt("invalid_mode")

    # === Tests for TEMPLATE/EXAMPLES removal ===

    def test_system_attack_has_no_template_section(self):
        """Test SYSTEM_ATTACK does not contain ### TEMPLATE section."""
        self.assertNotIn("### TEMPLATE", SYSTEM_ATTACK.template)

    def test_system_attack_has_no_examples_section(self):
        """Test SYSTEM_ATTACK does not contain ### EXAMPLES section."""
        self.assertNotIn("### EXAMPLES", SYSTEM_ATTACK.template)

    def test_system_chat_has_no_template_section(self):
        """Test SYSTEM_CHAT does not contain ### TEMPLATE section."""
        self.assertNotIn("### TEMPLATE", SYSTEM_CHAT.template)

    def test_system_chat_has_no_examples_section(self):
        """Test SYSTEM_CHAT does not contain ### EXAMPLES section."""
        self.assertNotIn("### EXAMPLES", SYSTEM_CHAT.template)

    def test_system_exploiter_has_no_template_section(self):
        """Test SYSTEM_EXPLOITER does not contain ### TEMPLATE section."""
        self.assertNotIn("### TEMPLATE", SYSTEM_EXPLOITER.template)

    def test_system_exploiter_has_no_examples_section(self):
        """Test SYSTEM_EXPLOITER does not contain ### EXAMPLES section."""
        self.assertNotIn("### EXAMPLES", SYSTEM_EXPLOITER.template)

    def test_system_attack_still_has_persona(self):
        """Test SYSTEM_ATTACK still contains ### PERSONA section."""
        self.assertIn("### PERSONA", SYSTEM_ATTACK.template)

    def test_system_attack_still_has_constraints(self):
        """Test SYSTEM_ATTACK still contains ### CONSTRAINTS section."""
        self.assertIn("### CONSTRAINTS", SYSTEM_ATTACK.template)


if __name__ == '__main__':
    unittest.main()

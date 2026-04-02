# tests/unit/test_ai_prompts.py
import unittest

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.prompts import (
		SYSTEM_ATTACK,
		SYSTEM_CHAT,
		SYSTEM_EXPLOIT,
		MODES,
		get_system_prompt,
		get_mode_config,
		format_tool_result,
		format_continue,
	)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestPrompts(unittest.TestCase):

	# === Structure tests: XML tags ===

	def test_system_attack_has_xml_structure(self):
		"""Test SYSTEM_ATTACK uses XML tags for structure."""
		self.assertIn("<persona>", SYSTEM_ATTACK.template)
		self.assertIn("<instructions>", SYSTEM_ATTACK.template)
		self.assertIn("<constraints>", SYSTEM_ATTACK.template)
		self.assertIn("<context>", SYSTEM_ATTACK.template)

	def test_system_chat_has_xml_structure(self):
		"""Test SYSTEM_CHAT uses XML tags for structure."""
		self.assertIn("<persona>", SYSTEM_CHAT.template)
		self.assertIn("<instructions>", SYSTEM_CHAT.template)
		self.assertIn("<constraints>", SYSTEM_CHAT.template)

	def test_system_exploit_has_xml_structure(self):
		"""Test SYSTEM_EXPLOIT uses XML tags for structure."""
		self.assertIn("<persona>", SYSTEM_EXPLOIT.template)
		self.assertIn("<instructions>", SYSTEM_EXPLOIT.template)
		self.assertIn("<constraints>", SYSTEM_EXPLOIT.template)
		self.assertIn("<context>", SYSTEM_EXPLOIT.template)

	def test_no_markdown_headers_in_templates(self):
		"""Templates should use XML tags, not markdown ### headers (outside examples)."""
		import re
		for template in (SYSTEM_ATTACK, SYSTEM_CHAT, SYSTEM_EXPLOIT):
			# Strip content inside <example> tags before checking
			content = re.sub(r'<example\w*>.*?</example\w*>', '', template.template, flags=re.DOTALL)
			self.assertNotIn("### ", content)

	# === Content tests ===

	def test_system_attack_has_actions(self):
		self.assertIn("task", SYSTEM_ATTACK.template)
		self.assertIn("workflow", SYSTEM_ATTACK.template)
		self.assertIn("shell", SYSTEM_ATTACK.template)
		self.assertIn("query", SYSTEM_ATTACK.template)
		self.assertIn("follow_up", SYSTEM_ATTACK.template)

	def test_system_chat_has_query(self):
		self.assertIn("query", SYSTEM_CHAT.template)
		self.assertIn("follow_up", SYSTEM_CHAT.template)

	def test_system_exploit_has_expected_content(self):
		"""Test SYSTEM_EXPLOIT template mentions expected concepts."""
		self.assertIn("exploitation", SYSTEM_EXPLOIT.template)
		self.assertIn("proof-of-concept", SYSTEM_EXPLOIT.template)
		self.assertIn("docker", SYSTEM_EXPLOIT.template.lower())

	def test_system_attack_has_subagents(self):
		"""Test SYSTEM_ATTACK has subagent guidance."""
		self.assertIn("<subagents>", SYSTEM_ATTACK.template)
		self.assertIn("run_task", SYSTEM_ATTACK.template)
		self.assertIn('name "ai"', SYSTEM_ATTACK.template)

	def test_context_is_at_top(self):
		"""Best practice: long data (context) should be at top of prompt."""
		for template in (SYSTEM_ATTACK, SYSTEM_EXPLOIT):
			content = template.template.strip()
			context_pos = content.find("<context>")
			persona_pos = content.find("<persona>")
			instructions_pos = content.find("<instructions>")
			self.assertLess(context_pos, persona_pos, "Context should come before persona")
			self.assertLess(context_pos, instructions_pos, "Context should come before instructions")

	# === Rendered prompt tests ===

	def test_get_system_prompt_attack(self):
		prompt = get_system_prompt("attack")
		self.assertIn("task", prompt)
		self.assertIn("<tasks>", prompt)

	def test_get_system_prompt_chat(self):
		prompt = get_system_prompt("chat")
		self.assertIn("query", prompt)

	def test_get_system_prompt_exploit(self):
		"""Test get_system_prompt works for exploit mode."""
		prompt = get_system_prompt("exploit")
		self.assertIn("exploitation verification specialist", prompt)
		self.assertIn("proof-of-concept", prompt)

	def test_get_system_prompt_attack_has_library_reference(self):
		prompt = get_system_prompt("attack")
		self.assertIn('<tasks>', prompt)
		self.assertIn('<workflows>', prompt)
		self.assertIn('<profiles>', prompt)
		self.assertIn('<output_types>', prompt)
		self.assertIn('<option_formats>', prompt)

	def test_get_system_prompt_attack_has_query_reference(self):
		prompt = get_system_prompt("attack")
		self.assertIn('$in', prompt)
		self.assertIn('$regex', prompt)

	def test_get_system_prompt_invalid_mode_falls_back(self):
		"""Test get_system_prompt falls back to chat for invalid mode (consistent with get_mode_config)."""
		invalid_prompt = get_system_prompt("invalid_mode")
		chat_prompt = get_system_prompt("chat")
		self.assertEqual(invalid_prompt, chat_prompt)

	# === Format functions ===

	def test_format_tool_result(self):
		result = format_tool_result("nmap", "success", 5, [{"port": 80}])
		self.assertIn("nmap", result)
		self.assertIn("success", result)
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
		self.assertNotIn("\n", result)

	# === Reference builders ===

	def test_build_tasks_reference_format(self):
		from secator.ai.prompts import build_tasks_reference
		result = build_tasks_reference()
		lines = result.strip().split('\n')
		self.assertTrue(len(lines) > 0)
		first_line = lines[0]
		parts = first_line.split('|')
		self.assertGreaterEqual(len(parts), 4, f"Expected 4+ parts (name|desc|tags|opts[|meta:...]), got: {first_line}")

	def test_build_tasks_reference_includes_ai(self):
		from secator.ai.prompts import build_tasks_reference
		result = build_tasks_reference()
		self.assertIn('ai|', result)

	def test_build_workflows_reference_format(self):
		from secator.ai.prompts import build_workflows_reference
		result = build_workflows_reference()
		if result:
			lines = result.strip().split('\n')
			first_line = lines[0]
			parts = first_line.split('|')
			self.assertGreaterEqual(len(parts), 1)

	def test_build_profiles_reference_format(self):
		from secator.ai.prompts import build_profiles_reference
		result = build_profiles_reference()
		if result:
			lines = result.strip().split('\n')
			first_line = lines[0]
			parts = first_line.split('|')
			self.assertGreaterEqual(len(parts), 1)

	def test_build_wordlists_reference_format(self):
		from secator.ai.prompts import build_wordlists_reference
		result = build_wordlists_reference()
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
		self.assertIn(';;', OPTION_FORMATS)

	def test_build_library_reference_has_all_sections(self):
		from secator.ai.prompts import build_library_reference
		result = build_library_reference()
		self.assertIn('<tasks>', result)
		self.assertIn('<workflows>', result)
		self.assertIn('<profiles>', result)
		self.assertIn('<wordlists>', result)
		self.assertIn('<output_types>', result)
		self.assertIn('<option_formats>', result)
		self.assertIn('<meta_options>', result)

	# === MODES dict tests ===

	def test_modes_dict_exists_with_expected_modes(self):
		self.assertIn("attack", MODES)
		self.assertIn("chat", MODES)
		self.assertIn("exploit", MODES)

	def test_exploit_mode_config_has_correct_allowed_actions(self):
		exploit_config = MODES["exploit"]
		expected_actions = ["task", "workflow", "shell", "add_finding", "stop"]
		self.assertEqual(exploit_config["allowed_actions"], expected_actions)

	def test_exploit_mode_config_has_max_iterations_5(self):
		exploit_config = MODES["exploit"]
		self.assertEqual(exploit_config["max_iterations"], 5)

	def test_attack_mode_config_has_correct_allowed_actions(self):
		attack_config = MODES["attack"]
		expected_actions = ["task", "workflow", "shell", "query", "follow_up", "add_finding", "stop"]
		self.assertEqual(attack_config["allowed_actions"], expected_actions)

	def test_chat_mode_config_has_correct_allowed_actions(self):
		chat_config = MODES["chat"]
		expected_actions = ["query", "follow_up", "add_finding", "shell", "stop"]
		self.assertEqual(chat_config["allowed_actions"], expected_actions)

	def test_all_modes_have_max_iterations_5(self):
		self.assertEqual(MODES["attack"]["max_iterations"], 5)
		self.assertEqual(MODES["chat"]["max_iterations"], 5)
		self.assertEqual(MODES["exploit"]["max_iterations"], 5)

	def test_get_mode_config_returns_correct_mode(self):
		attack_config = get_mode_config("attack")
		self.assertEqual(attack_config["system_prompt"], SYSTEM_ATTACK)
		chat_config = get_mode_config("chat")
		self.assertEqual(chat_config["system_prompt"], SYSTEM_CHAT)
		exploit_config = get_mode_config("exploit")
		self.assertEqual(exploit_config["system_prompt"], SYSTEM_EXPLOIT)

	def test_get_mode_config_falls_back_to_chat_for_unknown_modes(self):
		unknown_config = get_mode_config("unknown_mode")
		chat_config = get_mode_config("chat")
		self.assertEqual(unknown_config, chat_config)

	# === Common rules tests ===

	def test_common_rules_has_xml_tags(self):
		"""COMMON_RULES should use XML tags for each rule category."""
		from secator.ai.prompts import COMMON_RULES
		self.assertIn("<tool_calling>", COMMON_RULES)
		self.assertIn("<response_style>", COMMON_RULES)
		self.assertIn("<guardrails>", COMMON_RULES)
		self.assertIn("<truncated_output>", COMMON_RULES)

	def test_common_rules_has_no_shouting(self):
		"""COMMON_RULES should not have excessive ALL CAPS directives."""
		from secator.ai.prompts import COMMON_RULES
		# Aggressive NEVER/ALWAYS at start of sentences should be toned down
		self.assertNotIn("NEVER INVENT", COMMON_RULES)
		self.assertNotIn("ALWAYS provide", COMMON_RULES)


if __name__ == '__main__':
	unittest.main()

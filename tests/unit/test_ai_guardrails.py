# tests/unit/test_ai_guardrails.py
import unittest
from unittest.mock import patch

from secator.config import CONFIG
from secator.ai.actions import dispatch_action, ActionContext
from secator.ai.guardrails import (
	parse_rule, match_rule, detect_targets, detect_paths, classify_command,
	build_target_choices, PermissionEngine
)
from secator.output_types import Warning, Error


class TestGuardrailsConfig(unittest.TestCase):

	def test_ai_config_has_permissions(self):
		"""AI config should have a permissions section with allow/deny/ask lists."""
		permissions = CONFIG.addons.ai.permissions
		self.assertIsInstance(permissions, dict)
		self.assertIn("allow", permissions)
		self.assertIn("deny", permissions)
		self.assertIn("ask", permissions)

	def test_ai_permissions_defaults(self):
		"""Default permissions should include task(*) and workflow(*) in allow."""
		allow = CONFIG.addons.ai.permissions["allow"]
		self.assertIn("task(*)", allow)
		self.assertIn("workflow(*)", allow)
		self.assertIn("target({targets})", allow)

	def test_ai_permissions_deny_defaults(self):
		"""Default deny should block AWS metadata and localhost."""
		deny = CONFIG.addons.ai.permissions["deny"]
		self.assertIn("target(169.254.169.254)", deny)
		self.assertIn("target(127.0.0.1)", deny)


class TestRuleParser(unittest.TestCase):

	def test_parse_rule_target(self):
		rule_type, patterns = parse_rule("target(10.0.0.1)")
		self.assertEqual(rule_type, "target")
		self.assertEqual(patterns, ["10.0.0.1"])

	def test_parse_rule_multiple_values(self):
		rule_type, patterns = parse_rule("shell(nmap,httpx,nuclei)")
		self.assertEqual(rule_type, "shell")
		self.assertEqual(patterns, ["nmap", "httpx", "nuclei"])

	def test_parse_rule_wildcard(self):
		rule_type, patterns = parse_rule("task(*)")
		self.assertEqual(rule_type, "task")
		self.assertEqual(patterns, ["*"])

	def test_parse_rule_glob(self):
		rule_type, patterns = parse_rule("read({workspace}/*)")
		self.assertEqual(rule_type, "read")
		self.assertEqual(patterns, ["{workspace}/*"])

	def test_match_rule_exact(self):
		self.assertTrue(match_rule("nmap", ["nmap", "httpx"]))
		self.assertFalse(match_rule("sqlmap", ["nmap", "httpx"]))

	def test_match_rule_wildcard(self):
		self.assertTrue(match_rule("anything", ["*"]))

	def test_match_rule_glob(self):
		self.assertTrue(match_rule("/home/user/.secator/reports/file.txt", ["/home/user/.secator/reports/*"]))
		self.assertFalse(match_rule("/etc/passwd", ["/home/user/.secator/reports/*"]))

	def test_match_rule_with_port_variable(self):
		self.assertTrue(match_rule("10.0.0.1:8080", ["10.0.0.1:{port}"]))
		self.assertTrue(match_rule("10.0.0.1:443", ["10.0.0.1:{port}"]))
		self.assertFalse(match_rule("10.0.0.2:8080", ["10.0.0.1:{port}"]))


class TestDetection(unittest.TestCase):

	def test_detect_targets_ip(self):
		targets = detect_targets("nmap -sV 10.0.0.1")
		self.assertIn("10.0.0.1", targets)

	def test_detect_targets_host(self):
		targets = detect_targets("curl https://example.com/api")
		self.assertIn("example.com", targets)

	def test_detect_targets_url(self):
		targets = detect_targets("curl https://example.com:8080/path")
		self.assertIn("https://example.com:8080/path", targets)

	def test_detect_targets_no_false_positives(self):
		targets = detect_targets("echo hello world")
		self.assertEqual(targets, [])

	def test_detect_paths_absolute(self):
		paths = detect_paths("cat /etc/passwd")
		self.assertIn("/etc/passwd", paths)

	def test_detect_paths_home(self):
		paths = detect_paths("cat ~/.ssh/id_rsa")
		self.assertIn("~/.ssh/id_rsa", paths)

	def test_detect_paths_relative(self):
		paths = detect_paths("cat ./config.yaml")
		self.assertIn("./config.yaml", paths)

	def test_detect_paths_no_false_positives(self):
		paths = detect_paths("nmap --timeout 30 10.0.0.1")
		self.assertEqual(paths, [])

	def test_classify_read_command(self):
		self.assertEqual(classify_command("cat"), "read")
		self.assertEqual(classify_command("grep"), "read")
		self.assertEqual(classify_command("head"), "read")
		self.assertEqual(classify_command("tail"), "read")
		self.assertEqual(classify_command("ls"), "read")
		self.assertEqual(classify_command("find"), "read")
		self.assertEqual(classify_command("jq"), "read")
		self.assertEqual(classify_command("wc"), "read")

	def test_classify_write_command(self):
		self.assertEqual(classify_command("tee"), "write")
		self.assertEqual(classify_command("cp"), "write")
		self.assertEqual(classify_command("mv"), "write")
		self.assertEqual(classify_command("sed"), "write")

	def test_classify_execute_command(self):
		self.assertEqual(classify_command("python"), "execute")
		self.assertEqual(classify_command("python3"), "execute")
		self.assertEqual(classify_command("bash"), "execute")
		self.assertEqual(classify_command("node"), "execute")

	def test_classify_other_command(self):
		self.assertEqual(classify_command("nmap"), "other")
		self.assertEqual(classify_command("curl"), "other")


class TestPermissionEngine(unittest.TestCase):

	def _make_engine(self, allow=None, deny=None, ask=None, targets=None, workspace="/tmp/workspace"):
		config = {
			"allow": allow or [],
			"deny": deny or [],
			"ask": ask or [],
		}
		return PermissionEngine(config, targets=targets or [], workspace=workspace)

	# --- Action checks ---

	def test_shell_allowed(self):
		engine = self._make_engine(allow=["shell(nmap,curl)", "target(*)"])
		result = engine.check_action({"action": "shell", "command": "nmap -sV 10.0.0.1"})
		self.assertEqual(result.decision, "allow")

	def test_shell_denied_by_command(self):
		engine = self._make_engine(deny=["shell(rm)"])
		result = engine.check_action({"action": "shell", "command": "rm -rf /*"})
		self.assertEqual(result.decision, "deny")

	def test_task_allowed_wildcard(self):
		engine = self._make_engine(allow=["task(*)", "target(*)"])
		result = engine.check_action({"action": "task", "name": "nmap", "targets": ["10.0.0.1"]})
		self.assertEqual(result.decision, "allow")

	def test_workflow_allowed_wildcard(self):
		engine = self._make_engine(allow=["workflow(*)", "target(*)"])
		result = engine.check_action({"action": "workflow", "name": "recon", "targets": ["example.com"]})
		self.assertEqual(result.decision, "allow")

	def test_query_always_allowed(self):
		engine = self._make_engine()
		result = engine.check_action({"action": "query", "query": {"_type": "vulnerability"}})
		self.assertEqual(result.decision, "allow")

	def test_follow_up_always_allowed(self):
		engine = self._make_engine()
		result = engine.check_action({"action": "follow_up", "reason": "test"})
		self.assertEqual(result.decision, "allow")

	# --- Target checks ---

	def test_target_allowed_via_targets_variable(self):
		engine = self._make_engine(
			allow=["shell(nmap)", "target({targets})"],
			targets=["10.0.0.1"]
		)
		result = engine.check_action({"action": "shell", "command": "nmap 10.0.0.1"})
		self.assertEqual(result.decision, "allow")

	def test_target_denied(self):
		engine = self._make_engine(
			allow=["shell(nmap)"],
			deny=["target(169.254.169.254)"]
		)
		result = engine.check_action({"action": "shell", "command": "nmap 169.254.169.254"})
		self.assertEqual(result.decision, "deny")

	def test_target_ask_for_unknown(self):
		engine = self._make_engine(
			allow=["shell(nmap)"],
			ask=["target(*)"]
		)
		result = engine.check_action({"action": "shell", "command": "nmap 10.5.2.3"})
		self.assertEqual(result.decision, "ask")
		self.assertIn("10.5.2.3", result.targets)

	def test_task_target_validation(self):
		engine = self._make_engine(
			allow=["task(*)", "target({targets})"],
			deny=["target(169.254.169.254)"],
			targets=["example.com"]
		)
		result = engine.check_action({"action": "task", "name": "nmap", "targets": ["169.254.169.254"]})
		self.assertEqual(result.decision, "deny")

	def test_task_target_allowed(self):
		engine = self._make_engine(
			allow=["task(*)", "target({targets})"],
			targets=["example.com"]
		)
		result = engine.check_action({"action": "task", "name": "nmap", "targets": ["example.com"]})
		self.assertEqual(result.decision, "allow")

	# --- Path checks ---

	def test_read_path_allowed(self):
		engine = self._make_engine(
			allow=["shell(cat)", "read(/tmp/workspace/*)"],
			workspace="/tmp/workspace"
		)
		result = engine.check_action({"action": "shell", "command": "cat /tmp/workspace/report.json"})
		self.assertEqual(result.decision, "allow")

	def test_read_path_denied(self):
		engine = self._make_engine(
			allow=["shell(cat)"],
			deny=["read(/etc/shadow)"]
		)
		result = engine.check_action({"action": "shell", "command": "cat /etc/shadow"})
		self.assertEqual(result.decision, "deny")

	# --- Runtime allow list expansion ---

	def test_add_runtime_allow(self):
		engine = self._make_engine(allow=["shell(nmap)"], ask=["target(*)"])
		result = engine.check_action({"action": "shell", "command": "nmap 10.5.2.3"})
		self.assertEqual(result.decision, "ask")
		engine.add_runtime_allow(["target(10.5.2.3)"])
		result = engine.check_action({"action": "shell", "command": "nmap 10.5.2.3"})
		self.assertEqual(result.decision, "allow")

	# --- Evaluation order ---

	def test_deny_takes_precedence_over_allow(self):
		engine = self._make_engine(
			allow=["shell(nmap)", "target(169.254.169.254)"],
			deny=["target(169.254.169.254)"]
		)
		result = engine.check_action({"action": "shell", "command": "nmap 169.254.169.254"})
		self.assertEqual(result.decision, "deny")

	def test_default_deny_when_no_rules_match(self):
		engine = self._make_engine()
		result = engine.check_action({"action": "shell", "command": "nmap 10.0.0.1"})
		self.assertEqual(result.decision, "deny")


class TestTargetPrompt(unittest.TestCase):

	def test_build_target_choices_ip(self):
		choices = build_target_choices("10.5.2.3")
		self.assertEqual(len(choices), 5)  # 4 scope options + deny
		self.assertEqual(choices[0]["label"], "Allow 10.5.2.3 only (host only)")
		self.assertEqual(choices[0]["rules"], ["target(10.5.2.3)"])
		self.assertEqual(choices[-1]["label"], "Deny (block this action)")

	def test_build_target_choices_host(self):
		choices = build_target_choices("example.com")
		self.assertEqual(len(choices), 5)
		self.assertIn("example.com", choices[0]["label"])

	def test_build_target_choices_all_of_above(self):
		choices = build_target_choices("10.5.2.3")
		all_choice = choices[3]
		self.assertEqual(all_choice["label"], "All of the above")
		self.assertTrue(len(all_choice["rules"]) >= 3)


class TestPromptTarget(unittest.TestCase):

	def _make_engine(self, allow=None, deny=None, ask=None, targets=None, workspace="/tmp/workspace"):
		config = {
			"allow": allow or [],
			"deny": deny or [],
			"ask": ask or [],
		}
		return PermissionEngine(config, targets=targets or [], workspace=workspace)

	def test_prompt_target_non_interactive_returns_deny(self):
		engine = self._make_engine(ask=["target(*)"])
		result = engine.prompt_target("10.5.2.3", interactive=False)
		self.assertEqual(result, "deny")

	def test_prompt_target_adds_to_runtime_allow(self):
		engine = self._make_engine(allow=["shell(nmap)"], ask=["target(*)"])
		with patch.object(engine, '_show_target_menu', return_value=[0]):
			result = engine.prompt_target("10.5.2.3", interactive=True)
		self.assertEqual(result, "allow")
		check = engine.check_action({"action": "shell", "command": "nmap 10.5.2.3"})
		self.assertEqual(check.decision, "allow")

	def test_prompt_target_deny_choice(self):
		engine = self._make_engine(allow=["shell(nmap)"], ask=["target(*)"])
		with patch.object(engine, '_show_target_menu', return_value=[4]):
			result = engine.prompt_target("10.5.2.3", interactive=True)
		self.assertEqual(result, "deny")


class TestGuardrailsIntegration(unittest.TestCase):

	def _make_engine(self, allow=None, deny=None, ask=None, targets=None, workspace="/tmp/workspace"):
		config = {
			"allow": allow or [],
			"deny": deny or [],
			"ask": ask or [],
		}
		return PermissionEngine(config, targets=targets or [], workspace=workspace)

	def test_dispatch_action_with_denied_shell(self):
		"""Shell commands to denied targets should be blocked."""
		engine = self._make_engine(
			allow=["shell(curl)"],
			deny=["target(169.254.169.254)"]
		)
		ctx = ActionContext(
			targets=["example.com"], model="test", permission_engine=engine
		)
		action = {"action": "shell", "command": "curl http://169.254.169.254/latest/meta-data/"}
		results = list(dispatch_action(action, ctx))
		has_denial = any(
			isinstance(r, (Warning, Error)) and "denied" in getattr(r, 'message', '').lower()
			for r in results
		)
		self.assertTrue(has_denial, f"Expected denial message, got: {results}")

	def test_dispatch_action_without_engine(self):
		"""When no permission_engine is set, actions should pass through."""
		ctx = ActionContext(targets=["example.com"], model="test")
		action = {"action": "follow_up", "reason": "test"}
		results = list(dispatch_action(action, ctx))
		# follow_up should work normally without guardrails
		has_denial = any(
			isinstance(r, (Warning, Error)) and "denied" in getattr(r, 'message', '').lower()
			for r in results
		)
		self.assertFalse(has_denial)


if __name__ == '__main__':
	unittest.main()

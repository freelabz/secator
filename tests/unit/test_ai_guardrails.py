# tests/unit/test_ai_guardrails.py
import unittest

from secator.config import CONFIG
from secator.ai.guardrails import parse_rule, match_rule, detect_targets, detect_paths, classify_command


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


if __name__ == '__main__':
	unittest.main()

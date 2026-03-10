# tests/unit/test_ai_guardrails.py
import unittest

from secator.config import CONFIG


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


if __name__ == '__main__':
	unittest.main()

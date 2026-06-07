"""Unit tests for the `secator query` command and its dispatch helpers."""

import unittest


class TestLooksLikeQueryExpr(unittest.TestCase):

	def _check(self, value):
		from secator.cli import _looks_like_query_expr
		return _looks_like_query_expr(value)

	def test_expressions_are_detected(self):
		exprs = [
			"vulnerability.severity == 'high'",
			"vulnerability.severity_nb < 2",
			"port.port > 1000",
			"vulnerability.name ~= 'SQL'",
			"a == 1 && b == 2",
			"a == 1 || b == 2",
			"vulnerability.severity == 'high' and vulnerability.confidence == 'high'",
			"severity in ['high', 'critical']",
			"extra_data.published",
		]
		for expr in exprs:
			with self.subTest(expr=expr):
				self.assertTrue(self._check(expr))

	def test_natural_language_is_not_detected(self):
		phrases = [
			"Analyze my workspace data",
			"critical_vulns",
			"show me the most exploitable hosts",
			"",
		]
		for phrase in phrases:
			with self.subTest(phrase=phrase):
				self.assertFalse(self._check(phrase))

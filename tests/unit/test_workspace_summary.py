"""`secator workspace summary` — template-driven workspace findings summary.

The summary renders a Jinja2 template that calls a `query(...)` helper (same --format/--count/
--sort/--limit surface as `secator q`). The query helper is backend-agnostic (runs on fetched
findings), so a fake engine proves the behavior for every backend.
"""
import unittest

from jinja2 import Template

from secator.cli import DEFAULT_SUMMARY_TEMPLATE, _summary_query, workspace


class FakeEngine:
	def __init__(self, findings):
		self._findings = findings

	def search(self, query, limit=0, dedupe=False):
		return list(self._findings)


class TestSummaryQuery(unittest.TestCase):

	def test_count_fmt_produces_top_rows(self):
		findings = [
			{'_type': 'port', 'port': 443, 'ip': '1'},
			{'_type': 'port', 'port': 443, 'ip': '2'},
			{'_type': 'port', 'port': 80, 'ip': '3'},
		]
		out = _summary_query(FakeEngine(findings), 'port', fmt='port', count=True, limit=15)
		self.assertEqual(out, '2  443\n1  80')   # 443 x2 then 80 x1, most-frequent-first

	def test_empty_returns_none_marker(self):
		out = _summary_query(FakeEngine([]), 'vulnerability', fmt='status', count=True)
		self.assertEqual(out, '[dim](none)[/]')

	def test_row_values_are_markup_escaped(self):
		# A finding value with brackets must not corrupt the rendered rich markup.
		findings = [{'_type': 'vulnerability', 'name': 'CVE [test]', 'severity': 'high'}]
		out = _summary_query(FakeEngine(findings), 'vulnerability', fmt='name', count=True)
		self.assertIn(r'\[test]', out)          # escaped, not a live markup tag


class TestSummaryTemplate(unittest.TestCase):

	def test_default_template_renders_and_calls_query(self):
		calls = []

		def q(type_or_expr, **kwargs):
			calls.append(type_or_expr)
			return f'ROWS({type_or_expr})'

		out = Template(DEFAULT_SUMMARY_TEMPLATE).render(workspace='ws1', query=q, q=q)
		self.assertIn('Workspace summary — ws1', out)
		self.assertIn('Top ports', out)
		self.assertIn('ROWS(port)', out)
		self.assertIn('ROWS(vulnerability)', out)
		# every confirmed section type is queried
		for t in ('port', 'ip', 'subdomain', 'technology', 'url', 'vulnerability'):
			self.assertIn(t, calls)


class TestSummaryCommandWiring(unittest.TestCase):

	def test_summary_registered_with_options(self):
		self.assertIn('summary', workspace.commands)
		params = {p.name for p in workspace.commands['summary'].params}
		self.assertTrue({'workspace_opt', 'driver', 'template_path'} <= params)


if __name__ == '__main__':
	unittest.main()

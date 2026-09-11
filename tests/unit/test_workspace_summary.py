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

	def iterate(self, query, batch_size=1000):   # StreamView streams via iterate() (batches)
		yield list(self._findings)

	def count(self, query):
		return len(self._findings)

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

	def test_group_collapses_to_unique_before_count(self):
		# Same vuln (name) on two targets -> group by name collapses to ONE, so the severity count
		# reflects UNIQUE vulns (1 high), not instances (2). matched_at is the aggregate field.
		findings = [
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'a'},
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'b'},
			{'_type': 'vulnerability', 'name': 'SQLi', 'severity': 'critical', 'matched_at': 'c'},
		]
		grouped = _summary_query(FakeEngine(findings), 'vulnerability', group=True, fmt='severity', count=True)
		self.assertEqual(grouped, '1  high\n1  critical')     # unique: XSS counted once
		# Without group it counts instances (2 high) — proves group changes the result.
		ungrouped = _summary_query(FakeEngine(findings), 'vulnerability', fmt='severity', count=True)
		self.assertEqual(ungrouped, '2  high\n1  critical')

	def test_row_values_are_markup_escaped(self):
		# A finding value with brackets must not corrupt the rendered rich markup.
		findings = [{'_type': 'vulnerability', 'name': 'CVE [test]', 'severity': 'high'}]
		out = _summary_query(FakeEngine(findings), 'vulnerability', fmt='name', count=True)
		self.assertIn(r'\[test]', out)          # escaped, not a live markup tag


class RecordingEngine:
	"""Filters findings by the query's _type clause (top-level or $and-nested) and records the
	queries passed to iterate(), so tests can assert on the query shape (dedup nesting)."""
	def __init__(self, findings):
		self._f = findings
		self.queries = []

	def _type_of(self, q):
		if isinstance(q.get('_type'), str):
			return q['_type']
		for c in q.get('$and', []):
			if isinstance(c, dict) and isinstance(c.get('_type'), str):
				return c['_type']
		return None

	def _match(self, q):
		t = self._type_of(q)
		return [f for f in self._f if t is None or f.get('_type') == t]

	def iterate(self, query, batch_size=1000):
		self.queries.append(query)
		yield self._match(query)

	def count(self, query):
		return len(self._match(query))

	def search(self, *a, **k):
		raise AssertionError('summary must stream via iterate(), not search()')


class TestSummaryQueryShape(unittest.TestCase):

	def test_dedup_predicate_is_nested_never_top_level(self):
		# workspace_duplicate is a PROTECTED_FIELD stripped by _merge_query at the TOP level, so the
		# dedup predicate must always live inside an $and clause to survive.
		from unittest import mock
		from secator.cli import CONFIG
		eng = RecordingEngine([{'_type': 'port', 'port': 443, 'ip': '1'}])
		with mock.patch.object(CONFIG.runners, 'remove_duplicates', True):
			_summary_query(eng, 'port', fmt='port', count=True)
		self.assertTrue(eng.queries)
		for q in eng.queries:
			self.assertNotIn('_context.workspace_duplicate', q)   # never top-level (would be stripped)
			nested = any(isinstance(c, dict) and '_context.workspace_duplicate' in c for c in q.get('$and', []))
			self.assertTrue(nested)                               # present, nested -> survives _merge_query

	def test_multi_type_in_query_partitions_without_crashing(self):
		# `_type in [...]` previously TypeError'd (unhashable dict in the type-map lookup). Now it
		# partitions per concrete type and aggregates each.
		findings = [
			{'_type': 'port', 'port': 443, 'ip': '1'},
			{'_type': 'port', 'port': 80, 'ip': '2'},
			{'_type': 'url', 'url': 'http://a', 'host': 'a'},
		]
		out = _summary_query(RecordingEngine(findings), "_type in ['port','url']", fmt='port', count=True)
		self.assertIn('443', out)   # port bucket aggregated; no crash


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

	def test_summary_streams_via_iterate_not_search(self):
		# _summary_query must STREAM (iterate) and never materialize via search() -> bounded memory.
		class IterOnly:
			def __init__(self, f):
				self._f = f

			def iterate(self, query, batch_size=1000):
				yield list(self._f)

			def count(self, query):
				return len(self._f)

			def search(self, *a, **k):
				raise AssertionError('summary must stream via iterate(), not search()')

		findings = [
			{'_type': 'port', 'port': 443, 'ip': '1'},
			{'_type': 'port', 'port': 443, 'ip': '2'},
			{'_type': 'port', 'port': 80, 'ip': '3'},
		]
		out = _summary_query(IterOnly(findings), 'port', fmt='port', count=True)
		self.assertEqual(out, '2  443\n1  80')


if __name__ == '__main__':
	unittest.main()

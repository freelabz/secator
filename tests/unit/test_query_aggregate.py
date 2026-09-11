"""`secator q` --sort / --count / --uniq post-processing.

These run on the already-fetched, formatted results dict (after report.build + --format), so they
are backend-agnostic: json, sqlite, mongodb and api all feed the SAME `{type: [items]}` structure
into these helpers, so proving the helpers proves every backend. The user's target
`secator q port -f port --sort port --limit 15 --count` is the sort-then-count flow below.
"""
import unittest

from secator.cli import _aggregate_values, _sort_results_by_field


class TestSortResultsByField(unittest.TestCase):

	def test_numeric_sort_is_not_lexical(self):
		results = {'port': [{'port': 443}, {'port': 22}, {'port': 80}]}
		_sort_results_by_field(results, 'port')
		self.assertEqual([d['port'] for d in results['port']], [22, 80, 443])  # not ['22','443','80']

	def test_descending_prefix(self):
		results = {'port': [{'port': 22}, {'port': 443}, {'port': 80}]}
		_sort_results_by_field(results, '-port')
		self.assertEqual([d['port'] for d in results['port']], [443, 80, 22])

	def test_missing_values_sort_last(self):
		results = {'port': [{'port': 80}, {}, {'port': 22}]}
		_sort_results_by_field(results, 'port')
		self.assertEqual([d.get('port') for d in results['port']], [22, 80, None])

	def test_nested_dotted_field(self):
		results = {'x': [{'a': {'b': 3}}, {'a': {'b': 1}}]}
		_sort_results_by_field(results, 'a.b')
		self.assertEqual([d['a']['b'] for d in results['x']], [1, 3])

	def test_mixed_types_do_not_crash(self):
		results = {'x': [{'v': 5}, {'v': 'z'}, {'v': 1}]}
		_sort_results_by_field(results, 'v')  # falls back to string ordering, must not raise
		self.assertEqual(len(results['x']), 3)


class TestAggregateValues(unittest.TestCase):

	def test_count_most_frequent_first_by_default(self):
		results = {'port': ['443', '443', '80', '443', '80', '22']}
		out = _aggregate_values(results, count=True)
		self.assertEqual(out['port'], ['3  443', '2  80', '1  22'])  # top-N: count desc

	def test_count_keeps_value_order_when_sort_given(self):
		# findings already ordered by --sort -> keep that (value) order, don't re-sort by count.
		results = {'port': ['22', '443', '443', '80', '80', '80']}
		out = _aggregate_values(results, count=True, sort_given=True)
		self.assertEqual(out['port'], ['1  22', '2  443', '3  80'])

	def test_count_column_is_width_aligned(self):
		results = {'port': ['80'] * 12 + ['22']}   # counts 12 and 1 -> width 2
		out = _aggregate_values(results, count=True)
		self.assertEqual(out['port'], ['12  80', ' 1  22'])

	def test_uniq_dedupes_preserving_order(self):
		results = {'port': ['443', '80', '443', '22', '80']}
		out = _aggregate_values(results, uniq=True)
		self.assertEqual(out['port'], ['443', '80', '22'])

	def test_uniq_without_format_keeps_dicts_for_rich_render(self):
		# Raw finding dicts (no --format): --uniq keeps the DICTS (so they render richly, not as
		# str(dict)/JSON), deduped by their OutputType display string.
		results = {'vulnerability': [
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'a'},
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'a'},  # dup
			{'_type': 'vulnerability', 'name': 'SQLi', 'severity': 'critical', 'matched_at': 'b'},
		]}
		out = _aggregate_values(results, uniq=True)
		self.assertEqual(len(out['vulnerability']), 2)                       # deduped
		self.assertTrue(all(isinstance(x, dict) for x in out['vulnerability']))  # still dicts -> rich

	def test_count_without_format_renders_via_outputtype(self):
		# --count without --format tallies the OutputType display string, not str(dict).
		results = {'vulnerability': [
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'a'},
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'high', 'matched_at': 'a'},
		]}
		out = _aggregate_values(results, count=True)
		self.assertEqual(len(out['vulnerability']), 1)
		self.assertTrue(out['vulnerability'][0].startswith('2  '))           # "2  <rendered>"
		self.assertNotIn("{'_type'", out['vulnerability'][0])                # not a raw dict repr

	def test_cli_options_registered_on_both_commands(self):
		from secator.cli import query, report_show
		for cmd in (query, report_show):
			names = {p.name for p in cmd.params}
			self.assertTrue({'sort', 'count', 'uniq'} <= names, f'missing options on {cmd.name}: {names}')

	def test_sort_then_count_flow_matches_example(self):
		# The `-f port --sort port --count` path: sort findings by port, extract, count, keep order.
		results = {'port': [{'port': 443}, {'port': 22}, {'port': 443}, {'port': 80}, {'port': 443}, {'port': 80}]}
		_sort_results_by_field(results, 'port')
		formatted = {'port': [str(d['port']) for d in results['port']]}   # simulates -f port
		out = _aggregate_values(formatted, count=True, sort_given=True)
		self.assertEqual(out['port'], ['1  22', '2  80', '3  443'])   # by port asc, with counts


class TestGroupSortComposition(unittest.TestCase):
	"""--sort composes with --group: `--group name --sort -_group_count --limit N` = top-N groups
	by frequency (the ordering --group lacks on its own)."""

	def _vuln(self, name):
		return {'_type': 'vulnerability', 'name': name, 'matched_at': f'{name}-u', 'severity': 'info'}

	def test_sort_by_group_count_orders_groups_for_top_n(self):
		from secator.query.utils import group_findings
		# B is seen first, but A occurs more often -> -_group_count must rank A ahead of B.
		items = [self._vuln('B'), self._vuln('A'), self._vuln('A'), self._vuln('A'), self._vuln('B')]
		results = {'vulnerability': group_findings(items, ['name'], 'matched_at')}
		_sort_results_by_field(results, '-_group_count')
		ordered = [(r.name, r._group_count) for r in results['vulnerability']]
		self.assertEqual(ordered, [('A', 3), ('B', 2)])
		self.assertEqual(results['vulnerability'][0].name, 'A')  # --limit 1 -> top group


if __name__ == '__main__':
	unittest.main()

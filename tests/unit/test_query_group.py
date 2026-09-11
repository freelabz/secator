"""`--group` findings aggregation (query.utils.group_findings).

Groups findings of one type by one or more fields, collapsing each group to the newest finding,
which carries `_group_count` and (optionally) the distinct, truncated values of an aggregate field.
Backend-agnostic (runs on the fetched findings).
"""
import unittest

from secator.query.utils import group_findings


def _vuln(name, matched_at, ts=0, severity='info'):
	return {
		'_type': 'vulnerability', 'name': name, 'matched_at': matched_at,
		'severity': severity, '_timestamp': ts,
	}


class TestGroupFindings(unittest.TestCase):

	def test_groups_with_counts_in_first_seen_order(self):
		reps = group_findings([_vuln('A', 'u1'), _vuln('B', 'u2'), _vuln('A', 'u3')], ['name'])
		self.assertEqual([r.name for r in reps], ['A', 'B'])          # first-seen order
		self.assertEqual({r.name: r._group_count for r in reps}, {'A': 2, 'B': 1})

	def test_representative_is_the_newest_finding(self):
		old = _vuln('A', 'u1', ts=1, severity='low')
		new = _vuln('A', 'u2', ts=9, severity='high')
		reps = group_findings([old, new], ['name'], aggregate_field='matched_at')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 2)
		self.assertEqual(reps[0].severity, 'high')                   # newest wins for other fields

	def test_aggregate_collects_distinct_values(self):
		reps = group_findings([_vuln('A', 'u1'), _vuln('A', 'u2'), _vuln('A', 'u1')], ['name'], 'matched_at')
		self.assertEqual(reps[0].matched_at, 'u1, u2')               # distinct, first-seen

	def test_aggregate_truncates_past_max_display(self):
		items = [_vuln('A', f'u{i}') for i in range(7)]
		reps = group_findings(items, ['name'], 'matched_at', max_display=5)
		self.assertIn('.. and 2 more', reps[0].matched_at)           # 7 values, 5 shown

	def test_composite_group_by(self):
		items = [_vuln('A', 'u1'), _vuln('A', 'u1'), _vuln('A', 'u2')]
		reps = group_findings(items, ['name', 'matched_at'])          # (A,u1)x2, (A,u2)x1
		self.assertEqual(sorted(r._group_count for r in reps), [1, 2])

	def test_matched_at_aggregated_across_targets(self):
		# The core use case: one vulnerability hitting many targets collapses to a single row whose
		# matched_at lists all its targets.
		items = [_vuln('XSS', 'a'), _vuln('XSS', 'b'), _vuln('XSS', 'c')]
		reps = group_findings(items, ['name'], aggregate_field='matched_at')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 3)
		self.assertEqual(sorted(reps[0].matched_at.split(', ')), ['a', 'b', 'c'])

	def test_per_type_group_defaults(self):
		# Each type's default group field + aggregate field (used by the `--group` flag).
		from secator.output_types import Vulnerability, Exploit, Port, Url, Subdomain, Tag, Technology
		self.assertEqual((tuple(Vulnerability._group_by), Vulnerability._group_aggregate), (('name',), 'matched_at'))
		self.assertEqual((tuple(Exploit._group_by), Exploit._group_aggregate), (('name',), 'matched_at'))
		self.assertEqual((tuple(Port._group_by), Port._group_aggregate), (('host',), 'port'))
		self.assertEqual((tuple(Url._group_by), Url._group_aggregate), (('host',), 'url'))
		self.assertEqual((tuple(Subdomain._group_by), Subdomain._group_aggregate), (('domain',), 'host'))
		self.assertEqual((tuple(Tag._group_by), Tag._group_aggregate), (('category', 'name'), 'match'))
		self.assertEqual((tuple(Technology._group_by), Technology._group_aggregate), (('product',), 'match'))


if __name__ == '__main__':
	unittest.main()

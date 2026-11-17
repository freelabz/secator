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


class TestGroupFindingsRawDicts(unittest.TestCase):
	"""group_findings must produce identical results whether it receives raw dicts (the fast
	path used by --group via StreamView.iter_raw) or pre-rehydrated OutputType objects."""

	def test_dict_input_produces_same_groups_as_object_input(self):
		"""Raw dicts → group_findings → same representative count and fields as the rehydrated path."""
		from secator.output_types import Vulnerability
		dicts = [_vuln('XSS', 'a', ts=1), _vuln('XSS', 'b', ts=3), _vuln('SQLi', 'c', ts=2)]
		objects = [Vulnerability.load(d) for d in dicts]

		reps_dict = group_findings(dicts, ['name'], aggregate_field='matched_at')
		reps_obj = group_findings(objects, ['name'], aggregate_field='matched_at')

		self.assertEqual(len(reps_dict), len(reps_obj))
		self.assertEqual([r.name for r in reps_dict], [r.name for r in reps_obj])
		for rd, ro in zip(reps_dict, reps_obj):
			self.assertEqual(rd._group_count, ro._group_count)
			self.assertEqual(rd.matched_at, ro.matched_at)

	def test_dict_representative_is_newest(self):
		"""With raw dict input the newest finding (highest _timestamp) wins as representative."""
		old = _vuln('A', 'u1', ts=1, severity='low')
		new = _vuln('A', 'u2', ts=9, severity='high')
		reps = group_findings([old, new], ['name'], aggregate_field='matched_at')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0].severity, 'high')   # newest rep field
		self.assertEqual(reps[0]._group_count, 2)


class TestGroupFindingsDefaults(unittest.TestCase):
	"""Raw-dict grouping must fill absent group-by fields with the OutputType dataclass
	default (what rehydration does) so it groups identically to the object path.

	Regression: a stored tag omitting `category` must group with a tag whose
	`category` is explicitly the `general` default, not form a separate `None` group.
	"""

	def _tag(self, name, match, category=None, ts=0):
		d = {'_type': 'tag', 'name': name, 'value': name, 'match': match, '_timestamp': ts}
		if category is not None:
			d['category'] = category
		return d

	def test_missing_category_groups_with_default(self):
		from secator.output_types import Tag
		defaults = Tag.field_defaults()
		self.assertEqual(defaults.get('category'), 'general')

		# One tag omits category (stored dict), one sets it to the 'general' default.
		dicts = [self._tag('T', 'a', category=None, ts=1), self._tag('T', 'b', category='general', ts=2)]
		objects = [Tag.load(d) for d in dicts]

		reps_dict = group_findings(dicts, ['category', 'name'], aggregate_field='match', defaults=defaults)
		reps_obj = group_findings(objects, ['category', 'name'], aggregate_field='match')

		# Object path collapses to a single 'general' group; raw path must match.
		self.assertEqual(len(reps_obj), 1)
		self.assertEqual(len(reps_dict), len(reps_obj))
		self.assertEqual(reps_dict[0]._group_count, reps_obj[0]._group_count)
		self.assertEqual(reps_dict[0].category, reps_obj[0].category)
		self.assertEqual(sorted(reps_dict[0].match.split(', ')), sorted(reps_obj[0].match.split(', ')))

	def test_without_defaults_missing_field_splits_groups(self):
		# Documents the bug the defaults map fixes: no defaults -> None vs 'general' split.
		dicts = [self._tag('T', 'a', category=None, ts=1), self._tag('T', 'b', category='general', ts=2)]
		reps = group_findings(dicts, ['category', 'name'], aggregate_field='match')
		self.assertEqual(len(reps), 2)


class TestStreamViewIterRaw(unittest.TestCase):
	"""StreamView.iter_raw() yields the raw backend dicts without rehydration."""

	def _make_sv(self, records):
		"""Build a StreamView backed by a minimal in-memory engine."""
		class _FakeEngine:
			def iterate(self, query, batch_size):
				# yield all records in one batch (limit ignored for simplicity)
				yield list(records)

			def count(self, query):
				return len(records)

		from secator.query._stream import StreamView
		return StreamView(_FakeEngine(), {})

	def test_iter_raw_yields_dicts(self):
		raw = [_vuln('A', 'u1'), _vuln('B', 'u2')]
		sv = self._make_sv(raw)
		result = list(sv.iter_raw())
		self.assertEqual(result, raw)
		for item in result:
			self.assertIsInstance(item, dict)

	def test_iter_raw_respects_limit(self):
		raw = [_vuln('A', f'u{i}') for i in range(10)]

		class _FakeEngine:
			def iterate(self, query, batch_size):
				yield list(raw)

			def count(self, query):
				return len(raw)

		from secator.query._stream import StreamView
		sv = StreamView(_FakeEngine(), {}, limit=3)
		result = list(sv.iter_raw())
		self.assertEqual(len(result), 3)

	def test_group_findings_via_iter_raw_matches_normal_path(self):
		"""End-to-end: iter_raw() fed into group_findings() produces the same grouped output."""
		raw = [_vuln('XSS', 'a', ts=1), _vuln('XSS', 'b', ts=2), _vuln('SQLi', 'c', ts=1)]
		sv = self._make_sv(raw)

		reps = group_findings(list(sv.iter_raw()), ['name'], aggregate_field='matched_at')
		names = [r.name for r in reps]
		self.assertEqual(sorted(names), ['SQLi', 'XSS'])
		xss = next(r for r in reps if r.name == 'XSS')
		self.assertEqual(xss._group_count, 2)
		self.assertIn('a', xss.matched_at)
		self.assertIn('b', xss.matched_at)


if __name__ == '__main__':
	unittest.main()


def _tag(name, match, ts=None, category='info'):
	doc = {'_type': 'tag', 'category': category, 'name': name, 'value': match, 'match': match}
	if ts is not ...:
		doc['_timestamp'] = ts
	return doc


class TestGroupFindingsMixedTimestamps(unittest.TestCase):
	"""Stores can hold `_timestamp` as a float, a numeric string, an ISO string, a datetime, or
	nothing at all. Ordering within a group must not compare those raw values (TypeError)."""

	def test_missing_then_numeric_string_does_not_crash(self):
		# The original crash: rep has no timestamp (-> 0), next item has a string timestamp.
		no_ts = _tag('traceroute', 'a', ts=...)
		str_ts = _tag('traceroute', 'b', ts='1700000000.5')
		reps = group_findings([no_ts, str_ts], ['category', 'name'], aggregate_field='match')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 2)
		self.assertEqual(reps[0].value, 'b')  # the string timestamp is the newest

	def test_int_str_empty_none_mixed(self):
		items = [
			_tag('t', 'int', ts=1000),
			_tag('t', 'str', ts='3000'),
			_tag('t', 'empty', ts=''),
			_tag('t', 'none', ts=None),
			_tag('t', 'missing', ts=...),
			_tag('t', 'float', ts=2000.5),
		]
		reps = group_findings(items, ['category', 'name'])
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 6)
		self.assertEqual(reps[0].value, 'str')

	def test_iso_and_datetime_timestamps_order_by_time(self):
		from datetime import datetime, timezone
		items = [
			_tag('t', 'iso_z', ts='2026-01-02T00:00:00Z'),
			_tag('t', 'dt', ts=datetime(2026, 1, 3, tzinfo=timezone.utc)),
			_tag('t', 'epoch', ts=datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()),
			_tag('t', 'garbage', ts='not a date'),
		]
		self.assertEqual(group_findings(items, ['name'])[0].value, 'dt')
		self.assertEqual(group_findings(items[:1] + items[2:], ['name'])[0].value, 'iso_z')

	def test_output_type_objects_with_string_timestamp(self):
		from secator.output_types import Tag
		old = Tag(name='t', value='old', match='x', _timestamp=10)
		new = Tag(name='t', value='new', match='y', _timestamp='20')
		reps = group_findings([old, new], ['category', 'name'])
		self.assertEqual(reps[0].value, 'new')


class TestFindingTs(unittest.TestCase):

	def test_coercion(self):
		from datetime import datetime, timezone
		from secator.query.utils import _finding_ts
		epoch = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
		cases = [
			({'_timestamp': 5}, 5.0),
			({'_timestamp': 5.5}, 5.5),
			({'_timestamp': '5.5'}, 5.5),
			({'_timestamp': ' 7 '}, 7.0),
			({'_timestamp': '2026-01-01T00:00:00Z'}, epoch),
			({'_timestamp': '2026-01-01T00:00:00+00:00'}, epoch),
			({'_timestamp': '2026-01-01T00:00:00'}, epoch),  # naive -> UTC
			({'_timestamp': datetime(2026, 1, 1)}, epoch),
			({'_timestamp': ''}, 0.0),
			({'_timestamp': None}, 0.0),
			({'_timestamp': 'nan'}, 0.0),
			({'_timestamp': 'garbage'}, 0.0),
			({'_timestamp': True}, 0.0),
			({'_timestamp': [1]}, 0.0),
			({}, 0.0),
		]
		for item, expected in cases:
			with self.subTest(item=item):
				self.assertEqual(_finding_ts(item), expected)

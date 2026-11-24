"""Output equivalence for the json store's read shortcuts and the --group aggregation.

- ``JsonBackend._iter_latest`` skips ndjson lines that cannot match a ``_type`` / ``_uuid``
equality without parsing them, and only re-parses each finding's latest line in pass 2. Its
results must stay identical to a plain "parse everything, keep the latest record per _uuid,
then match" reference, including with update records, records without a _uuid, blank and torn
lines, and records written with or without spaces.
- ``group_findings`` dedups aggregated values with an ordered set; the output must match the
original list-based implementation.
- ``secator workspace list`` counts runs from the fixed-depth report layout.
"""
import json
import random
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import orjson
from click.testing import CliRunner

from secator.query.json import JsonBackend, _line_needles, match_query
from secator.query.utils import _finding_ts, _finding_value, _truncate_aggregate, group_findings

TYPES = ['url', 'port', 'vulnerability', 'tag', 'subdomain', 'info']


def _random_record(rng, uid, _type=None):
	_type = _type or rng.choice(TYPES)
	rec = {
		'_type': _type,
		'_uuid': uid,
		'_timestamp': rng.randint(0, 50),
		'host': rng.choice(['a.com', 'b.com', 'c.com']),
		'status': rng.choice(['OPEN', 'FIXED']),
		'name': rng.choice(['x', 'y', 'url', 'port']),  # type names as values: prefilter false positives
	}
	if _type == 'url':
		rec['url'] = f'https://{rec["host"]}/{rng.randint(0, 5)}'
	return rec


def _write_store(rng, path, n):
	"""Write an append-only store: findings, update records (same _uuid appended later, fields
	changed), records without a _uuid, blank lines, mixed JSON spacing and a torn final line."""
	records = [_random_record(rng, f'{path.parent.parent.name}-{path.parent.name}-{i}') for i in range(n)]
	lines = []
	for rec in records:
		lines.append(rec)
		if rng.random() < 0.3:  # an update record for an earlier finding
			old = rng.choice(records[:records.index(rec) + 1])
			lines.append({**old, 'status': rng.choice(['OPEN', 'FIXED']), '_timestamp': old['_timestamp'] + 1})
		if rng.random() < 0.05:
			no_uid = _random_record(rng, None)
			del no_uid['_uuid']
			lines.append(no_uid)
		if rng.random() < 0.05:
			lines.append(b'')
	with open(path, 'wb') as f:
		for line in lines:
			if isinstance(line, bytes):
				f.write(line + b'\n')
			elif rng.random() < 0.5:
				f.write(orjson.dumps(line) + b'\n')
			else:
				f.write(json.dumps(line).encode() + b'\n')  # '"_type": "url"' (with spaces)
		f.write(b'{"_type": "url", "_uuid": "torn')  # torn final line after a crash


def _reference(reports_dir, workspace, query):
	"""The plain reference: parse every line, keep each _uuid's latest record (at its position),
	then match; first runner dir read wins on a _uuid seen in several dirs."""
	out, seen = [], set()
	ws = Path(reports_dir) / workspace
	for runner_type in ['tasks', 'workflows', 'scans']:
		if not (ws / runner_type).exists():
			continue
		for d in (ws / runner_type).iterdir():
			parsed = []
			for line in (d / 'results.ndjson').read_bytes().splitlines():
				try:
					parsed.append(orjson.loads(line))
				except orjson.JSONDecodeError:
					continue
			latest = {r['_uuid']: i for i, r in enumerate(parsed) if r.get('_uuid')}
			for i, rec in enumerate(parsed):
				uid = rec.get('_uuid')
				if uid and latest[uid] != i:
					continue
				rec.setdefault('_context', {})[f'{runner_type[:-1]}_id'] = d.name
				if not match_query(rec, query):
					continue
				if uid:
					if uid in seen:
						continue
					seen.add(uid)
				out.append(rec)
	return out


class TestLineNeedles(unittest.TestCase):

	def test_type_and_uuid_equalities(self):
		self.assertEqual(_line_needles({'_type': 'url'}), [b'"url"'])
		self.assertEqual(_line_needles({'_uuid': 'abc', 'host': 'x'}), [b'"abc"'])

	def test_and_branches_all_apply(self):
		query = {'$and': [{'_type': {'$nin': ['target']}}, {'_type': 'port'}], 'host': 'x'}
		self.assertEqual(_line_needles(query), [b'"port"'])
		self.assertEqual(_line_needles({'$and': [{'_type': 'url'}, {'_type': 'port'}]}), [b'"url"', b'"port"'])

	def test_no_prefilter_without_an_equality(self):
		for query in ({}, {'_type': {'$in': ['url']}}, {'$or': [{'_type': 'url'}]}, {'_type': {'$nin': ['url']}}):
			self.assertEqual(_line_needles(query), [], query)


class TestIterLatestEquivalence(unittest.TestCase):

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)
		rng = random.Random(1234)
		for runner_type in ['tasks', 'workflows', 'scans']:
			for n in range(4):
				d = self.tmp / 'ws' / runner_type / str(n)
				d.mkdir(parents=True)
				_write_store(rng, d / 'results.ndjson', rng.randint(0, 60))
		self.backend = JsonBackend('ws', config={'reports_dir': str(self.tmp)})
		self.uuids = [r['_uuid'] for r in _reference(self.tmp, 'ws', {}) if r.get('_uuid')]

	def _assert_same(self, query):
		got = list(self.backend._iter_latest(query))
		self.assertEqual(got, _reference(self.tmp, 'ws', query), query)
		self.assertEqual(self.backend._execute_count(query), len(got))
		return got

	def test_per_type_reads(self):
		total = 0
		for _type in TYPES + ['target']:
			total += len(self._assert_same({'_type': _type}))
			self._assert_same({'_type': _type, 'status': 'OPEN'})
			self._assert_same({'$and': [{'_type': {'$nin': ['target', 'ai']}}, {'_type': _type}]})
		self.assertEqual(total, len(self._assert_same({})))

	def test_multi_type_reads(self):
		# `_type: {$in: [...]}` (one read for several types) skips lines naming none of the types
		for query in ({'_type': {'$in': ['url', 'tag']}},
				{'$and': [{'_type': {'$nin': ['target']}}, {'_type': {'$in': ['port', 'info']}}], 'status': 'OPEN'},
				{'_type': {'$in': ['nope']}}):
			self._assert_same(query)

	def test_conflicting_types_match_nothing(self):
		self.assertEqual(self._assert_same({'$and': [{'_type': 'url'}, {'_type': 'port'}]}), [])

	def test_point_reads(self):
		for uid in random.Random(5).sample(self.uuids, 20):
			self.assertEqual(len(self._assert_same({'_uuid': uid})), 1)

	def test_unconstrained_reads(self):
		or_query = {'$or': [{'_type': 'tag'}, {'host': 'a.com'}]}
		for query in ({}, {'status': 'FIXED'}, {'_type': {'$in': ['url', 'port']}}, or_query):
			self._assert_same(query)

	def test_legacy_report_json(self):
		d = self.tmp / 'legacy' / 'tasks' / '0'
		d.mkdir(parents=True)
		results = {'url': [_random_record(random.Random(i), f'l{i}', 'url') for i in range(5)]}
		results['url'].append({**results['url'][0], 'status': 'UPDATED'})
		(d / 'report.json').write_text(json.dumps({'info': {}, 'results': results}))
		backend = JsonBackend('legacy', config={'reports_dir': str(self.tmp)})
		got = list(backend._iter_latest({'_type': 'url'}))
		self.assertEqual([r['_uuid'] for r in got], ['l1', 'l2', 'l3', 'l4', 'l0'])
		self.assertEqual(got[-1]['status'], 'UPDATED')


def _group_findings_reference(items, group_by, aggregate_field=None, max_display=5, defaults=None):
	"""The list-based grouping (before aggregated values were kept in an ordered set)."""
	groups, order = {}, []
	for item in items:
		key = tuple(str(_finding_value(item, f, defaults)) for f in group_by)
		if key not in groups:
			groups[key] = {'rep': item, 'agg': [], 'count': 0}
			order.append(key)
		group = groups[key]
		group['count'] += 1
		if _finding_ts(item) >= _finding_ts(group['rep']):
			group['rep'] = item
		if aggregate_field:
			value = _finding_value(item, aggregate_field)
			if value and value not in group['agg']:
				group['agg'].append(value)
	return [(key, groups[key]['rep'], groups[key]['count'],
			_truncate_aggregate(groups[key]['agg'], max_display) if aggregate_field else None) for key in order]


class TestGroupFindingsEquivalence(unittest.TestCase):

	def test_matches_list_based_reference(self):
		rng = random.Random(7)
		for _ in range(20):
			items = [{
				'_type': 'url', 'host': rng.choice(['a', 'b', 'c', 'd']),
				'url': rng.choice([f'https://x/{i}' for i in range(30)] + ['']),
				'_timestamp': rng.randint(0, 5), '_uuid': str(i),
			} for i in range(rng.randint(0, 300))]
			max_display = rng.choice([2, 5, 100])
			expected = _group_findings_reference(items, ['host'], 'url', max_display)
			reps = group_findings(items, ['host'], 'url', max_display)
			self.assertEqual(len(reps), len(expected))
			for rep, (_, exp_rep, exp_count, exp_agg) in zip(reps, expected):
				self.assertEqual(rep._uuid, exp_rep['_uuid'])  # same (newest, last-seen on ties) representative
				self.assertEqual(rep._group_count, exp_count)
				self.assertEqual(rep.url, exp_agg)

	def test_unhashable_aggregate_values(self):
		items = [{'_type': 'tag', 'name': 'n', 'category': 'c', 'match': m, 'value': 'v', '_timestamp': 0}
				for m in (['a'], ['a'], ['b'], 'a')]
		expected = _group_findings_reference(items, ['category', 'name'], 'match')
		reps = group_findings(items, ['category', 'name'], 'match')
		self.assertEqual(reps[0].match, expected[0][3])
		self.assertEqual(reps[0]._group_count, 4)


class TestAggregateStreamedNoCount(unittest.TestCase):

	def test_ungrouped_type_is_read_without_a_count_query(self):
		from secator.query.aggregate import _aggregate_streamed
		from secator.query._stream import StreamView

		class _Engine:
			def iterate(self, query, batch_size):
				yield [{'_type': 'ip', 'ip': '1.2.3.4', 'host': 'h', '_uuid': 'x'}]

			def count(self, query):
				raise AssertionError('count() must not be called to read a stream')

		rows = _aggregate_streamed(StreamView(_Engine(), {}), 'ip', None, sort='ip', group=True)
		self.assertEqual([r.ip for r in rows], ['1.2.3.4'])


class TestWorkspaceListCounts(unittest.TestCase):

	def test_counts_runs_without_walking_artifacts(self):
		from secator.cli import cli
		from secator.config import CONFIG
		tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, tmp, True)
		for ws, runs in (('alpha', 3), ('beta', 1)):
			for n in range(runs):
				d = tmp / ws / 'tasks' / str(n)
				(d / '.outputs' / 'x').mkdir(parents=True)
				(d / 'report.json').write_text('{}')
				(d / '.outputs' / 'x' / 'report.json').write_text('{}')  # an artifact, not a run
		(tmp / 'empty').mkdir()
		with mock.patch.object(CONFIG.dirs, 'reports', tmp):
			result = CliRunner().invoke(cli, ['workspace', 'list', '--driver', 'local'], env={'COLUMNS': '400'})
		self.assertEqual(result.exit_code, 0, result.output)
		output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)  # the console may force colors
		counts = {line.split('│')[1].strip(): line.split('│')[2].strip() for line in output.splitlines()
				if line.startswith('│')}
		self.assertEqual(counts, {'alpha': '3', 'beta': '1', 'empty': '0'})


if __name__ == '__main__':
	unittest.main()

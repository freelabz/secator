"""`secator q --group/--sort/--count/--uniq` reads only the finding types the query can match.

The aggregating path streams one view per type (``Report.build(stream=True)``). On the json
store every query is a full read of every report file, so:

- a type the query cannot match is not queried at all (``query_possible_types``, derived
conservatively from the compiled query: ``&&`` intersects, ``||`` unites, anything not
analysable keeps every type);
- on the json store, the remaining types are read in ONE pass and split by ``_type``.

Results must be identical to the unoptimised path (every type queried, one query per type), on
the json and sqlite backends, for typed, multi-type and untyped queries.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import orjson
from click.testing import CliRunner

from secator.output_types import FINDING_TYPES
from secator.query import QueryEngine
from secator.query.json import JsonBackend
from secator.query.utils import python_expr_to_mongo, query_possible_types

WS = 'stream_types_ws'
ALL_TYPES = [c.get_name() for c in FINDING_TYPES] + ['target']
UNTYPED = [t for t in ALL_TYPES if t not in ('target', 'ai')]  # `q` hides target/ai without a type filter


def _records():
	ctx = {'workspace_id': WS, 'workspace_name': WS, 'workspace_duplicate': False}
	recs = []
	n = 0

	def add(_type, **fields):
		nonlocal n
		n += 1
		recs.append({'_type': _type, '_uuid': f'u{n:04d}', '_timestamp': float(n), '_context': dict(ctx),
			'is_false_positive': False, **fields})

	for i in range(12):
		add('technology', product=('nginx', 'apache', 'php')[i % 3], version=str(i % 4), match=f'https://h{i % 5}/')
	for i in range(10):
		add('vulnerability', name=('CVE-2026-20484', 'XSS', 'SQLi')[i % 3], id=('CVE-2026-20484', '', '')[i % 3],
			severity=('high', 'low')[i % 2], matched_at=f'https://h{i % 4}/')
	for i in range(10):
		add('url', url=f'https://h{i % 3}/p{i}', host=f'h{i % 3}', status_code=(200, 301, 404)[i % 3])
	for i in range(8):
		add('port', port=(80, 443, 22)[i % 3], ip='10.0.0.1', host=f'h{i % 2}')
	for i in range(4):
		add('tag', name=f't{i % 2}', value='v', match=f'https://h{i}/', category='info')
	for i in range(3):
		add('ip', ip=f'10.0.0.{i}', host=f'h{i}')
	add('subdomain', host='a.h0', domain='h0')
	add('domain', domain='h0')
	add('record', name='h0', type='A', host='h0')
	add('target', name='h0', type='host')
	add('ai', content='thinking', ai_type='response')
	# store-side duplicates (hidden when runners.remove_duplicates is on); equal timestamps (group ties)
	for rec in recs[1:40:7]:
		rec['_context']['workspace_duplicate'] = True
	for rec in recs[0:12:4]:
		rec['_timestamp'] = 1.0
	return recs


def _updates(recs):
	"""Later records of existing findings (same _uuid, appended after): the latest one wins."""
	by_type = {}
	for rec in recs:
		by_type.setdefault(rec['_type'], []).append(rec)
	return [
		{**by_type['technology'][0], 'product': 'php', '_timestamp': 99.0},
		{**by_type['vulnerability'][1], 'id': 'CVE-2026-20484', 'severity': 'high', '_timestamp': 98.0},
		{**by_type['url'][2], 'status_code': 404, '_timestamp': 97.0},
	]


def _types_of(query):
	"""The `_type` values a backend query was narrowed to (one per-type view, or a union pass)."""
	clause = query['$and'][-1] if '$and' in query and set(query['$and'][-1]) == {'_type'} else query
	value = clause.get('_type')
	return [value] if isinstance(value, str) else list(value.get('$in', []))


def _normalize(results):
	"""Comparable form of report.data['results'] after aggregation."""
	out = {}
	for name, rows in results.items():
		norm = []
		for row in rows:
			if hasattr(row, 'toDict'):
				norm.append(('obj', json.dumps(row.toDict(), sort_keys=True, default=str), getattr(row, '_group_count', None)))
			elif isinstance(row, dict):
				norm.append(('dict', json.dumps(row, sort_keys=True, default=str)))
			else:
				norm.append(('str', str(row)))
		out[name] = norm
	return out


# (expression or None, extra flags, types the query can match)
CASES = [
	('technology', ['--group'], ['technology']),
	('technology', ['--count', '-f', '{product}'], ['technology']),
	('technology', ['--sort', 'product'], ['technology']),
	('technology', ['--uniq', '-f', '{product}'], ['technology']),
	("technology.product ~= 'nginx' || vulnerability.id == 'CVE-2026-20484'", ['--group'],
		['vulnerability', 'technology']),
	("technology.product ~= 'nginx' || vulnerability.id == 'CVE-2026-20484'", ['--sort', 'name'],
		['vulnerability', 'technology']),
	("technology.product ~= 'nginx' && technology.version == '1'", ['--count', '-f', '{product}'], ['technology']),
	("technology.product == 'nginx' && vulnerability.name == 'XSS'", ['--group'], []),
	('url.status_code in [200, 301]', ['--count', '-f', '{url}'], ['url']),
	('port.port not in [80]', ['--uniq', '-f', '{port}'], ['port']),
	("vulnerability.name !~= 'XSS'", ['--group'], ['vulnerability']),
	("technology.product != 'nginx'", ['--group'], ['technology']),
	("_type != 'url'", ['--count', '-f', '{_type}'], [t for t in ALL_TYPES if t != 'url']),
	("_type not in ['url', 'port']", ['--group'], [t for t in ALL_TYPES if t not in ('url', 'port')]),
	("_type in ['url', 'port'] || technology", ['--group'], ['port', 'url', 'technology']),
	("_type ~= 'tech'", ['--group'], ALL_TYPES),
	# a `_type` inside the `||` counts as a type constraint, so `q` keeps target/ai too
	("technology.product ~= 'nginx' || severity == 'high'", ['--group'], ALL_TYPES),
	("severity == 'high'", ['--group'], UNTYPED),
	(None, ['--group'], UNTYPED),
	(None, ['--count', '-f', '{_type}'], UNTYPED),
	(None, ['--uniq', '-f', '{_type}'], UNTYPED),
	(None, ['--sort', '_timestamp'], UNTYPED),
	(None, ['--sort', '_timestamp', '-f', '{_type}'], UNTYPED),
	(None, ['--group', '--limit', '2'], UNTYPED),
]


class TestQueryPossibleTypes(unittest.TestCase):
	"""The type set is derived from the query compiled by the real `secator q` expression parser."""

	def test_expressions(self):
		for expr, _flags, expected in CASES:
			if expr is None:
				continue
			# `q` adds the target/ai exclusion to a query without a type constraint; the bare
			# expression keeps every type.
			expected = ALL_TYPES if expected is UNTYPED else expected
			with self.subTest(expr=expr):
				self.assertEqual(sorted(query_possible_types(python_expr_to_mongo(expr), ALL_TYPES)), sorted(expected))

	def test_operators(self):
		cases = [
			({}, ALL_TYPES),
			({'_type': 'url'}, ['url']),
			({'_type': 'nope'}, []),
			({'_type': {'$in': ['url', 'port']}}, ['port', 'url']),
			({'_type': {'$nin': ['url', None], '$exists': True}}, [t for t in ALL_TYPES if t != 'url']),
			({'_type': {'$ne': 'url'}}, [t for t in ALL_TYPES if t != 'url']),
			({'_type': {'$in': ['url', 'port'], '$nin': ['port']}}, ['url']),
			({'$and': [{'_type': {'$nin': ['target', 'ai']}}, {'_type': 'url'}]}, ['url']),
			({'$and': [{'_type': {'$nin': ['url']}}, {'_type': 'url'}]}, []),
			({'$or': [{'_type': 'url'}, {'$and': [{'_type': 'port'}, {'port': 80}]}]}, ['port', 'url']),
			({'$or': [{'_type': 'url'}, {'host': 'x'}]}, ALL_TYPES),
			({'_type': 'url', '$or': [{'_type': 'port'}, {'_type': 'url'}]}, ['url']),
			# not analysed -> every type kept
			({'_type': {'$regex': 'u'}}, ALL_TYPES),
			({'_type': {'$not': {'$eq': 'url'}}}, ALL_TYPES),
			({'_type': {'$eq': 'url'}}, ALL_TYPES),  # the json matcher has no $eq: not narrowed
			({'_type': ['url']}, ALL_TYPES),
			({'$nor': [{'_type': 'url'}]}, ALL_TYPES),
			({'$or': []}, ALL_TYPES),
			('not a query', ALL_TYPES),
		]
		for query, expected in cases:
			with self.subTest(query=query):
				self.assertEqual(sorted(query_possible_types(query, ALL_TYPES)), sorted(expected))

	def test_keeps_universe_order(self):
		self.assertEqual(query_possible_types({'_type': {'$in': ['url', 'port']}}, ['url', 'port']), ['url', 'port'])
		self.assertEqual(query_possible_types({'_type': {'$in': ['url', 'port']}}, ['port', 'url']), ['port', 'url'])


class _QueryCliBase:
	driver = None

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)
		recs = _records()
		self.write_store(recs, _updates(recs))

	def _invoke(self, expr, flags, optimised=True, dedupe=False):
		"""Run `secator q` and return (normalized results, [types of each backend iterate])."""
		from secator.cli import cli
		captured, calls = {}, []
		orig_iterate = QueryEngine.iterate

		def iterate(engine, query, batch_size=1000):
			calls.append(sorted(_types_of(query)))
			yield from orig_iterate(engine, query, batch_size)

		def send(report):
			captured['results'] = report.data['results']

		args = ['q'] + ([expr] if expr else []) + ['-w', WS, '--driver', self.driver] + flags
		patches = [
			mock.patch('secator.query.json.CONFIG'),
			mock.patch('secator.cli.CONFIG'),
			mock.patch('secator.report.Report.send', send),
			mock.patch.object(QueryEngine, 'iterate', iterate),
		]
		if not optimised:
			patches += [
				mock.patch('secator.query.utils.query_possible_types', lambda query, universe: list(universe)),
				mock.patch.object(JsonBackend, 'scan_per_query', False),
			]
		with patches[0] as json_cfg, patches[1] as cli_cfg, patches[2], patches[3]:
			json_cfg.dirs.reports = self.tmp
			cli_cfg.dirs.reports = self.tmp
			cli_cfg.workspaces.current = None
			cli_cfg.runners.remove_duplicates = dedupe
			cli_cfg.queries = {}
			for p in patches[4:]:
				p.start()
			try:
				result = CliRunner().invoke(cli, args)
			finally:
				for p in patches[4:]:
					p.stop()
		self.assertIsNone(result.exception, f'{args}: {result.exception!r}\n{result.output}')
		return _normalize(captured['results']), calls

	def test_same_results_and_only_matching_types_read(self):
		for (expr, flags, expected), dedupe in [(case, d) for case in CASES for d in (False, True)]:
			with self.subTest(expr=expr, flags=flags, dedupe=dedupe):
				got, calls = self._invoke(expr, flags, dedupe=dedupe)
				ref, ref_calls = self._invoke(expr, flags, optimised=False, dedupe=dedupe)
				self.assertEqual(got, ref)
				self.assertEqual(len(ref_calls), len(ALL_TYPES))  # unoptimised: one read per type
				scanned = sorted(t for call in calls for t in call)
				self.assertEqual(scanned, sorted(expected))      # each matching type read exactly once
				self.assert_reads(calls, expected, flags)
		# the fixture is not trivially empty for the cases above
		got, _ = self._invoke('technology', ['--group'])
		self.assertEqual(len(got['technology']), 3)


class TestQueryCliJson(_QueryCliBase, unittest.TestCase):
	driver = 'local'

	def write_store(self, recs, updates):
		lines = {i: list(recs[i::3]) for i in range(3)}  # several runner stores: a pass reads them all
		for upd in updates:  # appended to the store holding the finding
			lines[next(i for i in lines if any(r['_uuid'] == upd['_uuid'] for r in lines[i]))].append(upd)
		lines[2].append({**lines[0][3], 'status_code': 999})  # same _uuid in two stores: first one read wins
		for i, store in lines.items():
			d = self.tmp / WS / 'tasks' / str(i)
			d.mkdir(parents=True)
			with open(d / 'results.ndjson', 'wb') as f:
				for rec in store:
					f.write(orjson.dumps(rec) + b'\n')

	def assert_reads(self, calls, expected, flags):
		materializing = '--sort' in flags and not ({'--count', '--uniq', '--group'} & set(flags))
		if len(expected) <= 1 or (materializing and ({'-f', '--limit'} & set(flags))):
			self.assertEqual(len(calls), len(expected))   # one read per type (or none)
		elif {'-f', '--limit'} & set(flags) and '--group' in flags:
			# types without a group key materialize -> own read when --format/--limit; the rest share one
			self.assertGreater(len(calls), 1)
			self.assertLess(len(calls), len(expected))
		else:
			self.assertEqual(len(calls), 1)               # all types in ONE read, split by _type


class TestQueryCliSqlite(_QueryCliBase, unittest.TestCase):
	driver = 'sqlite'

	def write_store(self, recs, updates):
		recs = list({r['_uuid']: r for r in recs + updates}.values())  # one row per finding, latest data
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		self.sqlite_mod = sqlite_mod
		orig = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(self.tmp / 'test.db')
		sqlite_mod._conns.clear()

		def restore():
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = orig
		self.addCleanup(restore)
		conn = sqlite_mod.get_sqlite_conn()
		for rec in recs:
			conn.execute(
				'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) VALUES (?, ?, ?, 0, 0, ?)',
				(rec['_uuid'], rec['_type'], WS, json.dumps(rec)))
		conn.commit()

	def assert_reads(self, calls, expected, flags):
		self.assertEqual(len(calls), len(expected))   # indexed backend: one query per matching type


class TestSummaryQueryTypes(unittest.TestCase):
	"""The workspace summary `query()` reads the same type set; an explicit list keeps its order."""

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)
		TestQueryCliJson.write_store(self, _records(), [])

	def _rows(self, expr, **kwargs):
		from secator.cli import _summary_query
		calls = []
		orig_iterate = QueryEngine.iterate

		def iterate(engine, query, batch_size=1000):
			calls.append((query['$and'][0] if '$and' in query else query)['_type'])  # the per-type clause
			yield from orig_iterate(engine, query, batch_size)

		json_cfg_patch, cli_cfg_patch = mock.patch('secator.query.json.CONFIG'), mock.patch('secator.cli.CONFIG')
		with json_cfg_patch as json_cfg, cli_cfg_patch as cli_cfg, mock.patch.object(QueryEngine, 'iterate', iterate):
			json_cfg.dirs.reports = self.tmp
			cli_cfg.runners.remove_duplicates = False
			engine = QueryEngine(WS, context={'drivers': [], 'workspace_name': WS})
			rows = _summary_query(engine, expr, **kwargs)
		return rows.splitlines(), calls

	def test_explicit_type_list_keeps_order_and_non_finding_types(self):
		rows, calls = self._rows("_type in ['target', 'port']", fmt='{_type}', uniq=True)
		self.assertEqual(rows, ['target', 'port'])
		self.assertEqual(calls, ['target', 'port'])

	def test_multi_type_or_and_negation(self):
		expr = "technology.product ~= 'nginx' || vulnerability.id == 'CVE-2026-20484'"
		rows, calls = self._rows(expr, fmt='{_type}', count=True)
		self.assertEqual(sorted(calls), ['technology', 'vulnerability'])
		self.assertEqual(len(rows), 2)
		rows, calls = self._rows("_type != 'url'", fmt='{_type}', uniq=True)
		self.assertNotIn('url', rows)  # the type exclusion is honoured (it used to be dropped)
		self.assertNotIn('url', calls)


if __name__ == '__main__':
	unittest.main()

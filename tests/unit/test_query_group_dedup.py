"""`secator q --group` collapses the copies of one finding stored by several runs, on every backend.

A workspace accumulates one copy of a finding per run that reports it. `--group` used to collapse only
the types declaring a `_group_by` (port, url, technology, ...): every other type (domain, record, ip,
certificate, user_account, ai) was passed through as-is, so the same SOA record or the same domain
was listed once per run. Those types now collapse on their equality fields (`compare=True`, the
identity duplicate tagging uses), and a domain collapses on its name.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from secator.output_types import FINDING_TYPES, Domain, Ip, Record

WS = 'ws_group'


def _ctx(**extra):
	return {'workspace_id': WS, **extra}


def _domain(alive, ts, source='whois'):
	return {
		'_type': 'domain', 'domain': 'example.com', 'alive': alive, 'registrar': 'Example Registrar',
		'extra_data': {'name_servers': ['ns1.example.com', 'ns2.example.com']},
		'_source': source, '_timestamp': ts, '_context': _ctx(),
	}


def _record(rtype, ts, name='ns1.example.com'):
	return {
		'_type': 'record', 'name': name, 'type': rtype, 'host': 'example.com',
		'_source': 'dnsx', '_timestamp': ts, '_context': _ctx(),
	}


def _ip(ip, ts):
	return {'_type': 'ip', 'ip': ip, 'host': 'example.com', 'alive': True, '_timestamp': ts, '_context': _ctx()}


# The same domain, SOA and AXFR record and ip, each stored by three runs (alive toggles between runs).
DOCS = (
	[_domain(alive=a, ts=t) for a, t in ((True, 1), (False, 2), (True, 3))]
	+ [_record('SOA', t) for t in (1, 2, 3)]
	+ [_record('AXFR', t) for t in (1, 2, 3)]
	+ [_ip('192.0.2.1', t) for t in (1, 2, 3)]
)


class TestGroupKeys(unittest.TestCase):

	def test_declared_group_by_wins(self):
		from secator.output_types import Port, Technology
		self.assertEqual(Port.group_keys(), ('host',))
		self.assertEqual(Technology.group_keys(), ('product',))

	def test_domain_groups_by_name(self):
		# `alive` is an equality field, so the equality key alone would keep alive and not-alive
		# copies of the same domain apart.
		self.assertEqual(Domain.group_keys(), ('domain',))

	def test_types_without_group_by_fall_back_to_equality_fields(self):
		self.assertEqual(Record.group_keys(), ('name', 'type', 'host'))
		self.assertEqual(Ip.group_keys(), ('ip', 'alive', 'protocol'))

	def test_every_finding_type_is_groupable(self):
		for cls in FINDING_TYPES:
			with self.subTest(type=cls.get_name()):
				self.assertTrue(cls.group_keys())
				self.assertNotIn('_type', cls.group_keys())


class _FakeView:
	def __init__(self, docs):
		self.docs = docs

	def iter_raw(self):
		return iter([dict(d) for d in self.docs])

	def __iter__(self):
		from secator.output_types._base import load_output_types
		return iter(load_output_types([dict(d) for d in self.docs]))


class TestAggregateStreamedGroup(unittest.TestCase):

	def _group(self, _type):
		from secator.cli import _aggregate_streamed
		cls = {c.get_name(): c for c in FINDING_TYPES}[_type]
		return _aggregate_streamed(_FakeView([d for d in DOCS if d['_type'] == _type]), _type, cls, group=True)

	def test_records_collapse_per_name_type_host(self):
		reps = self._group('record')
		self.assertEqual(sorted(r.type for r in reps), ['AXFR', 'SOA'])
		self.assertEqual([r._group_count for r in reps], [3, 3])

	def test_domain_collapses_despite_alive_toggling(self):
		reps = self._group('domain')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 3)
		self.assertIs(reps[0].alive, True)  # the newest copy is the representative

	def test_ip_collapses(self):
		reps = self._group('ip')
		self.assertEqual(len(reps), 1)
		self.assertEqual(reps[0]._group_count, 3)

	def test_without_group_nothing_collapses(self):
		from secator.cli import _aggregate_streamed
		rows = _aggregate_streamed(_FakeView([d for d in DOCS if d['_type'] == 'record']), 'record', Record, sort='type')
		self.assertEqual(len(rows), 6)


# --------------------------------------------------------------------------------------------------
# End to end: `secator q` on the four backends, seeded with the same documents.
# --------------------------------------------------------------------------------------------------

class _FakeCursor:
	def __init__(self, docs):
		self.docs = docs

	def skip(self, n):
		return _FakeCursor(self.docs[n:]) if n else self

	def limit(self, n):
		return _FakeCursor(self.docs[:n]) if n else self

	def batch_size(self, _):
		return self

	def __iter__(self):
		return iter([dict(d) for d in self.docs])


class _FakeMongo:
	"""A findings collection that applies the query the way Mongo would (json backend matcher)."""

	def __init__(self, docs):
		from secator.query.json import match_query
		self.docs, self.match, self.queries = docs, match_query, []
		self.main = self
		self.findings = self

	def find(self, query, *args, **kwargs):
		self.queries.append(query)
		return _FakeCursor([d for d in self.docs if self.match(d, query)])

	def count_documents(self, query):
		return len([d for d in self.docs if self.match(d, query)])


class BackendHarness:
	"""Seeds DOCS into one backend and runs `secator q` against it, capturing the report results."""

	BACKENDS = ('local', 'sqlite', 'mongodb', 'api')

	def __init__(self, test, backend, docs):
		self.test, self.backend, self.docs = test, backend, [json.loads(json.dumps(d)) for d in docs]
		self.queries = []

	def __enter__(self):
		from secator.config import CONFIG
		self.tmp = tempfile.mkdtemp()
		self.stack = []
		self._set(CONFIG.dirs, 'reports', Path(self.tmp))
		self._set(CONFIG.workspaces, 'current', WS)
		self._set(CONFIG.runners, 'remove_duplicates', False)
		getattr(self, f'_seed_{self.backend}')()
		return self

	def __exit__(self, *exc):
		for undo in reversed(self.stack):
			undo()
		shutil.rmtree(self.tmp, ignore_errors=True)

	def _set(self, obj, attr, value):
		old = getattr(obj, attr)
		setattr(obj, attr, value)
		self.stack.append(lambda: setattr(obj, attr, old))

	def _patch(self, *args, **kwargs):
		p = mock.patch(*args, **kwargs)
		p.start()
		self.stack.append(p.stop)

	def _seed_local(self):
		task_dir = Path(self.tmp) / WS / 'tasks' / '1'
		task_dir.mkdir(parents=True)
		results = {}
		for d in self.docs:
			results.setdefault(d['_type'], []).append(d)
		(task_dir / 'report.json').write_text(json.dumps({'info': {'name': 't'}, 'results': results}))

	def _seed_sqlite(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		self._set(CONFIG.addons.sqlite, 'path', str(Path(self.tmp) / 'q.db'))
		sqlite_mod._conns.clear()

		def _close():
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
		self.stack.append(_close)
		conn = sqlite_mod.get_sqlite_conn()
		for i, d in enumerate(self.docs):
			conn.execute(
				'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) VALUES (?, ?, ?, 0, 0, ?)',
				(f'u{i}', d['_type'], WS, json.dumps(d)))
		conn.commit()

	def _seed_mongodb(self):
		fake = _FakeMongo(self.docs)
		self.queries = fake.queries
		self._patch('secator.query.mongodb.MongoDBBackend._get_client', return_value=fake)

	def _seed_api(self):
		from tests.unit.test_query_backend_parity import FakeApiStore
		store = FakeApiStore(self.docs)
		self.queries = store.queries
		self._patch('secator.query.api.ApiBackend._make_request', side_effect=store)
		self._patch('secator.hooks.api.resolve_workspace', return_value=(WS, WS))

	def query(self, *args):
		from secator.cli import cli
		captured = {}

		def capture_send(report_self):
			captured.update({k: list(v) for k, v in report_self.data['results'].items()})

		with mock.patch('secator.report.Report.send', capture_send):
			result = CliRunner().invoke(cli, ['q', *args, '--driver', self.backend, '-ws', WS])
		self.test.assertIsNone(result.exception, f'{self.backend}: {result.output}')
		return captured


def _rows(results, _type):
	"""(identity, group count) per row, so backends can be compared."""
	out = []
	for r in results.get(_type, []):
		get = r.get if isinstance(r, dict) else (lambda k, r=r: getattr(r, k, None))
		key = get('domain') if _type == 'domain' else (get('name'), get('type')) if _type == 'record' else get('ip')
		out.append((str(key), getattr(r, '_group_count', None)))
	return sorted(out)


class TestQueryGroupParity(unittest.TestCase):

	def test_group_collapses_copies_on_every_backend(self):
		expected = {
			'domain': [('example.com', 3)],
			'record': [("('ns1.example.com', 'AXFR')", 3), ("('ns1.example.com', 'SOA')", 3)],
			'ip': [('192.0.2.1', 3)],
		}
		for backend in BackendHarness.BACKENDS:
			with self.subTest(backend=backend), BackendHarness(self, backend, DOCS) as h:
				results = h.query('--group')
				for _type, rows in expected.items():
					self.assertEqual(_rows(results, _type), rows, f'{backend} {_type}')


# --------------------------------------------------------------------------------------------------
# `secator q` hides workspace duplicates by default; `--include-duplicates` shows them.
# --------------------------------------------------------------------------------------------------

def _flag(doc, duplicate):
	doc = json.loads(json.dumps(doc))
	if duplicate is not None:
		doc['_context']['workspace_duplicate'] = duplicate
	doc['_tagged'] = duplicate is not None
	return doc


# Tagged copies: one main + two duplicates per finding. The AXFR record was never tagged (no flag)
# and must always show.
TAGGED_DOCS = (
	[_flag(_domain(alive=True, ts=t), dup) for t, dup in ((3, False), (1, True), (2, True))]
	+ [_flag(_record('SOA', t), dup) for t, dup in ((3, False), (1, True), (2, True))]
	+ [_flag(_record('AXFR', 1), None)]
)


def _count(results, _type):
	return len(results.get(_type, []))


class TestQueryExcludesWorkspaceDuplicates(unittest.TestCase):

	def _each_backend(self):
		for backend in BackendHarness.BACKENDS:
			with self.subTest(backend=backend), BackendHarness(self, backend, TAGGED_DOCS) as h:
				yield backend, h

	def test_duplicates_hidden_by_default(self):
		for backend, h in self._each_backend():
			results = h.query()
			self.assertEqual(_count(results, 'domain'), 1, backend)
			self.assertEqual(sorted(r['type'] for r in results['record']), ['AXFR', 'SOA'], backend)
			for items in results.values():
				for item in items:
					self.assertFalse(item['_context'].get('workspace_duplicate'), backend)

	def test_include_duplicates_shows_them(self):
		for backend, h in self._each_backend():
			results = h.query('--include-duplicates')
			self.assertEqual(_count(results, 'domain'), 3, backend)
			self.assertEqual(_count(results, 'record'), 4, backend)

	def test_group_counts_only_non_duplicates(self):
		for backend, h in self._each_backend():
			self.assertEqual(_rows(h.query('--group'), 'domain'), [('example.com', 1)], backend)
			self.assertEqual(_rows(h.query('--group', '--include-duplicates'), 'domain'), [('example.com', 3)], backend)

	def test_limit_counts_non_duplicates(self):
		# A raw page of 2 would hold a duplicate; the 2 results returned are both non-duplicates.
		for backend, h in self._each_backend():
			results = h.query('record', '--limit', '2')
			self.assertEqual(sorted(r['type'] for r in results['record']), ['AXFR', 'SOA'], backend)

	def test_filter_reaches_the_store_query_where_null_safe(self):
		for backend, h in self._each_backend():
			h.query('domain')
			if backend in ('mongodb', 'api'):
				self.assertTrue(h.queries)
				self.assertTrue(all('workspace_duplicate' in json.dumps(q) for q in h.queries), backend)
			h.queries.clear()
			h.query('domain', '--include-duplicates')
			self.assertFalse(any('workspace_duplicate' in json.dumps(q) for q in h.queries), backend)

	def test_report_show_is_unchanged(self):
		# Only `secator q` hides duplicates: `secator r show` keeps listing every copy.
		from secator.cli import cli
		for backend, h in self._each_backend():
			captured = {}

			def capture_send(report_self):
				captured.update({k: list(v) for k, v in report_self.data['results'].items()})

			with mock.patch('secator.report.Report.send', capture_send):
				CliRunner().invoke(cli, ['r', 'show', '--driver', backend, '-w', WS])
			self.assertEqual(_count(captured, 'domain'), 3, backend)


class TestRunnerQueriesUnchanged(unittest.TestCase):
	"""The exclusion lives in the `secator q` command only: the backends' enforced base query and
	the queries a runner's report issues never filter on the workspace duplicate flag."""

	def test_base_query_has_no_duplicate_filter(self):
		from secator.query.api import ApiBackend
		from secator.query.json import JsonBackend
		from secator.query.mongodb import MongoDBBackend
		from secator.query.sqlite import SqliteBackend
		expected = {'_context.workspace_id': WS, 'is_false_positive': {'$ne': True}}
		for cls in (ApiBackend, MongoDBBackend, SqliteBackend):
			with self.subTest(backend=cls.name):
				self.assertEqual(cls(workspace_id=WS).get_base_query(), expected)
				self.assertNotIn('workspace_duplicate', json.dumps(cls(workspace_id=WS)._merge_query({'_type': 'port'})))
		self.assertEqual(JsonBackend(WS).get_base_query(), {})

	def test_runner_report_queries_have_no_duplicate_filter(self):
		from dotmap import DotMap
		from secator.query import QueryEngine
		from secator.report import Report
		seen = []
		runner = DotMap({
			'config': DotMap({'name': 'host_recon', 'type': 'workflow'}), 'name': 'host_recon',
			'workspace_name': WS, 'errors': [], 'warnings': [], 'reports_folder': None,
			'context': {'workspace_id': WS, 'workspace_name': WS, 'workflow_id': 'wf1', 'drivers': ['mongodb']},
		})
		runner.toDict = lambda: {'name': 'host_recon', 'status': 'completed', 'targets': [], 'results_count': 0}
		search = mock.patch.object(QueryEngine, 'search', side_effect=lambda q, **kw: seen.append(q) or [])
		iterate = mock.patch.object(QueryEngine, 'iterate', side_effect=lambda q, *a: seen.append(q) or iter(()))
		with search, iterate:
			Report(runner).build(query={}, dedupe=False)
			report = Report(runner)
			report.build(query={}, dedupe=False, stream=True)
			for sv in report.data['results'].values():
				list(sv)
		self.assertTrue(seen)
		self.assertFalse(any('workspace_duplicate' in json.dumps(q) for q in seen))

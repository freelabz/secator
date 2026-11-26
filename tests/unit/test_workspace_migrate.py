"""`secator workspace migrate`: copy a local workspace to the sqlite, mongodb (mongomock) and api
(mocked HTTP) drivers through their own hooks, then check the copy is complete, relinked and
idempotent."""
import json
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import orjson
import pytest

mongomock = pytest.importorskip('mongomock')

from bson import ObjectId  # noqa: E402
from click.testing import CliRunner  # noqa: E402

from secator.config import CONFIG  # noqa: E402
from secator.query import QueryEngine  # noqa: E402
from secator.workspace_migrate import WorkspaceMigration  # noqa: E402

WS, COPY = 'acme', 'acme-copy'
T0 = 1767225600.0  # 2026-01-01T00:00:00Z

# ids of the source workspace
SCAN, WF, HTTPX, NMAP = 'scan-1', 'wf-1', 'task-httpx', 'task-nmap'
CHAT_A, CHAT_B, CMD, CMD_CHUNK = 'chat-a', 'chat-b', 'task-cmd', 'chunk-cmd'


def _runner(name, rtype, ctx, status='SUCCESS', done=True, has_parent=False, start=T0, **extra):
	return {'info': {
		'name': name, 'status': status, 'done': done, 'targets': ['example.com'], 'has_parent': has_parent,
		'start_time': f'2026-01-01T00:{int(start - T0) // 60:02d}:00+00:00', 'end_time': None, 'elapsed': 1,
		'last_updated_db': start, 'run_opts': {}, 'config': {'type': rtype, 'name': name},
		'context': {'workspace_id': WS, 'workspace_name': WS, **ctx}, **extra}, 'results': {}}


def _finding(uuid, _type, ctx, ts=T0, **fields):
	return {'_type': _type, '_uuid': uuid, '_timestamp': ts, '_source': fields.pop('_source', 'httpx'),
			'_context': {'workspace_id': WS, 'workspace_name': WS, **ctx}, **fields}


def build_workspace(reports):
	"""A local workspace reproducing the edge cases a migration must handle."""
	ws = Path(reports) / WS

	def write(rel, data):
		path = ws / rel
		path.parent.mkdir(parents=True, exist_ok=True)
		if rel.endswith('.ndjson'):
			path.write_bytes(b''.join(orjson.dumps(r) + b'\n' for r in data))
		else:
			path.write_text(json.dumps(data))

	# A scan with a child workflow and task. The url is updated by an appended newer record, and
	# has a duplicate (linked by `_related`).
	scan_ctx = {'scan_id': SCAN}
	wf_ctx = {**scan_ctx, 'workflow_id': WF}
	httpx_ctx = {**wf_ctx, 'task_id': HTTPX}
	write('scans/0/report.json', _runner('host_recon', 'scan', scan_ctx))
	write('scans/0/report_url_crawl.json', _runner('url_crawl', 'workflow', wf_ctx, has_parent=True))
	write('scans/0/report_url_crawl_httpx.json', _runner('httpx', 'task', httpx_ctx, has_parent=True))
	write('scans/0/results.ndjson', [
		_finding('u-dup', 'url', httpx_ctx, ts=T0 - 1, url='https://example.com/login', _duplicate=True),
		_finding('u-url', 'url', httpx_ctx, url='https://example.com/login', status_code=0, _related=['u-dup']),
		_finding('u-port', 'port', httpx_ctx, ip='192.0.2.10', port=443),
		_finding('u-url', 'url', httpx_ctx, url='https://example.com/login', status_code=200, _related=['u-dup']),
	])
	# The same runner stored twice: a stale child copy and its finished copy.
	nmap_ctx = {'task_id': NMAP}
	write('tasks/0/report.json', _runner('nmap', 'task', nmap_ctx))
	write('tasks/0/results.ndjson', [_finding('u-ip', 'ip', nmap_ctx, ip='192.0.2.20', _source='nmap')])
	write('tasks/1/report_nmap.json', _runner('nmap', 'task', nmap_ctx, status='RUNNING', done=False, has_parent=True))
	# Chat A reused tasks/2, then chat B overwrote its report.json (B is left RUNNING). Chat A
	# also ran a command child, stored in its own dir.
	a_ctx = {'task_id': CHAT_A, 'session_id': CHAT_A}
	b_ctx = {'task_id': CHAT_B, 'session_id': CHAT_B}
	cmd_ctx = {'task_id': CMD, 'task_chunk_id': CMD_CHUNK, 'session_id': CHAT_A}
	write('tasks/2/report.json', _runner('ai', 'task', b_ctx, status='RUNNING', done=False, start=T0 + 600))
	write('tasks/2/results.ndjson', [
		_finding('a-prompt', 'ai', a_ctx, ts=T0 + 60, _source='ai', content='check example.com', ai_type='prompt',
				model='m-1'),
		_finding('a-map', 'ai', a_ctx, ts=T0 + 61, _source='ai', content='', ai_type='pii_map',
				extra_data={'[HOST_1]': 'example.com'}),
		_finding('a-cmd', 'ai', cmd_ctx, ts=T0 + 62, _source='ai', content='ran curl', ai_type='response'),
		_finding('a-reply', 'ai', a_ctx, ts=T0 + 120, _source='ai', content='done', ai_type='response'),
		_finding('b-prompt', 'ai', b_ctx, ts=T0 + 600, _source='ai', content='again', ai_type='prompt'),
	])
	write('tasks/3/report_command.json', _runner('command', 'task', cmd_ctx, has_parent=True, start=T0 + 62))
	write('notes.ndjson', [
		{'target_type': 'url', 'target_key': {'url': 'https://example.com/login'}, 'body': 'login form',
			'author_id': 'ai', 'created_at': '2026-01-01T00:05:00+00:00', '_context': {'workspace_id': WS}},
		{'target_type': 'ip', 'target_key': {'ip': '192.0.2.20'}, 'body': 'gateway', 'author_id': 'ai',
			'created_at': '2026-01-01T00:06:00+00:00', '_context': {'workspace_id': WS}},
	])


SOURCE_COUNTS = {
	'scans': 1, 'workflows': 1, 'tasks': 5, 'notes': 2,
	'findings: ai': 5, 'findings: ip': 1, 'findings: port': 1, 'findings: url': 2,
}


def _bulk_write(collection, ops, **kwargs):
	for op in ops:
		collection.update_one(op._filter, op._doc)


class FakeApi:
	"""The api driver's remote store over mongomock. It drops the runner context keys it does not
	know, here the migration marker."""

	def __init__(self):
		self.db = mongomock.MongoClient().main
		self.workspaces = []

	def __call__(self, method, endpoint, data=None):
		path, _, qs = endpoint.partition('?')
		params = dict(p.split('=', 1) for p in qs.split('&') if p)
		data = json.loads(json.dumps(data, default=str)) if data is not None else None
		if path == 'workspaces':
			if method == 'POST':
				self.workspaces.append({'_id': str(ObjectId()), 'name': data['name']})
				return self.workspaces[-1]
			return self.workspaces
		if path.startswith('workspace/'):
			return next(w for w in self.workspaces if w['_id'] == path.split('/')[1])
		if path in ('runners', 'findings', 'notes') and method == 'POST':
			oid = ObjectId()
			coll = f'{data["config"]["type"]}s' if path == 'runners' else path
			if path == 'runners':
				key = data['config']['type'] + ('_chunk_id' if data.get('chunk') else '_id')
				data['context'][key] = str(oid)
				data['context'].pop('migrated_from', None)
			self.db[coll].insert_one({**data, '_id': oid})
			return {'id': str(oid)}
		if path.startswith('runner/') and method == 'PUT':
			oid = ObjectId(path.split('/')[1])
			coll = f'{data["config"]["type"]}s'
			old = self.db[coll].find_one({'_id': oid})
			for k in ('task_id', 'task_chunk_id', 'workflow_id', 'scan_id'):
				data['context'][k] = old['context'].get(k)
			data['context'].pop('migrated_from', None)
			self.db[coll].replace_one({'_id': oid}, data)
			return {}
		if path.startswith('finding/') and method == 'PUT':
			self.db.findings.update_one({'_id': ObjectId(path.split('/')[1])}, {'$set': data})
			return {}
		if path == 'findings/_search':
			docs = list(self.db.findings.find(data or {}).skip(int(params.get('skip', 0))))
			return {'items': [{**d, '_id': str(d['_id'])} for d in docs]}
		if path == 'runners/any':
			ws = params.get('workspace_id')
			out = []
			for coll in ('tasks', 'workflows', 'scans'):
				out += [{**d, '_id': str(d['_id'])} for d in self.db[coll].find({'context.workspace_id': ws})]
			return out
		raise AssertionError(f'unexpected request {method} {endpoint}')


class _MigrateCase(unittest.TestCase):
	dst = None

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp)
		reports = self.tmp / 'reports'
		build_workspace(reports)
		self._patch(mock.patch.object(CONFIG.dirs, 'reports', reports))
		self.mongo = mongomock.MongoClient()
		# mongomock's bulk_write does not take the UpdateOne of recent pymongo versions.
		self._patch(mock.patch.object(mongomock.collection.Collection, 'bulk_write', _bulk_write))
		self._patch(mock.patch('secator.hooks.mongodb.get_mongodb_client', return_value=self.mongo))
		self._patch(mock.patch('secator.query.mongodb.MongoDBBackend._get_client', return_value=self.mongo))
		self._patch(mock.patch.object(CONFIG.addons.sqlite, 'path', str(self.tmp / 'test.db')))
		self.addCleanup(self._close_sqlite)
		self.api = FakeApi()
		self._patch(mock.patch('secator.hooks.api._make_request', side_effect=self.api))
		self._patch(mock.patch('secator.query.api.ApiBackend._make_request', side_effect=self.api))
		import secator.hooks.api as api_hooks
		api_hooks.resolve_workspace.cache_clear()
		self.addCleanup(api_hooks.resolve_workspace.cache_clear)

	def _patch(self, patcher):
		patcher.start()
		self.addCleanup(patcher.stop)

	@staticmethod
	def _close_sqlite():
		import secator.hooks.sqlite as sqlite_mod
		for conn in sqlite_mod._conns.values():
			conn.close()
		sqlite_mod._conns.clear()

	def migrate(self, **kwargs):
		migration = WorkspaceMigration(WS, 'local', self.dst, new_name=COPY, **kwargs)
		migration.apply()
		return migration

	def engine(self):
		ws_id = WorkspaceMigration(WS, 'local', self.dst, new_name=COPY).dst_ws
		return QueryEngine(ws_id, context={'drivers': [] if self.dst == 'local' else [self.dst], 'workspace_name': COPY})

	def findings(self):
		return {r['_context']['migrated_from']: r for r in self.engine().search({}, scope_only=True, include_internal=True)}

	def runners(self):
		engine = self.engine()
		return {r['context']['migrated_from']: r for r in engine.list_runners(workspace_id=engine.workspace_id)}


class MigrateToSqlite(_MigrateCase):
	dst = 'sqlite'

	def test_dry_run_writes_nothing(self):
		migration = WorkspaceMigration(WS, 'local', self.dst, new_name=COPY)
		plan = {kind: (n, new, old) for kind, n, new, old in migration.plan()}
		self.assertEqual({k: v[0] for k, v in plan.items()}, SOURCE_COUNTS)
		self.assertTrue(all(old == 0 for _, _, old in plan.values()))
		self.assertEqual(self.findings(), {})
		self.assertEqual(self.runners(), {})

	def test_copy_counts(self):
		migration = self.migrate()
		self.assertEqual(dict(migration.destination_counts()), SOURCE_COUNTS)

	def test_latest_record_wins(self):
		self.migrate()
		self.assertEqual(self.findings()['u-url']['status_code'], 200)

	def test_duplicate_runner_keeps_finished_copy(self):
		self.migrate()
		nmap = self.runners()[NMAP]
		self.assertEqual((nmap['status'], nmap['done'], nmap['has_parent']), ('SUCCESS', True, False))

	def test_overwritten_chat_rebuilt_from_findings(self):
		self.migrate()
		chat = self.runners()[CHAT_A]
		self.assertEqual((chat['name'], chat['status'], chat['done']), ('ai', 'SUCCESS', True))
		self.assertEqual(chat['run_opts'], {'prompt': 'check example.com', 'model': 'm-1'})

	def test_stale_running_marked_failure(self):
		self.migrate()
		self.assertEqual(self.runners()[CHAT_B]['status'], 'FAILURE')

	def test_keep_status(self):
		self.migrate(keep_status=True)
		self.assertEqual(self.runners()[CHAT_B]['status'], 'RUNNING')

	def test_pii_map_migrated_and_internal(self):
		self.migrate()
		self.assertEqual(self.findings()['a-map']['extra_data'], {'[HOST_1]': 'example.com'})
		self.assertNotIn('a-map', [r['_context']['migrated_from'] for r in self.engine().search({})])

	def test_ids_relinked(self):
		self.migrate()
		findings, runners = self.findings(), self.runners()
		self.assertIn(findings['u-dup']['_uuid'], findings['u-url']['_related'])
		chat_id = runners[CHAT_A]['context']['task_id']
		self.assertNotEqual(chat_id, CHAT_A)
		for doc in (findings['a-prompt'], findings['a-cmd'], findings['a-map']):
			self.assertEqual(doc['_context']['session_id'], chat_id)
		self.assertEqual(runners[CMD_CHUNK]['context']['session_id'], chat_id)
		self.assertEqual(findings['a-cmd']['_context']['task_chunk_id'], runners[CMD_CHUNK]['context']['task_chunk_id'])
		httpx = runners[HTTPX]['context']
		self.assertEqual(httpx['scan_id'], runners[SCAN]['context']['scan_id'])
		self.assertEqual(httpx['workflow_id'], runners[WF]['context']['workflow_id'])
		self.assertEqual(findings['u-url']['_context']['task_id'], httpx['task_id'])
		for doc in list(findings.values()) + list(runners.values()):
			ctx = doc.get('_context') or doc.get('context')
			self.assertEqual((ctx['workspace_id'], ctx['workspace_name']), (self.engine().workspace_id, COPY))

	def test_rerun_is_idempotent(self):
		self.migrate()
		first = {k: v['_uuid'] for k, v in self.findings().items()}
		migration = self.migrate()
		self.assertTrue(all(old == n for _, n, _, old in migration.plan()))
		self.assertEqual(dict(migration.destination_counts()), SOURCE_COUNTS)
		self.assertEqual({k: v['_uuid'] for k, v in self.findings().items()}, first)

	def test_finding_without_runner_skipped(self):
		path = Path(CONFIG.dirs.reports) / WS / 'tasks' / '0' / 'results.ndjson'
		with open(path, 'ab') as f:
			f.write(orjson.dumps(_finding('u-lost', 'ip', {'task_id': 'gone'}, ip='192.0.2.30')) + b'\n')
		migration = self.migrate()
		self.assertEqual(migration.failed, 1)
		self.assertNotIn('u-lost', self.findings())

	def test_runner_write_failure_skips_its_findings(self):
		def fail_nmap(run):
			if run.name == 'nmap':
				raise RuntimeError('store down')
		hooks = {cls: {**ev, 'on_end': [fail_nmap, *ev['on_end']]} for cls, ev in self._hooks().items()}
		with mock.patch('secator.workspace_migrate.import_dynamic', side_effect=lambda p, n: hooks if n == 'HOOKS' else None):
			migration = self.migrate()
		self.assertNotIn(NMAP, self.runners())
		self.assertNotIn('u-ip', self.findings())
		self.assertEqual(migration.failed, 2)

	def _hooks(self):
		from secator.utils import import_dynamic
		return import_dynamic(f'secator.hooks.{self.dst}', 'HOOKS')

	def test_notes(self):
		self.migrate()
		notes = self.engine().list_notes()
		self.assertEqual(sorted(n['body'] for n in notes), ['gateway', 'login form'])
		self.assertTrue(all(n['_context']['migrated_from'] for n in notes))


class MigrateToMongodb(MigrateToSqlite):
	dst = 'mongodb'

	def test_ids_are_object_ids(self):
		self.migrate()
		runners = self.runners()
		self.assertTrue(ObjectId.is_valid(runners[CHAT_A]['context']['task_id']))
		self.assertTrue(ObjectId.is_valid(self.findings()['u-url']['_uuid']))

	def test_original_timestamps_kept(self):
		self.migrate()
		self.assertEqual(self.findings()['a-reply']['_timestamp'], T0 + 120)
		start = self.runners()[SCAN]['start_time']  # a date (naive from mongomock)
		self.assertEqual(start.replace(tzinfo=None), datetime(2026, 1, 1))

	def test_duplicates_tagged(self):
		self.migrate()
		self.assertTrue(self.findings()['u-url']['_tagged'])


class MigrateToApi(_MigrateCase):
	dst = 'api'

	def test_copy(self):
		migration = self.migrate()
		counts = migration.destination_counts()
		self.assertEqual({k: counts[k] for k in ('scans', 'workflows', 'tasks', 'findings: ai', 'findings: url')},
			{k: SOURCE_COUNTS[k] for k in ('scans', 'workflows', 'tasks', 'findings: ai', 'findings: url')})
		findings = self.findings()
		dup_id = str(self.api.db.findings.find_one({'_context.migrated_from': 'u-dup'})['_id'])
		self.assertEqual(findings['u-url']['_related'], [dup_id])
		chat_id = self.api.db.tasks.find_one({'name': 'ai', 'status': 'SUCCESS'})['context']['task_id']
		self.assertEqual(findings['a-prompt']['_context']['session_id'], chat_id)
		self.assertEqual(self.api.db.notes.count_documents({}), 2)

	def test_rerun_refused(self):
		# The remote store drops the runners' migration marker and cannot list notes.
		self.migrate()
		with self.assertRaisesRegex(RuntimeError, 'runners .* notes'):
			self.migrate()


class MigrateCli(_MigrateCase):
	dst = 'mongodb'

	def test_dry_run_and_apply(self):
		from secator.cli import cli
		runner = CliRunner()
		args = ['workspace', 'migrate', WS, '--from', 'local', '--to', 'mongodb', '--as', COPY]
		result = runner.invoke(cli, args)
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('Dry run', result.output)
		self.assertEqual(self.findings(), {})
		result = runner.invoke(cli, args + ['--apply'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertEqual(len(self.findings()), 9)

	def test_same_workspace_refused(self):
		from secator.cli import cli
		for extra in ([], ['--as', f'./{WS}']):
			result = CliRunner().invoke(cli, ['workspace', 'migrate', WS, '--from', 'local', '--to', 'local', *extra])
			self.assertIn('same workspace', result.output)
			self.assertNotEqual(result.exit_code, 0)


class MigrateToLocal(_MigrateCase):
	dst = 'local'

	def test_copy_counts_and_rerun(self):
		migration = self.migrate()
		self.assertEqual(dict(migration.destination_counts()), SOURCE_COUNTS)
		migration = self.migrate()
		self.assertEqual(dict(migration.destination_counts()), SOURCE_COUNTS)
		self.assertEqual(self.findings()['u-url']['status_code'], 200)

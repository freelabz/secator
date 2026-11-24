"""Derived `target` field on output types, query by host/domain/ip, and the `secator migrate` backfill."""
import json
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import orjson
from click.testing import CliRunner

from secator.decorators import task
from secator.migrations import m0001_target_fields
from secator.output_types import (
	Ai, Certificate, Domain, Exploit, ExploitAttempt, Info, Ip, Port, Record, Subdomain, Tag, Target, Technology, Url,
	UserAccount, Vulnerability)
from secator.output_types._base import load_output_types
from secator.query.json import JsonBackend
from secator.query.sqlite import SqliteBackend
from secator.query.utils import python_expr_to_mongo
from secator.runners import PythonRunner
from secator.scope import item_in_scope

WS = 'ws1'


class TestTarget(unittest.TestCase):

	CASES = [
		(Domain(domain='example.com'), 'example.com'),
		(Subdomain(host='api.example.com', domain='example.com'), 'api.example.com'),
		(Ip(ip='10.0.0.1', host='a.example.com'), '10.0.0.1'),
		(Port(port=443, ip='10.0.0.1', host='app.example.com'), 'app.example.com:443'),
		(Port(port=22, ip='10.0.0.1'), '10.0.0.1:22'),
		(Url(url='https://app.example.com:8443/login'), 'https://app.example.com:8443/login'),
		(Tag(name='t', value='v', match='src/App.js:12:3'), 'src/App.js:12:3'),
		(Technology(product='nginx', match='10.0.0.1:80'), '10.0.0.1:80'),
		(Vulnerability(name='v', matched_at='https://example.com/a'), 'https://example.com/a'),
		(Vulnerability(name='v', ip='10.0.0.2'), '10.0.0.2'),
		(Exploit(name='e', provider='p', id='1', matched_at='nginx 1.2'), 'nginx 1.2'),
		(ExploitAttempt(name='a', matched_at='app.example.com:443'), 'app.example.com:443'),
		(UserAccount(username='jdoe', email='jdoe@example.com'), 'jdoe@example.com'),
		(UserAccount(username='jdoe'), 'jdoe'),
		(Certificate(host='example.com', ip='10.0.0.1'), 'example.com'),
		(Record(name='ns1.example.com', type='NS'), 'ns1.example.com'),
	]

	def test_target_per_type(self):
		for item, target in self.CASES:
			with self.subTest(item=item._type):
				self.assertEqual(item.target, target)
				self.assertEqual(item.toDict()['target'], target)

	def test_empty_target_not_serialized(self):
		for item in (Ai(content='hello'), Info(message='hi'), Target(name='example.com')):
			with self.subTest(item=item._type):
				self.assertEqual(item.target, '')
				self.assertNotIn('target', item.toDict())

	def test_derived_not_compared_nor_in_schema(self):
		a = Port(port=443, ip='10.0.0.1', host='a.example.com')
		b = Port(port=443, ip='10.0.0.1', host='b.example.com')
		self.assertNotEqual(a.target, b.target)
		self.assertEqual(a, b)
		self.assertNotIn('target', Port.schema())

	def test_caller_and_stored_values_replaced(self):
		self.assertEqual(Vulnerability(name='v', matched_at='a.example.com', target='evil.com').target, 'a.example.com')
		doc = {**Port(port=80, ip='10.0.0.1', host='app.example.com').toDict(), 'target': 'stale'}
		self.assertEqual(next(load_output_types([doc])).target, 'app.example.com:80')

	def test_merge_with_recomputes(self):
		vuln = Vulnerability(name='v', ip='10.0.0.1')
		vuln.merge_with(Vulnerability(name='v', matched_at='app.example.com:8080'))
		self.assertEqual(vuln.target, 'app.example.com:8080')


@task()
class portprobe(PythonRunner):
	input_types = None
	output_types = [Port]
	output_scope_filter = True

	def yielder(self):
		yield Port(port=443, ip='10.0.0.5', host='app.example.com')
		yield Port(port=443, ip='192.168.1.1', host='other.example.net')


class TestItemInScope(unittest.TestCase):

	def test_ip_is_an_alternate_allow_path(self):
		self.assertTrue(item_in_scope('app.example.com:443', '10.0.0.5', ['10.0.0.0/24']))
		self.assertTrue(item_in_scope('app.example.com:443', '1.2.3.4', ['*.example.com']))
		self.assertFalse(item_in_scope('app.example.com:443', '1.2.3.4', ['10.0.0.0/24']))

	def test_deny_on_either_value_wins(self):
		self.assertFalse(item_in_scope('app.example.com:443', '10.0.0.5', ['10.0.0.0/24'], ['app.example.com']))
		self.assertFalse(item_in_scope('app.example.com:443', '10.0.0.5', ['*.example.com'], ['10.0.0.5']))

	def test_runner_scope_guard_uses_the_target(self):
		results = portprobe(inputs=['10.0.0.1'], in_scope=['10.0.0.0/24']).run()
		self.assertEqual([r.target for r in results if r._type == 'port'], ['app.example.com:443'])


def _legacy(item, uuid, **extra):
	"""A finding as stored before `target` existed."""
	doc = item.toDict()
	doc.pop('target', None)
	doc.update(_uuid=uuid, _context={'workspace_id': WS}, **extra)
	return doc


LEGACY = [
	_legacy(Port(port=443, ip='10.0.0.1', host='app.example.com'), 'u1'),
	_legacy(Url(url='https://app.example.com/login'), 'u2', is_false_positive=True),
	_legacy(Vulnerability(name='v', matched_at='/tmp/a'), 'u3'),
]
EXPECTED = {'u1': 'app.example.com:443', 'u2': 'https://app.example.com/login', 'u3': '/tmp/a'}


class MigrateTestMixin:
	"""Dry run writes nothing, apply backfills (false positives included), a rerun changes nothing."""

	def test_dry_run_apply_rerun(self):
		self.assertEqual(m0001_target_fields.run(self.backend), (3, 3))
		self.assertTrue(all('target' not in d for d in self.stored().values()))
		self.assertEqual(m0001_target_fields.run(self.backend, apply=True), (3, 3))
		self.assertEqual({u: d['target'] for u, d in self.stored().items()}, EXPECTED)
		self.assertEqual(m0001_target_fields.run(self.backend, apply=True), (3, 0))
		self.backend.workspace_id, self.backend.context = WS, {}
		query = python_expr_to_mongo("port.port == 443 && host == 'app.example.com'")
		found = [d['_uuid'] for d in self.backend.search(query)]
		self.assertEqual(found, ['u1'])


class TestMigrateSqlite(MigrateTestMixin, unittest.TestCase):

	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		self.sqlite_mod = sqlite_mod
		self.tmp = tempfile.mkdtemp()
		self.backend = SqliteBackend('', config={'db_path': str(Path(self.tmp) / 'test.db')})
		conn = self.backend._get_conn()
		for doc in LEGACY:
			conn.execute(
				"INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) VALUES (?, ?, ?, ?, 0, ?)",
				(doc['_uuid'], doc['_type'], WS, int(doc['is_false_positive']), json.dumps(doc)))
		conn.commit()

	def tearDown(self):
		conn = self.sqlite_mod._conns.pop(self.backend.config['db_path'], None)
		if conn:
			conn.close()
		shutil.rmtree(self.tmp)

	def stored(self):
		rows = self.backend._get_conn().execute('SELECT uuid, data FROM findings').fetchall()
		return {uuid: json.loads(data) for uuid, data in rows}


class TestMigrateJson(MigrateTestMixin, unittest.TestCase):

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.backend = JsonBackend('', config={'reports_dir': str(self.tmp)})
		# One live run (ndjson, with an info line) and one legacy run (report.json only).
		ndjson = self.tmp / WS / 'tasks' / '0' / 'results.ndjson'
		ndjson.parent.mkdir(parents=True)
		lines = [LEGACY[0], LEGACY[1], {'_type': 'info', 'message': 'hi'}]
		ndjson.write_bytes(b''.join(orjson.dumps(d) + b'\n' for d in lines))
		report = self.tmp / WS / 'scans' / '0' / 'report.json'
		report.parent.mkdir(parents=True)
		report.write_text(json.dumps({'info': {'name': 'x'}, 'results': {'vulnerability': [LEGACY[2]]}}))

	def tearDown(self):
		shutil.rmtree(self.tmp)

	def stored(self):
		docs = {}  # last record per _uuid wins, like the json store's reads
		for line in (self.tmp / WS / 'tasks' / '0' / 'results.ndjson').read_text().splitlines():
			doc = json.loads(line)
			if '_uuid' in doc:
				docs[doc['_uuid']] = doc
		for doc in json.loads((self.tmp / WS / 'scans' / '0' / 'report.json').read_text())['results']['vulnerability']:
			docs[doc['_uuid']] = doc
		return docs


class TestMigrateMongo(MigrateTestMixin, unittest.TestCase):

	def setUp(self):
		import pytest
		pytest.importorskip('pymongo')
		mongomock = pytest.importorskip('mongomock')
		from secator.query.mongodb import MongoDBBackend
		self.client = mongomock.MongoClient()
		self.client.main.findings.insert_many([dict(d) for d in LEGACY])
		self.backend = MongoDBBackend('')
		self.backend._client = self.client

	def stored(self):
		return {d['_uuid']: {k: v for k, v in d.items() if k != '_id'} for d in self.client.main.findings.find()}


HOST_DOCS = {
	'url': Url(url='https://secator.cloud/login'),
	'port': Port(port=443, ip='10.0.0.2', host='secator.cloud'),
	'dom': Domain(domain='secator.cloud'),
	'sub': Subdomain(host='api.secator.cloud', domain='secator.cloud'),
	'ip': Ip(ip='10.0.0.1'),
	'evil1': Subdomain(host='evil-secator.cloud', domain='evil-secator.cloud'),
	'evil2': Url(url='https://secator.cloud.evil.com/'),
	'not': Domain(domain='notsecator.cloud'),
	'path': Vulnerability(name='v', matched_at='/tmp/secator.cloud'),
	'pip': Port(port=80, ip='10.0.0.1', host='app.example.net'),
	'vip': Vulnerability(name='v', matched_at='10.0.0.1:443'),
	'p10': Port(port=80, ip='10.0.0.10'),
	'ip110': Ip(ip='110.0.0.1'),
}


class VirtualHostQueryMixin:
	"""Virtual `host` / `domain` / `ip` query fields match the host of `target` on every type."""

	CASES = [
		("host == 'secator.cloud'", {'url', 'port', 'dom'}),
		("host == 'SECATOR.cloud'", {'url', 'port', 'dom'}),
		("host == '10.0.0.1'", {'ip', 'vip'}),
		("domain == 'secator.cloud'", {'url', 'port', 'dom', 'sub'}),
		("host in ['secator.cloud', '10.0.0.1']", {'url', 'port', 'dom', 'ip', 'vip'}),
		("host != 'secator.cloud'", set(HOST_DOCS) - {'url', 'port', 'dom'}),
		("domain not in ['secator.cloud']", set(HOST_DOCS) - {'url', 'port', 'dom', 'sub'}),
		("host == 'secator.cloud' && port.port == 443", {'port'}),
		("ip == '10.0.0.1'", {'ip', 'pip', 'vip'}),
		("ip != '10.0.0.1'", set(HOST_DOCS) - {'ip', 'pip', 'vip'}),
		("ip == '10.0.0.1' && port.port == 80", {'pip'}),
		("host in []", set()),
	]

	def test_virtual_host_fields(self):
		for expr, expected in self.CASES:
			with self.subTest(expr=expr):
				found = {d['_uuid'] for d in self.backend.search(python_expr_to_mongo(expr))}
				self.assertEqual(found, expected)

	def test_typed_field_stays_real(self):
		found = {d['_uuid'] for d in self.backend.search(python_expr_to_mongo("subdomain.domain == 'secator.cloud'"))}
		self.assertEqual(found, {'sub'})

	@staticmethod
	def docs():
		return [{**item.toDict(), '_uuid': uuid, '_context': {'workspace_id': WS}} for uuid, item in HOST_DOCS.items()]


class TestVirtualHostSqlite(VirtualHostQueryMixin, unittest.TestCase):

	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		self.sqlite_mod = sqlite_mod
		self.tmp = tempfile.mkdtemp()
		self.backend = SqliteBackend(WS, config={'db_path': str(Path(self.tmp) / 'test.db')})
		conn = self.backend._get_conn()
		for doc in self.docs():
			conn.execute(
				"INSERT INTO findings (uuid, type, workspace_id, data) VALUES (?, ?, ?, ?)",
				(doc['_uuid'], doc['_type'], WS, json.dumps(doc, default=str)))
		conn.commit()

	def tearDown(self):
		conn = self.sqlite_mod._conns.pop(self.backend.config['db_path'], None)
		if conn:
			conn.close()
		shutil.rmtree(self.tmp)


class TestVirtualHostJson(VirtualHostQueryMixin, unittest.TestCase):

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.backend = JsonBackend(WS, config={'reports_dir': str(self.tmp)})
		ndjson = self.tmp / WS / 'tasks' / '0' / 'results.ndjson'
		ndjson.parent.mkdir(parents=True)
		ndjson.write_bytes(b''.join(orjson.dumps(d, default=str) + b'\n' for d in self.docs()))

	def tearDown(self):
		shutil.rmtree(self.tmp)


class TestVirtualHostMongo(VirtualHostQueryMixin, unittest.TestCase):

	def setUp(self):
		import pytest
		pytest.importorskip('pymongo')
		mongomock = pytest.importorskip('mongomock')
		from secator.query.mongodb import MongoDBBackend
		client = mongomock.MongoClient()
		client.main.findings.insert_many(self.docs())
		self.backend = MongoDBBackend(WS)
		self.backend._client = client


class TestMigrateCli(unittest.TestCase):

	def test_api_driver_refused(self):
		from secator.cli import cli
		with unittest.mock.patch('secator.query.QueryEngine.resolve_backend', return_value='api'):
			result = CliRunner().invoke(cli, ['migrate'])
		self.assertEqual(result.exit_code, 1)
		self.assertIn('where the store lives', result.output)


if __name__ == '__main__':
	unittest.main()

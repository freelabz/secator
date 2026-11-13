"""Derived `target` / `target_host` fields on findings, and their `secator migrate` backfill."""
import json
import shutil
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

import orjson
from click.testing import CliRunner

from secator.decorators import task
from secator.migrations import m0001_target_fields, run_migrations
from secator.output_types import (
	FINDING_TYPES, Ai, Certificate, Domain, Exploit, ExploitAttempt, Info, Ip, Port, Record, Subdomain, Tag, Target,
	Technology, Url, UserAccount, Vulnerability)
from secator.output_types._base import load_output_types
from secator.query.json import JsonBackend
from secator.query.utils import python_expr_to_mongo
from secator.query.sqlite import SqliteBackend
from secator.runners import PythonRunner
from secator.scope import item_in_scope
from secator.utils import remove_duplicates

WS = 'ws1'


class TestTargetPerType(unittest.TestCase):

	CASES = [
		(Domain(domain='Example.com'), 'example.com', 'example.com'),
		(Subdomain(host='API.example.com', domain='example.com'), 'api.example.com', 'api.example.com'),
		(Subdomain(host='www.example.com.', domain='example.com'), 'www.example.com', 'www.example.com'),
		(Ip(ip='10.0.0.1', host='a.example.com'), '10.0.0.1', '10.0.0.1'),
		(Port(port=443, ip='10.0.0.1', host='app.example.com'), 'app.example.com:443', 'app.example.com'),
		(Port(port=22, ip='10.0.0.1'), '10.0.0.1:22', '10.0.0.1'),
		(Port(port=22, ip='2001:db8::1'), '[2001:db8::1]:22', '2001:db8::1'),
		(Url(url='HTTPS://App.Example.com:8443/Login?next=/A'), 'https://app.example.com:8443/Login?next=/A', 'app.example.com'),  # noqa: E501
		(Tag(name='t', value='v', match='https://EXAMPLE.COM/x'), 'https://example.com/x', 'example.com'),
		(Tag(name='t', value='v', match='src/App.js:12:3'), 'src/App.js:12:3', ''),
		(Technology(product='nginx', match='10.0.0.1:80'), '10.0.0.1:80', '10.0.0.1'),
		(Vulnerability(name='v', matched_at='https://example.com/a'), 'https://example.com/a', 'example.com'),
		(Vulnerability(name='v', ip='10.0.0.2'), '10.0.0.2', '10.0.0.2'),
		(Vulnerability(name='v', matched_at='/tmp/Report.txt'), '/tmp/Report.txt', ''),
		(Exploit(name='e', provider='p', id='1', matched_at='nginx 1.2'), 'nginx 1.2', ''),
		(ExploitAttempt(name='a', matched_at='app.example.com:443'), 'app.example.com:443', 'app.example.com'),
		(UserAccount(username='u', url='https://github.com/u'), 'https://github.com/u', 'github.com'),
		(UserAccount(username='u', email='u@example.com'), 'u@example.com', ''),
		(UserAccount(username='u', site_name='example.com'), 'example.com', 'example.com'),
		(Certificate(host='example.com', ip='10.0.0.1'), 'example.com', 'example.com'),
		(Record(name='10.0.0.1', type='A', host='www.example.com'), 'www.example.com', 'www.example.com'),
		(Record(name='ns1.example.com', type='NS'), 'ns1.example.com', 'ns1.example.com'),
		(Ai(content='hello'), '', ''),
	]

	def test_target_per_type(self):
		for item, target, target_host in self.CASES:
			with self.subTest(item=item._type, target=target):
				self.assertEqual((item.target, item.target_host), (target, target_host))
				data = item.toDict()
				self.assertEqual((data['target'], data['target_host']), (target, target_host))

	def test_every_finding_type_has_the_fields(self):
		for cls in FINDING_TYPES:
			with self.subTest(cls=cls.__name__):
				self.assertIn('target', cls.fields())
				self.assertIn('target_host', cls.fields())
				self.assertNotIn('target', cls._table_fields)
				self.assertNotIn('target', cls.schema())

	def test_non_finding_types_have_no_target_field(self):
		for cls in (Target, Info):
			self.assertNotIn('target', cls.fields())

	def test_caller_value_ignored(self):
		vuln = Vulnerability(name='v', matched_at='app.example.com', target='evil.com', target_host='evil.com')
		self.assertEqual((vuln.target, vuln.target_host), ('app.example.com', 'app.example.com'))

	def test_recomputed_after_mutation(self):
		vuln = Vulnerability(name='v', ip='10.0.0.1')
		vuln.matched_at = 'app.example.com:8080'  # e.g. set by a task after building the item
		vuln.target = 'stale'
		self.assertEqual(vuln.toDict()['target'], 'app.example.com:8080')
		self.assertEqual(vuln.target_host, 'app.example.com')

	def test_old_doc_auto_filled_on_load(self):
		doc = Port(port=80, ip='10.0.0.1', host='app.example.com').toDict()
		del doc['target'], doc['target_host']
		item = Port.load(doc)
		self.assertEqual((item.target, item.target_host), ('app.example.com:80', 'app.example.com'))
		doc['target'] = 'stale'
		item = next(load_output_types([doc]))
		self.assertEqual(item.target, 'app.example.com:80')


class TestTargetDoesNotAffectIdentity(unittest.TestCase):

	def test_not_a_compare_field(self):
		for cls in FINDING_TYPES:
			compared = [f.name for f in fields(cls) if f.compare]
			self.assertNotIn('target', compared)
			self.assertNotIn('target_host', compared)

	def test_dedup_and_uuid_unchanged(self):
		# Same Port identity (port, ip, state), different host -> different target, still duplicates.
		a = Port(port=443, ip='10.0.0.1', host='a.example.com', _uuid='u1')
		b = Port(port=443, ip='10.0.0.1', host='b.example.com', _uuid='u2')
		self.assertNotEqual(a.target, b.target)
		self.assertEqual(a, b)
		self.assertEqual(a._compare_key(), b._compare_key())
		self.assertEqual(len(remove_duplicates([a, b])), 1)
		a.toDict()
		self.assertEqual(a._uuid, 'u1')


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
		self.assertFalse(item_in_scope('app.example.com:443', '10.0.0.5', None, ['app.example.com']))

	def test_runner_scope_guard_uses_the_target(self):
		results = portprobe(inputs=['10.0.0.1'], in_scope=['10.0.0.0/24']).run()
		self.assertEqual([r.target for r in results if r._type == 'port'], ['app.example.com:443'])


def _legacy(item, uuid, **extra):
	"""Serialize a finding as stored before the target fields existed."""
	doc = item.toDict()
	del doc['target'], doc['target_host']
	doc.update(_uuid=uuid, _context={'workspace_id': WS}, **extra)
	return doc


LEGACY = [
	_legacy(Port(port=443, ip='10.0.0.1', host='app.example.com'), 'u1'),
	_legacy(Url(url='https://app.example.com/login'), 'u2', is_false_positive=True),
	_legacy(Vulnerability(name='v', matched_at='/tmp/a'), 'u3'),
]
EXPECTED = {
	'u1': ('app.example.com:443', 'app.example.com'),
	'u2': ('https://app.example.com/login', 'app.example.com'),
	'u3': ('/tmp/a', ''),
}


class MigrateTestMixin:
	"""Shared checks: dry run writes nothing, apply backfills (false positives included), reruns are no-ops."""

	def stored(self):
		raise NotImplementedError

	def test_dry_run_then_apply(self):
		[res] = run_migrations(self.backend)
		self.assertEqual((res['status'], res['matched'], res['changed']), ('pending', 3, 3))
		self.assertTrue(all('target' not in d for d in self.stored().values()))
		self.assertEqual(self.backend.get_migrations(), {})

		[res] = run_migrations(self.backend, apply=True)
		self.assertEqual((res['status'], res['changed']), ('done', 3))
		docs = self.stored()
		self.assertEqual({u: (d['target'], d['target_host']) for u, d in docs.items()}, EXPECTED)
		self.assertTrue(docs['u2']['is_false_positive'])
		self.assertIn(m0001_target_fields.ID, self.backend.get_migrations())

	def test_idempotent(self):
		run_migrations(self.backend, apply=True)
		before = self.stored()
		[res] = run_migrations(self.backend, apply=True)
		self.assertEqual(res['status'], 'applied')
		[res] = run_migrations(self.backend, apply=True, force=True)
		self.assertEqual((res['status'], res['changed']), ('done', 0))
		self.assertEqual(self.stored(), before)

	def test_queryable_after_backfill(self):
		run_migrations(self.backend, apply=True)
		self.backend.workspace_id = WS

		def found(expr):
			return sorted(d['_uuid'] for d in self.backend.search(python_expr_to_mongo(expr)))

		self.assertEqual(found("target ~= 'APP.example.com:443'"), ['u1'])
		self.assertEqual(found("port.target_host == 'app.example.com'"), ['u1'])
		self.assertEqual(found("target_host == 'nope.example.com'"), [])


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
		# One live run (ndjson, with a re-emitted line) and one legacy run (report.json only).
		self.ndjson = self.tmp / WS / 'tasks' / '0' / 'results.ndjson'
		self.ndjson.parent.mkdir(parents=True)
		lines = [LEGACY[0], LEGACY[1], LEGACY[1], {'_type': 'info', 'message': 'hi'}]
		self.ndjson.write_bytes(b''.join(orjson.dumps(d) + b'\n' for d in lines))
		self.report = self.tmp / WS / 'scans' / '0' / 'report.json'
		self.report.parent.mkdir(parents=True)
		self.report.write_text(json.dumps({'info': {'name': 'x'}, 'results': {'vulnerability': [LEGACY[2]]}}))

	def tearDown(self):
		shutil.rmtree(self.tmp)

	def stored(self):
		docs = {}
		for line in self.ndjson.read_text().splitlines():
			doc = json.loads(line)
			if '_uuid' in doc:
				docs[doc['_uuid']] = doc
		for doc in json.loads(self.report.read_text())['results']['vulnerability']:
			docs[doc['_uuid']] = doc
		return docs

	def test_non_findings_untouched(self):
		run_migrations(self.backend, apply=True)
		info = json.loads(self.ndjson.read_text().splitlines()[-1])
		self.assertEqual(info, {'_type': 'info', 'message': 'hi'})


class TestMigrateMongo(MigrateTestMixin, unittest.TestCase):

	def setUp(self):
		import pytest
		pytest.importorskip('pymongo')
		mongomock = pytest.importorskip('mongomock')
		from secator.query.mongodb import MongoDBBackend

		def bulk_write(coll, ops, ordered=True):  # mongomock rejects recent pymongo UpdateOne objects
			for op in ops:
				coll.update_one(op._filter, op._doc)

		patcher = patch.object(mongomock.collection.Collection, 'bulk_write', bulk_write)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.client = mongomock.MongoClient()
		self.client.main.findings.insert_many([dict(d) for d in LEGACY])
		self.backend = MongoDBBackend('')
		self.backend._client = self.client

	def stored(self):
		return {d['_uuid']: {k: v for k, v in d.items() if k != '_id'} for d in self.client.main.findings.find()}

	def test_index_created(self):
		run_migrations(self.backend, apply=True)
		keys = [[k for k, _ in ix['key']] for ix in self.client.main.findings.index_information().values()]
		self.assertIn(['_context.workspace_id', 'target_host'], keys)


class TestMigrateCli(unittest.TestCase):

	def test_api_driver_refused(self):
		from secator.cli import cli
		result = CliRunner().invoke(cli, ['migrate', '--driver', 'api'])
		self.assertEqual(result.exit_code, 1)
		self.assertIn('where the store lives', result.output)


if __name__ == '__main__':
	unittest.main()

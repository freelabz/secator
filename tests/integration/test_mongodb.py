"""End to end with the mongodb driver against a real MongoDB server.

A small local task (no external tool, no network) emits a url and a vulnerability with the
mongodb driver; the findings must be stored, and finding updates made through the AI tools
(update_finding, mark_vuln_fixed) must persist and read back.

Needs a MongoDB server at SECATOR_ADDONS_MONGODB_URL. Skipped when none is reachable, unless
SECATOR_TEST_MONGODB=1 (set in CI), where an unreachable server fails the test.
"""
import json
import os
import shlex
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

ObjectId = pytest.importorskip('bson.objectid').ObjectId  # the mongodb extra (pymongo)

from secator.output_types import Certificate, Domain, Url, Vulnerability  # noqa: E402
from secator.runners import Command  # noqa: E402
from secator.serializers import JSONSerializer  # noqa: E402

REQUIRED = os.environ.get('SECATOR_TEST_MONGODB') == '1'

URL = {'_type': 'url', 'url': 'http://127.0.0.1:8000/login', 'status_code': 200}
VULN = {
	'_type': 'vulnerability', 'name': 'mongodb-e2e', 'id': 'CVE-2099-0001',
	'matched_at': 'http://127.0.0.1:8000/login', 'severity': 'low', 'confidence': 'high',
}


class mongodbe2e(Command):
	"""Prints a url and a vulnerability as JSON lines: deterministic, local, instant."""
	cmd = 'printf ' + shlex.quote(f'{json.dumps(URL)}\\n{json.dumps(VULN)}\\n') + ' #'
	input_types = ['url']
	input_flag = None
	file_flag = None
	output_types = [Url, Vulnerability]
	item_loaders = [JSONSerializer()]


CERT = {
	'_type': 'certificate', 'host': 'dt.example.com', 'subject_cn': 'dt.example.com',
	'not_before': '2025-01-01T00:00:00Z', 'not_after': '2026-06-01T00:00:00Z',
}
DOMAIN = {'_type': 'domain', 'domain': 'dt.example.com', 'creation_date': '2001-02-03T04:05:06Z'}
DT_FIELDS = {'certificate': ('not_before', 'not_after'), 'domain': ('creation_date', 'expiration_date', 'updated_date')}


class mongodbdte2e(Command):
	"""Prints a certificate and a domain as JSON lines (datetime fields as ISO strings)."""
	cmd = 'printf ' + shlex.quote(f'{json.dumps(CERT)}\\n{json.dumps(DOMAIN)}\\n') + ' #'
	input_types = ['host']
	input_flag = None
	file_flag = None
	output_types = [Certificate, Domain]
	item_loaders = [JSONSerializer()]


def _mongodb_reachable():
	from secator.hooks.mongodb import get_mongodb_client
	try:
		get_mongodb_client().admin.command('ping')
		return True
	except Exception:
		return False


class TestMongoDBDriver(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		if not _mongodb_reachable():
			if REQUIRED:
				raise RuntimeError('MongoDB is not reachable at SECATOR_ADDONS_MONGODB_URL')
			raise unittest.SkipTest('no MongoDB server reachable')
		from secator.hooks.mongodb import get_mongodb_client
		cls.db = get_mongodb_client().main
		cls.workspace_id = str(ObjectId())
		cls.db.workspaces.insert_one({'_id': ObjectId(cls.workspace_id), 'name': 'mongodb-e2e'})

	@classmethod
	def tearDownClass(cls):
		cls.db.findings.delete_many({'_context.workspace_id': cls.workspace_id})
		cls.db.tasks.delete_many({'context.workspace_id': cls.workspace_id})
		cls.db.workspaces.delete_one({'_id': ObjectId(cls.workspace_id)})

	def _context(self):
		return {'drivers': ['mongodb'], 'workspace_id': self.workspace_id, 'workspace_name': 'mongodb-e2e'}

	def _engine(self):
		from secator.query import QueryEngine
		return QueryEngine(self.workspace_id, context=self._context())

	def test_findings_stored_and_updates_read_back(self):
		task = mongodbe2e(['http://127.0.0.1:8000'], sync=True, print_item=False, print_line=False,
			context=self._context())
		list(task)
		self.assertEqual(task.status, 'SUCCESS')

		# Findings are stored by the driver.
		engine = self._engine()
		url = engine.search({'_type': 'url', 'url': URL['url']}, limit=10)
		vuln = engine.search({'_type': 'vulnerability', 'name': VULN['name']}, limit=10)
		self.assertEqual(len(url), 1)
		self.assertEqual(len(vuln), 1)

		# Updates through the AI tools persist and read back.
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		ctx = ActionContext(targets=[], model='m', context=self._context())
		for name, args in (
			('update_finding', {'_uuid': url[0]['_uuid'], 'fields': {'tags': ['mongodb-e2e']}}),
			('mark_vuln_fixed', {'_uuid': vuln[0]['_uuid'], 'reason': 'no longer reproduces'}),
		):
			tool = TOOLS_BY_NAME[name]
			out = list(tool.run({'action': tool.action, **args}, ctx))
			self.assertEqual([o.message for o in out if o._type == 'error'], [], name)

		engine = self._engine()
		url_after = engine.search({'_uuid': url[0]['_uuid']}, limit=1)[0]
		vuln_after = engine.search({'_uuid': vuln[0]['_uuid']}, limit=1, scope_only=True)[0]
		self.assertEqual(url_after['tags'], ['mongodb-e2e'])
		self.assertEqual(vuln_after['status'], 'FIXED')
		# ... and straight from the collection, not only through the query backend.
		doc = self.db.findings.find_one({'_id': ObjectId(vuln[0]['_uuid'])})
		self.assertEqual(doc['status'], 'FIXED')

	def _assert_bson_utc_date(self, uuid, field, expected):
		"""The raw document holds a BSON date (not a string) at the expected UTC instant."""
		self.assertEqual(self.db.findings.count_documents({'_id': ObjectId(uuid), field: {'$type': 'date'}}), 1, field)
		self.assertEqual(self.db.findings.find_one({'_id': ObjectId(uuid)})[field], expected, field)

	def test_datetime_fields_tools_driver_and_queries(self):
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		from secator.hooks.mongodb import update_finding as driver_update_finding
		utc = timezone.utc
		task = mongodbdte2e(['dt.example.com'], sync=True, print_item=False, print_line=False, context=self._context())
		list(task)
		self.assertEqual(task.status, 'SUCCESS')
		engine = self._engine()
		cert = engine.search({'_type': 'certificate', 'host': CERT['host']}, limit=1)[0]
		dom = engine.search({'_type': 'domain', 'domain': DOMAIN['domain']}, limit=1)[0]
		# Task-produced: the driver stores BSON dates.
		self._assert_bson_utc_date(cert['_uuid'], 'not_after', datetime(2026, 6, 1, tzinfo=utc))
		self._assert_bson_utc_date(dom['_uuid'], 'creation_date', datetime(2001, 2, 3, 4, 5, 6, tzinfo=utc))

		ctx = ActionContext(targets=[], model='m', context=self._context())

		def run(name, **args):
			tool = TOOLS_BY_NAME[name]
			return list(tool.run({'action': tool.action, **args}, ctx))

		# update_finding: $set on an existing doc, non-UTC offset / epoch / $date inputs -> UTC BSON dates.
		target = datetime(2026, 11, 21, 20, 10, 23, tzinfo=utc)
		for value in ('2026-11-21T22:10:23+02:00', '2026-11-21 20:10:23', int(target.timestamp()),
		              {'$date': '2026-11-21T20:10:23Z'}):
			with self.subTest(value=value):
				out = run('update_finding', _uuid=cert['_uuid'], fields={'not_after': value})
				self.assertEqual([o.message for o in out if o._type == 'error'], [])
				self._assert_bson_utc_date(cert['_uuid'], 'not_after', target)
				# the tool's own re-read and the query backend return the same UTC instant
				self.assertEqual(out[-1].extra_data['finding']['not_after'], target)
				stored = self._engine().search({'_uuid': cert['_uuid']}, limit=1)[0]
				self.assertEqual(Certificate.load(stored).not_after, target)
		out = run('update_finding', _uuid=dom['_uuid'], fields={'expiration_date': '2030-01-01T00:00:00Z'})
		self.assertEqual([o.message for o in out if o._type == 'error'], [])
		self._assert_bson_utc_date(dom['_uuid'], 'expiration_date', datetime(2030, 1, 1, tzinfo=utc))
		# garbage is rejected and nothing is written
		out = run('update_finding', _uuid=cert['_uuid'], fields={'not_after': 'next week'})
		self.assertIn('ISO 8601', ' '.join(o.message for o in out if o._type == 'error'))
		self._assert_bson_utc_date(cert['_uuid'], 'not_after', target)

		# add_finding: the created finding goes through the mongodb driver like any task result.
		out = run('add_finding', _type='certificate', fields={
			'host': 'added.example.com', 'not_before': '2025-03-01T02:00:00+02:00', 'not_after': '2027-03-01T00:00:00Z'})
		self.assertEqual([o.message for o in out if o._type == 'error'], [])
		added = [o for o in out if o._type == 'certificate'][0]
		runner = SimpleNamespace(context=self._context(), config=SimpleNamespace(type='task', name='ai'))
		driver_update_finding(runner, added)
		self._assert_bson_utc_date(added._uuid, 'not_before', datetime(2025, 3, 1, tzinfo=utc))
		self._assert_bson_utc_date(added._uuid, 'not_after', datetime(2027, 3, 1, tzinfo=utc))

		# Date filters and sorts on datetime fields (string operands, as `secator q` sends them).
		engine = self._engine()
		hosts = lambda q: sorted(d['host'] for d in engine.search({'_type': 'certificate', **q}))  # noqa: E731
		self.assertEqual(hosts({'not_after': {'$lt': '2027-01-01'}}), ['dt.example.com'])
		self.assertEqual(hosts({'not_after': {'$gte': '2027-01-01T00:00:00Z'}}), ['added.example.com'])
		self.assertEqual(hosts({'not_after': '2026-11-21T20:10:23Z'}), ['dt.example.com'])
		docs = list(self.db.findings.find({'_context.workspace_id': self.workspace_id, '_type': 'certificate'})
		            .sort('not_after', -1))
		self.assertEqual([d['host'] for d in docs], ['added.example.com', 'dt.example.com'])

		from click.testing import CliRunner
		from secator.cli import cli
		res = CliRunner().invoke(cli, [
			'q', 'certificate.not_after < 2027-01-01', '--driver', 'mongodb', '-ws', self.workspace_id,
			'-f', '{certificate.host}'])
		self.assertEqual(res.exit_code, 0, res.output)
		self.assertIn('dt.example.com', res.output)
		self.assertNotIn('added.example.com', res.output)
		res = CliRunner().invoke(cli, [
			'q', 'certificate', '--driver', 'mongodb', '-ws', self.workspace_id, '-f', '{certificate.host}',
			'--sort', '-not_after'])
		self.assertEqual(res.exit_code, 0, res.output)
		self.assertLess(res.output.index('added.example.com'), res.output.index('dt.example.com'))

		# tz-aware and naive pymongo reads give the same UTC instant.
		import pymongo
		from secator.hooks.mongodb import MONGODB_URL
		naive_client = pymongo.MongoClient(MONGODB_URL, tz_aware=False)
		try:
			raw = naive_client.main.findings.find_one({'_id': ObjectId(cert['_uuid'])})
		finally:
			naive_client.close()
		self.assertIsNone(raw['not_after'].tzinfo)
		self.assertEqual(Certificate.load(raw).not_after, target)


if __name__ == '__main__':
	unittest.main()

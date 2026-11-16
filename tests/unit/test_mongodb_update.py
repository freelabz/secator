"""MongoDB driver updates: the matched-count contract shared by every query backend.

An update returns the number of findings MATCHED (a finding already in the requested state
counts), so an idempotent re-mark is a success, not "not found". Uses mongomock.
"""
import unittest
from unittest import mock

import pytest

mongomock = pytest.importorskip('mongomock')
ObjectId = pytest.importorskip('bson.objectid').ObjectId

from secator.definitions import ADDONS_ENABLED  # noqa: E402

WS = 'ws-update'


def _vuln(**extra):
	return {
		'_type': 'vulnerability', 'name': 'test-vuln', 'id': 'CVE-2099-0001', 'severity': 'low',
		'matched_at': 'http://127.0.0.1/', 'status': 'OPEN', 'is_false_positive': False,
		'_context': {'workspace_id': WS}, **extra,
	}


class TestMongoBackendUpdate(unittest.TestCase):

	def setUp(self):
		from secator.query.mongodb import MongoDBBackend
		self.client = mongomock.MongoClient()
		self.backend = MongoDBBackend(WS)
		self.backend._client = self.client

	def _insert(self, doc):
		oid = ObjectId()
		self.client.main.findings.insert_one({'_id': oid, '_uuid': str(oid), **doc})
		return str(oid)

	def test_idempotent_update_counts_the_match(self):
		uuid = self._insert(_vuln())
		self.assertEqual(self.backend.update({'_uuid': uuid}, {'$set': {'status': 'FIXED'}}), 1)
		# Already FIXED: nothing modified, but the finding matched.
		self.assertEqual(self.backend.update({'_uuid': uuid}, {'$set': {'status': 'FIXED'}}), 1)

	def test_update_reaches_every_matching_finding(self):
		self._insert(_vuln(matched_at='http://a/'))
		self._insert(_vuln(matched_at='http://b/'))
		self._insert(_vuln(name='other'))
		count = self.backend.update({'_type': 'vulnerability', 'name': 'test-vuln'}, {'$set': {'verified': True}})
		self.assertEqual(count, 2)
		verified = self.client.main.findings.count_documents({'verified': True})
		self.assertEqual(verified, 2)

	def test_update_stays_in_workspace(self):
		self._insert(_vuln())
		self._insert({**_vuln(), '_context': {'workspace_id': 'other-ws'}})
		self.assertEqual(self.backend.update({'name': 'test-vuln'}, {'$set': {'status': 'FIXED'}}), 1)
		self.assertEqual(self.client.main.findings.count_documents({'status': 'FIXED'}), 1)

	def test_no_match_returns_zero(self):
		self.assertEqual(self.backend.update({'_uuid': str(ObjectId())}, {'$set': {'status': 'FIXED'}}), 0)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestAiToolsRepeatOnMongo(unittest.TestCase):
	"""Running a finding-update tool twice on the mongodb driver must succeed both times."""

	def setUp(self):
		self.client = mongomock.MongoClient()
		patcher = mock.patch('secator.hooks.mongodb.get_mongodb_client', return_value=self.client)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _insert(self, doc):
		oid = ObjectId()
		self.client.main.findings.insert_one({'_id': oid, '_uuid': str(oid), **doc})
		return str(oid)

	def _run(self, name, args):
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		ctx = ActionContext(targets=[], model='m', context={'drivers': ['mongodb'], 'workspace_id': WS})
		tool = TOOLS_BY_NAME[name]
		return list(tool.run({'action': tool.action, **args}, ctx))

	def _errors(self, out):
		return [o.message for o in out if getattr(o, '_type', None) == 'error']

	def test_mark_vuln_fixed_twice(self):
		uuid = self._insert(_vuln())
		for _ in range(2):
			out = self._run('mark_vuln_fixed', {'_uuid': uuid, 'reason': 'patched'})
			self.assertEqual(self._errors(out), [])
		doc = self.client.main.findings.find_one({'_id': ObjectId(uuid)})
		self.assertEqual(doc['status'], 'FIXED')

	def test_update_finding_same_value_twice(self):
		uuid = self._insert(_vuln())
		for _ in range(2):
			out = self._run('update_finding', {'_uuid': uuid, 'fields': {'severity': 'high'}})
			self.assertEqual(self._errors(out), [])
		doc = self.client.main.findings.find_one({'_id': ObjectId(uuid)})
		self.assertEqual(doc['severity'], 'high')

	def test_mark_vuln_false_positive_twice(self):
		uuid = self._insert(_vuln())
		for _ in range(2):
			out = self._run('mark_vuln_false_positive', {'_uuid': uuid, 'reason': 'not reachable'})
			self.assertEqual(self._errors(out), [])
		doc = self.client.main.findings.find_one({'_id': ObjectId(uuid)})
		self.assertTrue(doc['is_false_positive'])

	def test_unknown_uuid_is_reported(self):
		out = self._run('mark_vuln_fixed', {'_uuid': str(ObjectId()), 'reason': 'x'})
		self.assertTrue(any('No vulnerability found' in m for m in self._errors(out)))

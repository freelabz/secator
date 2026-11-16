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

import pytest

ObjectId = pytest.importorskip('bson.objectid').ObjectId  # the mongodb extra (pymongo)

from secator.output_types import Url, Vulnerability  # noqa: E402
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


if __name__ == '__main__':
	unittest.main()

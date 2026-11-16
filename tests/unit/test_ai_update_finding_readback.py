"""update_finding returns the finding as the store holds it after the write, on every backend."""
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from secator.ai.actions import ActionContext
from secator.ai.tools import TOOLS_BY_NAME
from secator.query import QueryEngine
from secator.query.json import _apply_set, match_query

# The mongodb backend needs pymongo (bson) — guarded like the other mongodb unit tests.
HAS_PYMONGO = importlib.util.find_spec('bson') is not None

WS = 'ws1'
UUID = '0b8c9d4e-1f2a-4b3c-8d5e-6f7a8b9c0d1e'


def _finding():
	return {
		'_uuid': UUID, '_type': 'vulnerability', 'name': 'v1', 'id': 'CVE-0000-0001',
		'matched_at': 'http://a.com', 'severity': 'low', 'description': 'old',
		'_context': {'workspace_id': WS}, '_tagged': True,
	}


class _FakeCursor(list):
	def skip(self, n):
		return _FakeCursor(self[n:])

	def limit(self, n):
		return _FakeCursor(self[:n] if n else self)


class _FakeFindings:
	"""In-memory stand-in for the mongodb findings collection (find / update_one)."""

	def __init__(self, docs):
		self.docs = docs

	def find(self, query, projection=None):
		return _FakeCursor(copy.deepcopy(d) for d in self.docs if match_query(d, query))

	def update_one(self, query, update):
		for d in self.docs:
			if match_query(d, query):
				_apply_set(d, update['$set'])
				return MagicMock(modified_count=1)
		return MagicMock(modified_count=0)


class TestUpdateFindingReturnsStoredFinding(unittest.TestCase):

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)

	def _engine(self, driver):
		engine = QueryEngine(WS, context={'drivers': [driver]} if driver != 'json' else {})
		if driver == 'json':
			(self.tmp / 'results.ndjson').write_text(json.dumps(_finding()) + '\n')
			engine.backend.context['report_dir'] = str(self.tmp)
		elif driver == 'sqlite':
			from secator.hooks.sqlite import get_sqlite_conn
			from secator.query.sqlite import SqliteBackend
			db_path = str(self.tmp / 'store.db')
			conn = get_sqlite_conn(db_path)
			conn.execute(
				'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) VALUES (?, ?, ?, 0, 1, ?)',
				(UUID, 'vulnerability', WS, json.dumps(_finding())))
			conn.commit()
			engine.backend = SqliteBackend(WS, config={'db_path': db_path})
		elif driver == 'mongodb':
			client = MagicMock()
			client.main.findings = _FakeFindings([_finding()])
			engine.backend._client = client
		elif driver == 'api':
			docs = [dict(_finding(), _id='oid1')]

			def responses(method, endpoint, data=None):
				if method == 'POST':
					return {'items': [dict(d) for d in docs if match_query(d, data or {})]}
				_apply_set(docs[0], data)  # PUT finding/{_id}
				return {'success': True}
			engine.backend._make_request = MagicMock(side_effect=responses)
		return engine

	def _check(self, driver):
		tool = TOOLS_BY_NAME['update_finding']
		engine = self._engine(driver)
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': WS})
		ctx._query_engine = engine
		out = list(tool.run({'action': tool.action, '_uuid': UUID, 'fields': {'description': 'new'}}, ctx))
		self.assertEqual([o.message for o in out if o._type == 'error'], [])
		finding = out[-1].extra_data['finding']
		self.assertEqual(finding['_uuid'], UUID)
		self.assertEqual(finding['description'], 'new')
		stored = engine.search({'_uuid': UUID}, limit=1, scope_only=True)[0]
		self.assertEqual(stored['description'], 'new')

	def test_json(self):
		self._check('json')

	def test_sqlite(self):
		self._check('sqlite')

	@unittest.skipUnless(HAS_PYMONGO, 'pymongo not installed')
	def test_mongodb(self):
		self._check('mongodb')

	def test_api(self):
		self._check('api')


if __name__ == '__main__':
	unittest.main()

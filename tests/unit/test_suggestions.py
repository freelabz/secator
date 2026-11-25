"""Runner suggestions: the Suggestion output type, the add_suggestion AI tool, and how each
driver stores a suggestion (its own store, never with findings)."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secator.definitions import ADDONS_ENABLED
from secator.output_types import FINDING_TYPES, OUTPUT_TYPES, Error, Suggestion
from secator.output_types._base import load_output_types


def _suggestion(**kw):
	kw = {'name': 'httpx', 'type': 'task', 'targets': ['a.com', 'b.com'], 'reason': 'probe the hosts',
		'source': 'ai', '_context': {'workspace_id': 'ws1'}, **kw}
	return Suggestion(**kw)


class TestSuggestionOutputType(unittest.TestCase):
	def test_not_a_finding(self):
		self.assertIn(Suggestion, OUTPUT_TYPES)
		self.assertNotIn(Suggestion, FINDING_TYPES)

	def test_round_trip(self):
		item = _suggestion(opts={'rate_limit': 10}, priority='high')
		loaded = next(load_output_types([item.toDict()]))
		self.assertIsInstance(loaded, Suggestion)
		self.assertEqual(loaded.toDict(), item.toDict())
		self.assertIn('httpx', repr(loaded))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestAddSuggestionTool(unittest.TestCase):
	def _run(self, **action):
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		ctx = ActionContext(targets=['a.com'], model='m', context={'workspace_id': 'ws1'})
		return list(TOOLS_BY_NAME['add_suggestion'].handle(action, ctx))

	def test_valid_suggestion(self):
		[item] = self._run(type='task', name='httpx', targets=['a.com'], reason='probe', opts={'threads': 5})
		self.assertIsInstance(item, Suggestion)
		self.assertEqual((item.type, item.name, item.targets, item.opts), ('task', 'httpx', ['a.com'], {'threads': 5}))
		self.assertEqual((item.source, item.priority), ('ai', 'medium'))

	def test_targets_are_a_canonical_list(self):
		[item] = self._run(type='task', name='httpx', targets='a.com', reason='probe')
		self.assertEqual(item.targets, ['a.com'])
		[item] = self._run(type='task', name='httpx', targets=[' b.com', 'a.com', 'b.com', ''], reason='probe')
		self.assertEqual(item.targets, ['a.com', 'b.com'])

	def test_refuses_unknown_config(self):
		[item] = self._run(type='task', name='not_a_task', targets=['a.com'], reason='x')
		self.assertIsInstance(item, Error)
		self.assertIn('not_a_task', item.message)

	def test_refuses_bad_type_and_missing_fields(self):
		for action in (
			{'type': 'shell', 'name': 'httpx', 'targets': ['a.com'], 'reason': 'x'},
			{'type': 'task', 'name': 'httpx', 'targets': [], 'reason': 'x'},
			{'type': 'task', 'name': 'httpx', 'targets': ['a.com'], 'reason': 'x', 'priority': 'urgent'},
			{'type': 'task', 'name': 'httpx', 'targets': ['a.com'], 'reason': 'x', 'opts': ['x']},
		):
			[item] = self._run(**action)
			self.assertIsInstance(item, Error, action)

	def test_only_granted_through_extra_tools(self):
		from secator.ai.prompts import MODES
		from secator.ai.tools import build_tool_schemas

		def names(mode, **kw):
			return [s['function']['name'] for s in build_tool_schemas(mode, **kw)]

		for mode in MODES:
			self.assertNotIn('add_suggestion', names(mode), mode)
		self.assertIn('add_suggestion', names('chat', extra_tools=['add_suggestion']))
		# It is an opt-in (external) tool, so a glob over opt-in tools grants it too.
		self.assertIn('add_suggestion', names('chat', extra_tools=['add_*']))


class TestDriversStoreSuggestions(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def test_mongodb_writes_suggestions_collection_with_dedup(self):
		mongomock = pytest.importorskip('mongomock')
		from bson import ObjectId
		from secator.hooks import mongodb
		client = mongomock.MongoClient()
		with patch.object(mongodb, 'get_mongodb_client', return_value=client):
			first = mongodb.update_finding(MagicMock(), _suggestion())
			# Same runner and target set: refreshed, not duplicated (also the on_duplicate path).
			again = mongodb.update_finding(MagicMock(), _suggestion(targets=['b.com', 'a.com'], reason='new reason'))
			mongodb.update_finding(MagicMock(), again)
			other = mongodb.update_finding(MagicMock(), _suggestion(targets=['a.com']))
			# Duplicate targets are the same set; same size but another set is a distinct suggestion.
			self.assertEqual(mongodb.update_finding(MagicMock(), _suggestion(targets=['a.com', 'a.com']))._uuid, other._uuid)
			mongodb.update_finding(MagicMock(), _suggestion(targets=['a.com', 'c.com']))
		db = client.main
		self.assertEqual(db.findings.count_documents({}), 0)
		self.assertEqual(db.suggestions.count_documents({}), 3)
		self.assertEqual(first._uuid, again._uuid)
		self.assertNotEqual(first._uuid, other._uuid)
		doc = db.suggestions.find_one({'_id': ObjectId(first._uuid)})
		self.assertEqual(doc['type'], 'runner')
		self.assertEqual(doc['message'], 'new reason')
		self.assertEqual(doc['source'], 'ai')
		self.assertEqual(doc['context'], {'workspace_id': 'ws1', 'done': False})
		self.assertEqual(doc['data']['config_query'], {'config.name': 'httpx', 'config.type': 'task'})
		self.assertEqual(doc['data']['targets'], ['a.com', 'b.com'])
		self.assertEqual(doc['_context'], {'workspace_id': 'ws1'})

	def test_sqlite_writes_suggestions_table(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		orig = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.temp_dir) / 'test.db')
		sqlite_mod._conns.clear()
		try:
			item = sqlite_mod.update_finding(MagicMock(), _suggestion())
			# Same runner and target set (any order): refreshed, not duplicated.
			again = sqlite_mod.update_finding(MagicMock(), _suggestion(targets=['b.com', 'a.com']))
			self.assertEqual(again._uuid, item._uuid)
			other = sqlite_mod.update_finding(MagicMock(), _suggestion(targets=['a.com']))
			self.assertNotEqual(other._uuid, item._uuid)
			conn = sqlite_mod.get_sqlite_conn()
			self.assertEqual(conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 0)
			rows = conn.execute('SELECT uuid, workspace_id, data FROM suggestions ORDER BY rowid').fetchall()
			self.assertEqual([(r[0], r[1]) for r in rows], [(item._uuid, 'ws1'), (other._uuid, 'ws1')])
			self.assertEqual(json.loads(rows[0][2])['name'], 'httpx')
		finally:
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = orig

	def test_json_writes_suggestions_ndjson(self):
		from secator.hooks import json as mod
		runner = MagicMock(reports_folder=self.temp_dir)
		item = mod.update_finding(runner, _suggestion())
		mod.update_finding(runner, item)  # append-only, like results: last wins by _uuid on read
		self.assertFalse((Path(self.temp_dir) / 'results.ndjson').exists())
		lines = (Path(self.temp_dir) / 'suggestions.ndjson').read_text().splitlines()
		self.assertEqual([json.loads(line)['_uuid'] for line in lines], [item._uuid] * 2)
		self.assertEqual(json.loads(lines[0])['_type'], 'suggestion')

	def test_api_posts_suggestions_endpoint(self):
		from secator.hooks import api
		runner = MagicMock(context={'workspace_id': 'ws1', 'drivers': ['api']})
		with patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws')):
			with patch.object(api, '_make_request', return_value={'id': 'b' * 24}) as req:
				item = api.update_finding(runner, _suggestion())
				api.update_finding(runner, item)  # re-emitted by a parent runner: not posted again
		[call] = req.call_args_list
		method, endpoint, data = call.args
		self.assertEqual((method, endpoint), ('POST', api.API_SUGGESTION_CREATE_ENDPOINT))
		self.assertEqual(data['_context']['workspace_id'], 'a' * 24)
		self.assertEqual(data['name'], 'httpx')
		self.assertEqual(item._uuid, 'b' * 24)


if __name__ == '__main__':
	unittest.main()

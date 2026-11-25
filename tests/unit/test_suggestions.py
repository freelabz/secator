"""Runner suggestions: the Suggestion output type, the add_suggestion AI tool, and how each
driver stores a suggestion (its own store, never with findings)."""
import json
import shutil
import tempfile
import time
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
			{'type': 'task', 'name': 'httpx', 'targets': [None], 'reason': 'x'},
			{'type': 'task', 'name': 'httpx', 'targets': {'a.com': 1}, 'reason': 'x'},
			{'type': 'task', 'name': 'httpx', 'targets': ['a.com'], 'reason': 'x', 'priority': 'urgent'},
			{'type': 'task', 'name': 'httpx', 'targets': ['a.com'], 'reason': 'x', 'opts': ['x']},
		):
			[item] = self._run(**action)
			self.assertIsInstance(item, Error, action)

	def test_chat_mode_only(self):
		from secator.ai.prompts import MODES
		from secator.ai.tools import build_tool_schemas
		for mode in MODES:
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			for tool in ('add_suggestion', 'list_suggestions'):
				self.assertEqual(tool in names, mode == 'chat', (mode, tool))
		# an explicit extra_tools grant does not bring them into another mode
		names = [s['function']['name'] for s in build_tool_schemas('scan', extra_tools=['add_suggestion'])]
		self.assertNotIn('add_suggestion', names)

	def test_no_duplicate_rule_in_description_and_chat_prompt(self):
		from secator.ai.prompts import get_system_prompt
		from secator.ai.tools import TOOLS_BY_NAME
		description = TOOLS_BY_NAME['add_suggestion'].schema['function']['description']
		self.assertIn('Call list_suggestions first', description)
		self.assertIn('done or dismissed', description)
		self.assertIn('Call list_suggestions first', get_system_prompt('chat'))
		self.assertNotIn('list_suggestions', get_system_prompt('scan'))


class TestDriversStoreSuggestions(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def test_mongodb_writes_suggestions_collection_with_dedup(self):
		mongomock = pytest.importorskip('mongomock')
		pytest.importorskip('pymongo')  # provides bson; required by secator.hooks.mongodb
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


class TestListSuggestions(unittest.TestCase):
	"""list_suggestions reads each driver's store back, most recent first, capped."""

	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _list(self, drivers, workspace='ws1'):
		"""Run the list_suggestions tool in a session on ``drivers``; return the rows the model sees."""
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': workspace, 'drivers': drivers})
		return [r for r in TOOLS_BY_NAME['list_suggestions'].handle({}, ctx) if isinstance(r, dict)]

	@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
	def test_sqlite_session(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		orig = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.temp_dir) / 'test.db')
		sqlite_mod._conns.clear()
		try:
			for i in range(55):
				sqlite_mod.update_finding(MagicMock(), _suggestion(targets=[f'h{i}.com']))
			rows = self._list(['sqlite'])
			self.assertEqual(len(rows), 50)  # capped
			self.assertEqual(rows[0]['targets'], ['h54.com'])  # most recent first
			self.assertEqual(
				{k: rows[0][k] for k in ('type', 'name', 'source', 'status', 'reason')},
				{'type': 'task', 'name': 'httpx', 'source': 'ai', 'status': 'pending', 'reason': 'probe the hosts'})
			self.assertEqual(rows[0]['_type'], 'suggestion_row')
			self.assertEqual(self._list(['sqlite'], workspace='other'), [])
			sqlite_mod.update_finding(MagicMock(), _suggestion(targets=['h0.com']))  # re-added: moves to the top
			self.assertEqual(self._list(['sqlite'])[0]['targets'], ['h0.com'])
		finally:
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = orig

	@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
	def test_json_session(self):
		from secator.config import CONFIG
		from secator.hooks import json as mod
		from secator.utils import get_workspace_folder_name
		reports = Path(self.temp_dir)
		for i, run in enumerate(('tasks/1', 'tasks/2')):
			folder = reports / get_workspace_folder_name('ws1', reports) / run
			folder.mkdir(parents=True)
			item = mod.update_finding(MagicMock(reports_folder=str(folder)), _suggestion(targets=[f'h{i}.com']))
		mod.update_finding(MagicMock(reports_folder=str(folder)), item)  # re-emitted: last record wins
		with patch.object(CONFIG.dirs, 'reports', reports):
			rows = self._list(['json'])
		self.assertEqual([r['targets'] for r in rows], [['h1.com'], ['h0.com']])
		other = reports / get_workspace_folder_name('other', reports) / 'tasks/1'
		other.mkdir(parents=True)
		mod.update_finding(MagicMock(reports_folder=str(other)), _suggestion(targets=['x.com']))
		with patch.object(CONFIG.dirs, 'reports', reports):
			self.assertEqual([r['targets'] for r in self._list(['json'])], [['h1.com'], ['h0.com']])
			self.assertEqual([r['targets'] for r in self._list(['json'], workspace='other')], [['x.com']])

	def test_mongodb_backend(self):
		mongomock = pytest.importorskip('mongomock')
		pytest.importorskip('pymongo')
		from secator.hooks import mongodb
		from secator.query.mongodb import MongoDBBackend
		client = mongomock.MongoClient()
		with patch.object(mongodb, 'get_mongodb_client', return_value=client):
			mongodb.update_finding(MagicMock(), _suggestion(targets=['a.com']))
			mongodb.update_finding(MagicMock(), _suggestion(targets=['b.com']))
		client.main.suggestions.update_one({'data.targets': ['a.com']}, {'$set': {'context.dismissed': True}})
		backend = MongoDBBackend('ws1')
		backend._client = client
		from secator.ai.tools.suggestions import _summary
		rows = [_summary(d) for d in backend.list_suggestions(50)]
		self.assertEqual([(r['targets'], r['status']) for r in rows], [(['b.com'], 'pending'), (['a.com'], 'dismissed')])
		self.assertEqual(rows[0]['name'], 'httpx')
		other = MongoDBBackend('other')
		other._client = client
		self.assertEqual(other.list_suggestions(50), [])
		time.sleep(0.01)  # BSON dates keep milliseconds: avoid an updated_at tie
		with patch.object(mongodb, 'get_mongodb_client', return_value=client):
			mongodb.update_finding(MagicMock(), _suggestion(targets=['a.com']))  # re-added: moves to the top
		self.assertEqual(backend.list_suggestions(50)[0]['data']['targets'], ['a.com'])

	def test_api_backend(self):
		from secator.query.api import ApiBackend
		from secator.ai.tools.suggestions import _summary
		doc = {'data': {'type': 'scan', 'name': 'Basic domain scan', 'targets': ['a.com']}, 'context': {'done': True},
			'message': 'm', 'updated_at': '2026-01-01'}
		backend = ApiBackend('a' * 24)
		with patch.object(backend, '_make_request', return_value={'items': [doc]}) as req:
			[row] = [_summary(d) for d in backend.list_suggestions(50)]
		self.assertEqual(req.call_args.args, ('GET', f'workspace/{"a" * 24}/suggestions?skip=0&limit=50'))
		self.assertEqual((row['type'], row['name'], row['status'], row['source']), ('scan', 'Basic domain scan', 'done', ''))

	def test_api_backend_needs_a_workspace_id(self):
		from secator.query._base import QueryBackendError
		from secator.query.api import ApiBackend
		for workspace in ('my workspace', ''):
			backend = ApiBackend(workspace)
			with patch.object(backend, '_make_request') as req:
				with self.assertRaises(QueryBackendError):
					backend.list_suggestions(50)
			req.assert_not_called()

	@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
	def test_read_failure_is_an_error_not_an_empty_list(self):
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		from secator.output_types import Error, Info
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws1', 'drivers': ['sqlite']})
		engine = MagicMock()
		engine.list_suggestions.side_effect = RuntimeError('db down')
		with patch.object(ctx, 'get_query_engine', return_value=engine):
			out = list(TOOLS_BY_NAME['list_suggestions'].handle({}, ctx))
		self.assertTrue(any(isinstance(o, Error) and 'db down' in o.message for o in out))
		self.assertFalse(any(isinstance(o, (Info, dict)) for o in out))

	@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
	def test_has_more_fetches_one_extra(self):
		from secator.ai.actions import ActionContext
		from secator.ai.tools import TOOLS_BY_NAME
		from secator.output_types import Ai
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws1', 'drivers': ['sqlite']})
		engine = MagicMock()
		for count, has_more in ((50, False), (51, True)):
			engine.list_suggestions.return_value = [{'type': 'task', 'name': 'httpx'}] * count
			with patch.object(ctx, 'get_query_engine', return_value=engine):
				out = list(TOOLS_BY_NAME['list_suggestions'].handle({}, ctx))
			engine.list_suggestions.assert_called_with(51)
			[ai] = [o for o in out if isinstance(o, Ai)]
			self.assertEqual((ai.extra_data['count'], ai.extra_data['has_more']), (50, has_more))

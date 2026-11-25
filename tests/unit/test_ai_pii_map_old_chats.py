"""Resuming a chat saved by an older version resolves its placeholder map, on every driver.

Older versions wrote no ``session.json`` next to ``history.json``, and wrote no local report on
a store driver other than json. Such a chat has no known session id on resume: its map is read
from every map of the active workspace (a placeholder is a salted hash of its type and value
only), then re-keyed under the new run's id and pointed at by ``session.json``, so the next
resume reads it directly. Runs the real ai runner with a scripted model; the store of each
driver (json, sqlite, mongodb, api) is seeded with the map as the older version left it.
"""
import contextlib
import json
from types import SimpleNamespace as NS
from unittest import mock

import pytest

from secator.definitions import ADDONS_ENABLED

pytestmark = pytest.mark.skipif(not ADDONS_ENABLED.get('ai', False), reason='ai addon not installed')

WS = 'wsold'
OLD_SID = 'old-session'
HOST, IP, OTHER = 'internal-target.example.com', '10.20.30.40', 'other-ws.example.com'


def _plan_call(call_id, text):
	args = json.dumps({'items': [{'text': text}]})
	return NS(id=call_id, type='function', function=NS(name='update_plan', arguments=args))


def _map_doc(values, session_id=OLD_SID, workspace=WS):
	from secator.ai.encryption import SensitiveDataEncryptor
	enc = SensitiveDataEncryptor()
	for value in values:
		enc.encrypt(value)
	return {
		'_type': 'ai', 'ai_type': 'pii_map', 'content': '', '_uuid': f'pii-{session_id}-{workspace}',
		'_timestamp': 1, 'is_false_positive': False, '_tagged': False,
		'extra_data': {'pii_map': dict(enc.pii_map), 'hash_map': dict(enc.hash_map)},
		'_context': {'workspace_id': workspace, 'workspace_name': workspace, 'session_id': session_id}}


class _Store:
	"""One driver's store: ``insert`` writes a doc as that driver would, ``engine`` reads it."""

	def __init__(self, driver, reports):
		self.driver, self.reports = driver, reports
		if driver in ('mongodb', 'api'):
			mongomock = pytest.importorskip('mongomock')
			self.client = mongomock.MongoClient()

	def insert(self, doc):
		doc = json.loads(json.dumps(doc, default=str))
		if self.driver == 'json':
			folder = self.reports / doc['_context']['workspace_name'] / 'tasks' / 'seed'
			folder.mkdir(parents=True, exist_ok=True)
			with open(folder / 'results.ndjson', 'a') as f:
				f.write(json.dumps(doc) + '\n')
		elif self.driver == 'sqlite':
			import secator.hooks.sqlite as sqlite_mod
			conn = sqlite_mod.get_sqlite_conn(str(self.reports / 'store.db'))
			conn.execute(
				'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) VALUES (?, ?, ?, ?, ?, ?)',
				(doc['_uuid'], doc['_type'], doc['_context']['workspace_id'], 0, 0, json.dumps(doc)))
			conn.commit()
		else:
			self.client.main.findings.insert_one(doc)

	def engine(self):
		from secator.query import QueryEngine
		engine = QueryEngine(WS, context={'workspace_name': WS})
		if self.driver == 'sqlite':
			from secator.query.sqlite import SqliteBackend
			engine.backend = SqliteBackend(WS, config={'db_path': str(self.reports / 'store.db')})
		elif self.driver == 'mongodb':
			from secator.query.mongodb import MongoDBBackend
			engine.backend = MongoDBBackend(WS)
			engine.backend._client = self.client
		elif self.driver == 'api':
			from secator.query.api import ApiBackend
			engine.backend = ApiBackend(WS)

			def fake_request(method, endpoint, data=None):
				docs = list(self.client.main.findings.find(data or {}))
				for d in docs:
					d.pop('_id', None)
				return {'items': docs}
			engine.backend._make_request = fake_request
		return engine

	def close(self):
		import secator.hooks.sqlite as sqlite_mod
		for conn in sqlite_mod._conns.values():
			conn.close()
		sqlite_mod._conns.clear()


@pytest.fixture
def reports(tmp_path):
	from secator.config import CONFIG
	before = CONFIG.dirs.reports  # set by hand: a mock.patch of a pydantic config field does not restore cleanly
	CONFIG.dirs.reports = tmp_path
	yield tmp_path
	CONFIG.dirs.reports = before


def _write_chat(reports, with_report=False):
	"""history.json only (no session.json), as an older version left it; ``with_report`` adds
	the report a json-driver run exported, whose runner info carries the session id."""
	from secator.ai.encryption import SensitiveDataEncryptor
	enc = SensitiveDataEncryptor()
	folder = reports / WS / 'tasks' / '0'
	folder.mkdir(parents=True)
	history = [
		{'role': 'user', 'content': enc.encrypt(f'look at {HOST} and {IP}')},
		{'role': 'assistant', 'content': enc.encrypt(f'I will scan {HOST}.')}]
	(folder / 'history.json').write_text(json.dumps(history))
	if with_report:
		(folder / 'report.json').write_text(json.dumps({'info': {'name': 'ai', 'context': {'session_id': OLD_SID}}}))
	return enc.encrypt(HOST), enc.encrypt(IP)


def _resume(store, probes):
	"""Resume the latest chat; the model calls update_plan once per probe, then stops.

	Returns the plan texts that ran, the rejected calls' reasons, the ``_restore_pii_map``
	kwargs, the messages sent to the model, the debug lines and the runner."""
	import sys
	from secator.ai.interactivity import InteractivityBackend
	from secator.ai.session import list_sessions
	from secator.tasks.ai import ai as AiTask
	aimod = sys.modules['secator.tasks.ai']

	class Backend(InteractivityBackend):
		interactive = True

		def __init__(self):
			self.answers = ['continue']

		def get_initial_prompt(self, inputs, **context):
			return ''

		def ask_user(self, question, choices, session_id, prompt_type='stopped', **context):
			return {'answer': self.answers.pop(0)} if self.answers else None

	calls, restores, debug = [], [], []

	def llm(messages, *a, **k):
		calls.append(messages)
		if len(calls) == 1:
			return {'content': '', 'usage': {}, 'tool_calls': [_plan_call(f'c{i}', p) for i, p in enumerate(probes)]}
		return {'content': 'done', 'tool_calls': [], 'usage': {}}

	restore = AiTask._restore_pii_map

	def spy(runner, *a, **k):
		restores.append(k)
		return restore(runner, *a, **k)

	with contextlib.ExitStack() as stack:
		stack.enter_context(mock.patch.object(aimod, 'call_llm', llm))
		stack.enter_context(mock.patch.object(aimod, 'create_backend', lambda *a, **k: Backend()))
		stack.enter_context(mock.patch.object(
			aimod, 'show_session_picker', lambda sessions=None: (sessions or list_sessions())[0]))
		stack.enter_context(mock.patch.object(aimod.time, 'sleep', lambda *a: None))
		stack.enter_context(mock.patch.object(AiTask, '_get_query_engine', lambda runner: store.engine()))
		stack.enter_context(mock.patch.object(AiTask, '_restore_pii_map', spy))
		stack.enter_context(mock.patch.object(AiTask, 'debug', lambda runner, msg, *a, **k: debug.append(str(msg))))
		task = AiTask(
			[], mode='chat', model='gpt-4o', interactive='local', headless=True, sync=True,
			print_item=False, print_line=False, print_cmd=False, sensitive=True, resume=True,
			context={'workspace_name': WS})
		items = [i.toDict() if hasattr(i, 'toDict') else i for i in task]
	if store.driver != 'json':
		# that driver stores what the runner emits, and leaves no local report
		for item in items:
			if isinstance(item, dict) and item.get('ai_type') == 'pii_map':
				store.insert(item)
		for report in store.reports.glob(f'{WS}/tasks/*/report*.json'):
			report.unlink()
	plans = [i['extra_data']['items'][0]['text'] for i in items if isinstance(i, dict) and i.get('ai_type') == 'plan']
	rejected = [i['extra_data']['reason'] for i in items if isinstance(i, dict)
	            and i.get('ai_type') == 'tool_result' and (i.get('extra_data') or {}).get('error')]
	return NS(plans=plans, rejected=rejected, restores=restores, calls=calls, debug=debug, task=task)


@pytest.mark.parametrize('driver', ['json', 'sqlite', 'mongodb', 'api'])
@pytest.mark.parametrize('with_report', [False, True], ids=['no-report', 'report'])
def test_old_chat_resolves_its_map_then_resumes_directly(reports, driver, with_report):
	store = _Store(driver, reports)
	try:
		ph_host, ph_ip = _write_chat(reports, with_report=with_report)
		store.insert(_map_doc([HOST, IP]))
		store.insert(_map_doc([OTHER], session_id='elsewhere', workspace='wsother'))  # never read

		run = _resume(store, [f'probe {ph_host}', f'probe {ph_ip}'])
		assert run.plans == [f'probe {HOST}', f'probe {IP}']
		assert run.rejected == []
		assert OTHER not in run.task.encryptor.pii_map.values()
		assert HOST not in json.dumps(run.calls)
		# a known id (runner info in the report) is read directly, an unknown one from every map
		assert run.restores[0]['any_session'] is not with_report
		# the session file now points at the id the map was re-keyed under
		session_file = reports / WS / 'tasks' / '0' / 'session.json'
		assert json.loads(session_file.read_text()) == {'session_id': run.task.session_id}

		again = _resume(store, [f'probe {ph_host}'])
		assert again.plans == [f'probe {HOST}']
		assert not any(k.get('any_session') for k in again.restores)
	finally:
		store.close()


def test_no_map_stored_degrades_cleanly(reports):
	"""A run killed before its map was stored: no crash, the model keeps its placeholders, a
	call using one is rejected (never run with the literal placeholder), one debug line."""
	ph_host, _ = _write_chat(reports)
	run = _resume(_Store('json', reports), [f'probe {ph_host}'])
	assert run.plans == []
	assert len(run.rejected) == 1 and ph_host in run.rejected[0]
	assert ph_host in json.dumps(run.calls)
	assert [m for m in run.debug if 'no stored map' in m] == ['pii_map restore: no stored map for the workspace']


def test_partial_map_stored_resolves_what_it_has(reports):
	store = _Store('json', reports)
	ph_host, ph_ip = _write_chat(reports)
	store.insert(_map_doc([HOST]))  # the IP was minted after the last store
	run = _resume(store, [f'probe {ph_host}', f'probe {ph_ip}'])
	assert run.plans == [f'probe {HOST}']
	assert len(run.rejected) == 1 and ph_ip in run.rejected[0]

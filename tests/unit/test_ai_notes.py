"""Tests for the AI `add_note` tool + the query-backend note write path.

A note is an append-only annotation attached to a finding by its STABLE dedup identity
(``target_type`` + ``target_key``), stored in a dedicated notes store — never on the finding,
never keyed by the mutable ``_uuid``. Persistence follows the active driver: mongodb/sqlite/json
write locally, the api driver POSTs to the platform notes endpoint. These tests mock the query
engine (handler behaviour) and exercise the backend ``create_note`` scoping directly.
"""

import unittest
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext, dispatch_action, _NOTE_IDENTITY_FIELDS
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestAddNoteTool(unittest.TestCase):

	def _ctx(self, engine):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		ctx._query_engine = engine
		return ctx

	def _engine(self, existing, written=1):
		e = MagicMock()
		e.search.return_value = [dict(existing)] if existing else []
		e.create_note.return_value = written
		return e

	# ---- identity derivation mirrors the core dedup compare-key -------------------

	def test_identity_fields_match_compare_key(self):
		self.assertEqual(_NOTE_IDENTITY_FIELDS['vulnerability'], ['name', 'id', 'matched_at'])
		self.assertEqual(_NOTE_IDENTITY_FIELDS['url'], ['url'])
		self.assertEqual(_NOTE_IDENTITY_FIELDS['port'], ['port', 'ip', 'state'])
		for flds in _NOTE_IDENTITY_FIELDS.values():
			self.assertFalse(any(f.startswith('_') for f in flds))

	# ---- tool wiring --------------------------------------------------------------

	def test_tool_exposed_in_active_modes_only(self):
		for mode in ('scan', 'exploit', 'research'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			self.assertIn('add_note', names, f'add_note missing from {mode}')
		chat_names = [s['function']['name'] for s in build_tool_schemas('chat')]
		self.assertNotIn('add_note', chat_names, 'add_note must not be in read-only chat')

	def test_tool_call_maps_to_action(self):
		a = tool_call_to_action('add_note', {'_uuid': 'u1', 'body': 'looks real'})
		self.assertEqual(a['action'], 'add_note')

	def test_guardrails_auto_allow(self):
		engine = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		self.assertEqual(engine.check_action({'action': 'add_note', '_uuid': 'u1'}).decision, 'allow')

	# ---- happy path ---------------------------------------------------------------

	def test_add_note_persists_with_identity_key(self):
		finding = {'_uuid': 'u1', '_type': 'vulnerability', 'name': 'CVE-2016-20012',
		           'id': 'CVE-2016-20012', 'matched_at': 'http://h'}
		e = self._engine(finding)
		out = list(dispatch_action({'action': 'add_note', '_uuid': 'u1', 'body': 'confirmed reachable'}, self._ctx(e)))
		e.create_note.assert_called_once()
		note = e.create_note.call_args.args[0]
		self.assertEqual(note['target_type'], 'vulnerability')
		self.assertEqual(note['target_key'], {'name': 'CVE-2016-20012', 'id': 'CVE-2016-20012', 'matched_at': 'http://h'})
		self.assertEqual(note['body'], 'confirmed reachable')
		self.assertEqual(note['changes'], [])
		self.assertEqual(note['_context']['workspace_id'], 'ws')
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'add_note'][0]
		self.assertIn('CVE-2016-20012', ai.content)

	def test_add_note_stringifies_scalar_identity(self):
		# port identity has int/str fields -> target_key stored as strings (matches the endpoint)
		finding = {'_uuid': 'u2', '_type': 'port', 'port': 443, 'ip': '1.2.3.4', 'state': 'open'}
		e = self._engine(finding)
		list(dispatch_action({'action': 'add_note', '_uuid': 'u2', 'body': 'tls service'}, self._ctx(e)))
		note = e.create_note.call_args.args[0]
		self.assertEqual(note['target_key'], {'port': '443', 'ip': '1.2.3.4', 'state': 'open'})

	def test_add_note_carries_changes(self):
		finding = {'_uuid': 'u3', '_type': 'url', 'url': 'http://h/a'}
		e = self._engine(finding)
		changes = [{'field': 'status_code', 'old': 200, 'new': 404}]
		list(dispatch_action({'action': 'add_note', '_uuid': 'u3', 'body': 'gone', 'changes': changes}, self._ctx(e)))
		note = e.create_note.call_args.args[0]
		self.assertEqual(note['changes'], changes)

	# ---- error paths --------------------------------------------------------------

	def test_add_note_requires_uuid_and_body(self):
		e = self._engine({'_uuid': 'u1', '_type': 'url', 'url': 'http://h'})
		no_uuid = list(dispatch_action({'action': 'add_note', 'body': 'x'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in no_uuid))
		no_body = list(dispatch_action({'action': 'add_note', '_uuid': 'u1', 'body': '  '}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in no_body))
		e.create_note.assert_not_called()

	def test_add_note_missing_finding_errors(self):
		e = self._engine(None)
		out = list(dispatch_action({'action': 'add_note', '_uuid': 'nope', 'body': 'x'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.create_note.assert_not_called()

	def test_add_note_bad_changes_errors(self):
		e = self._engine({'_uuid': 'u1', '_type': 'url', 'url': 'http://h'})
		action = {'action': 'add_note', '_uuid': 'u1', 'body': 'x', 'changes': {'field': 'x'}}
		out = list(dispatch_action(action, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.create_note.assert_not_called()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBackendCreateNote(unittest.TestCase):
	"""The base ``create_note`` enforces the workspace scope from the backend, never the body."""

	def test_scope_enforced_from_backend(self):
		from secator.query.json import JsonBackend
		captured = {}
		b = JsonBackend('ws-name', context={})
		b._execute_create_note = lambda note: captured.update(note) or 1
		# body tries to smuggle a different workspace; backend overrides with its own
		b.create_note({'target_type': 'url', 'body': 'x', '_context': {'workspace_id': 'ATTACKER'}})
		self.assertEqual(captured['_context']['workspace_id'], 'ws-name')

	def test_default_backend_has_no_notes_store(self):
		# A backend that doesn't override _execute_create_note returns 0 (no store), not a crash.
		from secator.query._base import QueryBackend

		class _Bare(QueryBackend):
			name = 'bare'

			def _execute_search(self, *a, **k):
				return []

			def _execute_count(self, *a, **k):
				return 0

			def _execute_update(self, *a, **k):
				return 0

		self.assertEqual(_Bare('ws').create_note({'target_type': 'url', 'body': 'x'}), 0)


if __name__ == '__main__':
	unittest.main()

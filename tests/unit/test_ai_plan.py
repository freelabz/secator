"""Tests for the AI update_plan (to-do list) tool."""

import unittest

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestUpdatePlan(unittest.TestCase):

	def _ctx(self):
		return ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})

	def test_tool_exposed_and_mapped(self):
		for mode in ('attack', 'chat', 'exploit'):
			self.assertIn('update_plan', [s['function']['name'] for s in build_tool_schemas(mode)], mode)
		self.assertEqual(tool_call_to_action('update_plan', {'items': []})['action'], 'update_plan')

	def test_guardrail_auto_allow(self):
		e = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		self.assertEqual(e.check_action({'action': 'update_plan', 'items': []}).decision, 'allow')

	def test_normalizes_and_counts(self):
		items = [
			{'text': 'Recon', 'status': 'done'},
			{'text': 'Enumerate', 'status': 'in_progress'},
			{'text': 'Exploit'},                      # default -> pending
			{'text': 'Skip me', 'status': 'BOGUS'},   # invalid -> pending
		]
		out = list(dispatch_action({'action': 'update_plan', 'items': items}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'plan']
		self.assertEqual(len(ai), 1)
		ed = ai[0].extra_data
		self.assertEqual(ed['total'], 4)
		self.assertEqual(ed['done'], 1)                       # one done
		self.assertEqual(ed['items'][2]['status'], 'pending')  # defaulted
		self.assertEqual(ed['items'][3]['status'], 'pending')  # invalid coerced
		self.assertEqual(ai[0].content, 'Enumerate')          # the in_progress step

	def test_accepts_plain_strings(self):
		out = list(dispatch_action({'action': 'update_plan', 'items': ['a', 'b']}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai)][0]
		self.assertEqual(ai.extra_data['total'], 2)
		self.assertTrue(all(i['status'] == 'pending' for i in ai.extra_data['items']))

	def test_empty_errors(self):
		out = dispatch_action({'action': 'update_plan', 'items': []}, self._ctx())
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_items_as_json_string(self):
		out = list(dispatch_action({'action': 'update_plan', 'items': '[{"text": "x", "status": "done"}]'}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai)][0]
		self.assertEqual(ai.extra_data['total'], 1)
		self.assertEqual(ai.extra_data['done'], 1)

	def test_drops_empty_text_items(self):
		out = list(dispatch_action({'action': 'update_plan', 'items': [{'text': '  '}, {'text': 'keep'}]}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai)][0]
		self.assertEqual([i['text'] for i in ai.extra_data['items']], ['keep'])


if __name__ == '__main__':
	unittest.main()

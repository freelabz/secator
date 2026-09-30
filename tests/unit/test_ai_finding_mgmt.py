"""Tests for AI finding-management tools: mark_vuln_exploited, mark_vuln_false_positive, update_finding."""

import unittest
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFindingMgmtTools(unittest.TestCase):

	def _ctx(self, engine):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		ctx._query_engine = engine
		return ctx

	def _engine(self, existing, modified=1):
		e = MagicMock()
		# search returns the existing finding (lookup / re-fetch); [] when it doesn't exist
		e.search.return_value = [dict(existing)] if existing else []
		e.update.return_value = modified
		return e

	def test_tools_exposed_in_modes(self):
		for mode in ('attack', 'chat', 'exploit'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			self.assertIn('mark_vuln_exploited', names, mode)
			self.assertIn('mark_vuln_false_positive', names, mode)
			self.assertIn('mark_vuln_exploit_failed', names, mode)
			self.assertIn('update_finding', names, mode)
			self.assertNotIn('add_vuln_poc', names, mode)
			self.assertNotIn('delete_finding', names, mode)

	def test_tool_call_maps_to_action(self):
		a = tool_call_to_action('mark_vuln_exploited', {'_uuid': 'u1', 'poc': 'x'})
		self.assertEqual(a['action'], 'mark_vuln_exploited')
		b = tool_call_to_action('mark_vuln_false_positive', {'_uuid': 'u1', 'reason': 'nope'})
		self.assertEqual(b['action'], 'mark_vuln_false_positive')
		c = tool_call_to_action('update_finding', {'_uuid': 'u1', 'fields': {'severity': 'high'}})
		self.assertEqual(c['action'], 'update_finding')

	def test_guardrails_auto_allow(self):
		engine = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		for act in ('mark_vuln_exploited', 'mark_vuln_false_positive', 'mark_vuln_exploit_failed', 'update_finding'):
			self.assertEqual(engine.check_action({'action': act, '_uuid': 'u1'}).decision, 'allow', act)

	def test_console_rendering_is_friendly(self):
		"""The action line uses a friendly label and shows the finding NAME, not the
		raw uuid or the redundant content sentence."""
		import re
		strip = lambda s: re.sub(r'\x1b\[[0-9;]*m', '', s)  # noqa: E731
		cases = [
			({'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '# poc'}, 'Marked exploited'),
			({'action': 'mark_vuln_false_positive', '_uuid': 'u1', 'reason': 'dup'}, 'Marked false positive'),
			({'action': 'mark_vuln_exploit_failed', '_uuid': 'u1', 'reason': 'waf'}, 'Marked exploit-failed'),
			({'action': 'update_finding', '_uuid': 'u1', 'fields': {'severity': 'high'}}, 'Updated finding'),
		]
		for action, label in cases:
			e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'name': 'CVE-2016-20012'})
			out = list(dispatch_action(action, self._ctx(e)))
			ai = [o for o in out if isinstance(o, Ai) and o.ai_type == action['action']][0]
			plain = strip(repr(ai))
			self.assertIn(label, plain, action['action'])
			self.assertIn('CVE-2016-20012', plain, action['action'])  # names the finding
			self.assertNotIn('u1', plain, action['action'])  # not the raw uuid / sentence

	# --- mark_vuln_exploited ---
	def test_exploited_sets_status_and_attaches_finding(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi'})
		out = list(dispatch_action(
			{'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '### Description\nx', 'confidence': 'high'},
			self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['status'], 'EXPLOITED')
		self.assertTrue(set_arg['verified'])
		self.assertFalse(set_arg['is_false_positive'])
		# the poc is date-stamped and keeps the original body
		self.assertRegex(set_arg['poc'], r'^_Exploited on \d{4}-\d{2}-\d{2}_')
		self.assertIn('### Description\nx', set_arg['poc'])
		self.assertEqual(set_arg['confidence_nb'], 1)
		# the result carries the re-fetched finding (so consumers can render it)
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_exploited']
		self.assertTrue(ai and ai[0].extra_data.get('finding'))
		self.assertIn('SQLi', ai[0].content)  # names the vuln, not the raw uuid

	def test_exploited_fills_remediation_and_impact(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi'})
		list(dispatch_action(
			{'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '### Description\nx',
			 'remediation': 'use parameterized queries', 'impact': 'full DB read'},
			self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['remediation'], 'use parameterized queries')
		self.assertEqual(set_arg['impact'], 'full DB read')
		# they must NOT be forced into the poc body
		self.assertNotIn('parameterized queries', set_arg['poc'])

	def test_exploited_omits_blank_remediation_impact(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi'})
		list(dispatch_action(
			{'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '### Description\nx',
			 'remediation': '   ', 'impact': ''},
			self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertNotIn('remediation', set_arg)
		self.assertNotIn('impact', set_arg)

	def test_exploited_requires_poc(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi'})
		out = list(dispatch_action({'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '  '}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_exploited_missing_uuid_errors(self):
		e = self._engine(None)
		out = list(dispatch_action({'action': 'mark_vuln_exploited', 'poc': 'x'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_exploited_unknown_uuid_errors(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability'}, modified=0)
		out = list(dispatch_action({'action': 'mark_vuln_exploited', '_uuid': 'nope', 'poc': 'x'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	# --- mark_vuln_false_positive ---
	def test_false_positive_sets_flag_and_attaches_finding(self):
		e = self._engine({'_uuid': 'u2', '_type': 'vulnerability', 'name': 'XSS'})
		out = list(dispatch_action(
			{'action': 'mark_vuln_false_positive', '_uuid': 'u2', 'reason': 'not reachable'}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertTrue(set_arg['is_false_positive'])
		self.assertEqual(set_arg['status'], 'FALSE_POSITIVE')
		self.assertFalse(set_arg['verified'])
		self.assertEqual(set_arg['extra_data.false_positive_reason'], 'not reachable')
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_false_positive']
		self.assertTrue(ai and ai[0].extra_data.get('finding'))  # finding attached (unlike the old FP path)
		self.assertIn('XSS', ai[0].content)

	def test_false_positive_missing_uuid_errors(self):
		e = self._engine(None)
		out = list(dispatch_action({'action': 'mark_vuln_false_positive'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_false_positive_unknown_uuid_errors(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability'}, modified=0)
		out = list(dispatch_action({'action': 'mark_vuln_false_positive', '_uuid': 'nope'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	# --- mark_vuln_exploit_failed ---
	def test_exploit_failed_sets_status_without_hiding(self):
		e = self._engine({'_uuid': 'u3', '_type': 'vulnerability', 'name': 'RCE'})
		out = list(dispatch_action(
			{'action': 'mark_vuln_exploit_failed', '_uuid': 'u3', 'reason': 'WAF blocked',
			 'remediation': 'patch to 1.2.3', 'impact': 'RCE'}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['status'], 'EXPLOIT FAILED')
		# stays visible + retryable: never touches is_false_positive or verified
		self.assertNotIn('is_false_positive', set_arg)
		self.assertNotIn('verified', set_arg)
		self.assertEqual(set_arg['remediation'], 'patch to 1.2.3')
		self.assertEqual(set_arg['impact'], 'RCE')
		self.assertEqual(set_arg['extra_data.exploit_failed_reason'], 'WAF blocked')
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_exploit_failed']
		self.assertTrue(ai and ai[0].extra_data.get('finding'))
		self.assertIn('RCE', ai[0].content)

	def test_exploit_failed_omits_blank_optionals(self):
		e = self._engine({'_uuid': 'u3', '_type': 'vulnerability', 'name': 'RCE'})
		list(dispatch_action({'action': 'mark_vuln_exploit_failed', '_uuid': 'u3'}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg, {'status': 'EXPLOIT FAILED'})

	def test_exploit_failed_missing_uuid_errors(self):
		e = self._engine(None)
		out = list(dispatch_action({'action': 'mark_vuln_exploit_failed'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	# --- update_finding (unchanged) ---
	def test_update_sets_fields_and_merges_extra_data(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'severity': 'low'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1',
			 'fields': {'severity': 'high', '_type': 'evil', 'tags': ['xss']},
			 'extra_data': {'note': 'merged'}}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['severity'], 'high')
		self.assertEqual(set_arg['tags'], ['xss'])
		self.assertNotIn('_type', set_arg)
		self.assertEqual(set_arg['extra_data.note'], 'merged')
		self.assertTrue(any(isinstance(o, Ai) and o.ai_type == 'update_finding' for o in out))

	def test_update_drops_readonly_and_path_fields(self):
		# SECURITY: only content passes the GENERIC update_finding. `*_path` (file-read), verdict
		# (forging verified/status/is_false_positive bypasses the dedicated tools' gates), derived,
		# framework/dedup `_`-fields, and a bare workspace_id are all dropped.
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'severity': 'low'})
		list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {
				'severity': 'high', 'tags': ['xss'],
				'screenshot_path': '/proc/self/environ',
				'verified': True, 'status': 'EXPLOITED', 'is_false_positive': True, 'confidence_nb': 1,
				'_source': 'evil', '_timestamp': 1, '_tagged': True, '_related': ['x'],
				'workspace_id': 'other-ws'}}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['severity'], 'high')
		self.assertEqual(set_arg['tags'], ['xss'])
		for k in ('screenshot_path', 'verified', 'status', 'is_false_positive', 'confidence_nb',
		          '_source', '_timestamp', '_tagged', '_related', 'workspace_id'):
			self.assertNotIn(k, set_arg, k)

	def test_drop_readonly_helper(self):
		from secator.ai.actions import _drop_readonly_fields
		# keeps content (incl. `id` — a vuln's CVE id, legit on create); drops framework/verdict/path
		out = _drop_readonly_fields({
			'name': 'x', 'id': 'CVE-2021-41773', 'severity': 'high',  # kept
			'screenshot_path': '/etc/passwd', '_source': 'e', '_tagged': True,
			'verified': True, 'status': 'EXPLOITED', 'confidence_nb': 1, 'workspace_id': 'w'})
		self.assertEqual(out, {'name': 'x', 'id': 'CVE-2021-41773', 'severity': 'high'})

	def test_update_missing_uuid_errors(self):
		out = list(dispatch_action({'action': 'update_finding', 'fields': {'x': 1}}, self._ctx(self._engine(None))))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_update_unknown_finding_errors(self):
		e = self._engine(None)  # lookup returns nothing
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'nope', 'fields': {'severity': 'high'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_update_refuses_target_finding(self):
		e = self._engine({'_uuid': 'u1', '_type': 'target', 'name': 'x.com'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {'name': 'evil.com'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_update_nothing_to_set_errors(self):
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {'_type': 'x'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()


if __name__ == '__main__':
	unittest.main()

"""Tests for AI finding-management tools: mark_vuln_exploited, mark_vuln_false_positive, update_finding."""

import unittest
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error, ExploitAttempt


class FakeEngine:
	"""A tiny in-memory QueryEngine: stores docs, filters search() by exact field match,
	applies update()'s ``$set`` (incl. dotted ``extra_data.x`` keys). Enough to exercise the
	append-and-rollup flow (mark_vuln_* record an ExploitAttempt, then derive the vuln status)."""

	def __init__(self, docs=None):
		self.docs = [dict(d) for d in (docs or [])]

	def _match(self, doc, query):
		return all(doc.get(k) == v for k, v in query.items() if k != 'scope_only')

	def search(self, query, limit=0, scope_only=False, **kw):
		res = [dict(d) for d in self.docs if self._match(d, query)]
		return res[:limit] if limit and limit > 0 else res

	def update(self, query, update, **kw):
		n = 0
		for d in self.docs:
			if not self._match(d, query):
				continue
			for k, val in update.get('$set', {}).items():
				if '.' in k:
					parent, child = k.split('.', 1)
					d.setdefault(parent, {})
					if isinstance(d.get(parent), dict):
						d[parent][child] = val
				else:
					d[k] = val
			n += 1
		return n

	def count(self, query, **kw):
		return len(self.search(query))

	def persist(self, items):
		"""Simulate the pipeline persisting yielded findings (assigns a _uuid like add_result)."""
		import uuid as _uuid
		for it in items:
			if isinstance(it, ExploitAttempt):
				d = it.toDict()
				d['_uuid'] = d.get('_uuid') or str(_uuid.uuid4())
				self.docs.append(d)


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
		# Finding-management tools are ACTION-mode only. Since #1469 `chat` is strictly
		# read-only, so it must NOT expose any finding-write tool (see
		# test_ai_loop.test_chat_mode_tool_surface).
		write_tools = ('mark_vuln_exploited', 'mark_vuln_false_positive',
		               'mark_vuln_exploit_failed', 'update_finding')
		for mode in ('scan', 'exploit'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			for t in write_tools:
				self.assertIn(t, names, f'{t} missing from {mode}')
			self.assertNotIn('add_vuln_poc', names, mode)
			self.assertNotIn('delete_finding', names, mode)
		chat_names = [s['function']['name'] for s in build_tool_schemas('chat')]
		for t in write_tools:
			self.assertNotIn(t, chat_names, f'{t} must not be exposed in read-only chat')

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

	def test_false_positive_refetch_bypasses_display_filter(self):
		"""A just-marked false positive is HIDDEN by the `is_false_positive:{$ne:True}`
		display filter, so a plain re-fetch returns nothing and the row degrades to the
		bare uuid ("Updated Marked <uuid>…"). The re-fetch must pass scope_only=True so the
		finding (its name) still comes back. Mock search returns the finding ONLY when
		scope_only=True (modeling the display filter the default _engine mock ignores)."""
		finding = {'_uuid': 'u1', '_type': 'vulnerability', 'name': 'CVE-2016-20012'}
		e = MagicMock()

		def _search(query, limit=0, dedupe=False, exclude_fields=None, scope_only=False):
			if query.get('_type') == 'exploit_attempt':
				return []  # no prior attempts
			# The post-$set re-fetch carries _type=vulnerability and is hidden by the display
			# filter unless scope_only=True; the pre-FP lookup (by _uuid, no _type) is visible.
			if query.get('_type') == 'vulnerability':
				return [dict(finding)] if scope_only else []
			if '_uuid' in query:
				return [dict(finding)]
			return []
		e.search.side_effect = _search
		e.update.return_value = 1
		out = list(dispatch_action(
			{'action': 'mark_vuln_false_positive', '_uuid': 'u1', 'reason': 'dup'}, self._ctx(e)))
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_false_positive'][0]
		self.assertIn('CVE-2016-20012', ai.content)   # names the finding, not the bare uuid
		self.assertNotIn('u1', ai.content)
		self.assertTrue(ai.extra_data.get('finding'))  # attached so the UI renders name + card
		# the FP determination is recorded as an append-only attempt
		self.assertTrue([o for o in out if isinstance(o, ExploitAttempt) and o.verdict == 'false_positive'])

	# --- mark_vuln_exploited ---
	def test_exploited_sets_status_and_attaches_finding(self):
		vuln = {'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi', 'id': 'CVE-1', 'matched_at': 'http://x'}
		e = FakeEngine([vuln])
		out = list(dispatch_action(
			{'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '### Description\nx', 'confidence': 'high'},
			self._ctx(e)))
		# an append-only SUCCESS attempt is recorded, carrying the vuln identity + a date-stamped poc
		att = [o for o in out if isinstance(o, ExploitAttempt)]
		self.assertEqual(len(att), 1)
		self.assertEqual(att[0].verdict, 'success')
		self.assertEqual((att[0].vuln_name, att[0].vuln_id, att[0].matched_at), ('SQLi', 'CVE-1', 'http://x'))
		self.assertRegex(att[0].poc, r'^_Exploited on \d{4}-\d{2}-\d{2}_')
		# the vuln is ROLLED UP to EXPLOITED/verified with the derived poc + a recap count
		v = e.search({'_uuid': 'u1'})[0]
		self.assertEqual(v['status'], 'EXPLOITED')
		self.assertTrue(v['verified'])
		self.assertIn('### Description\nx', v['poc'])
		self.assertEqual(v['confidence_nb'], 1)
		self.assertEqual(v['extra_data']['exploit_attempts']['success'], 1)
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_exploited']
		self.assertTrue(ai and ai[0].extra_data.get('finding') and ai[0].extra_data.get('attempt'))
		self.assertIn('SQLi', ai[0].content)  # names the vuln, not the raw uuid

	def test_exploited_fills_remediation_and_impact(self):
		vuln = {'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi', 'id': '', 'matched_at': ''}
		e = FakeEngine([vuln])
		list(dispatch_action(
			{'action': 'mark_vuln_exploited', '_uuid': 'u1', 'poc': '### Description\nx',
			 'remediation': 'use parameterized queries', 'impact': 'full DB read'},
			self._ctx(e)))
		# remediation/impact stay VULN-owned (not in the poc, not on the attempt)
		v = e.search({'_uuid': 'u1'})[0]
		self.assertEqual(v['remediation'], 'use parameterized queries')
		self.assertEqual(v['impact'], 'full DB read')
		self.assertNotIn('parameterized queries', v['poc'])

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
		e = FakeEngine([{'_uuid': 'u1', '_type': 'vulnerability', 'name': 'SQLi'}])
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
		vuln = {'_uuid': 'u3', '_type': 'vulnerability', 'name': 'RCE', 'id': '', 'matched_at': ''}
		e = FakeEngine([vuln])
		out = list(dispatch_action(
			{'action': 'mark_vuln_exploit_failed', '_uuid': 'u3', 'reason': 'WAF blocked',
			 'remediation': 'patch to 1.2.3', 'impact': 'RCE'}, self._ctx(e)))
		# a FAILED attempt is recorded (append-only history)
		att = [o for o in out if isinstance(o, ExploitAttempt)]
		self.assertEqual(len(att), 1)
		self.assertEqual(att[0].verdict, 'failed')
		self.assertEqual(att[0].reason, 'WAF blocked')
		# the vuln is EXPLOIT FAILED but stays visible: is_false_positive untouched, verified False
		v = e.search({'_uuid': 'u3'})[0]
		self.assertEqual(v['status'], 'EXPLOIT FAILED')
		self.assertFalse(v['verified'])
		self.assertNotEqual(v.get('is_false_positive'), True)
		self.assertEqual(v['remediation'], 'patch to 1.2.3')
		self.assertEqual(v['impact'], 'RCE')
		self.assertEqual(v['extra_data']['exploit_failed_reason'], 'WAF blocked')
		self.assertEqual(v['extra_data']['exploit_attempts']['failed'], 1)
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'mark_vuln_exploit_failed']
		self.assertTrue(ai and ai[0].extra_data.get('finding'))
		self.assertIn('RCE', ai[0].content)

	def test_exploit_failed_verdict_partial(self):
		vuln = {'_uuid': 'u3', '_type': 'vulnerability', 'name': 'RCE', 'id': '', 'matched_at': ''}
		e = FakeEngine([vuln])
		out = list(dispatch_action(
			{'action': 'mark_vuln_exploit_failed', '_uuid': 'u3', 'verdict': 'partial'}, self._ctx(e)))
		att = [o for o in out if isinstance(o, ExploitAttempt)]
		self.assertEqual(att[0].verdict, 'partial')
		self.assertEqual(e.search({'_uuid': 'u3'})[0]['status'], 'EXPLOIT FAILED')

	def test_exploit_failed_omits_blank_optionals(self):
		vuln = {'_uuid': 'u3', '_type': 'vulnerability', 'name': 'RCE', 'id': '', 'matched_at': ''}
		e = FakeEngine([vuln])
		list(dispatch_action({'action': 'mark_vuln_exploit_failed', '_uuid': 'u3'}, self._ctx(e)))
		v = e.search({'_uuid': 'u3'})[0]
		self.assertEqual(v['status'], 'EXPLOIT FAILED')
		self.assertNotIn('remediation', v)  # no blank enrichment written

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

	# --- update_finding: attack-surface cleanup verdicts on NON-vuln types ---
	def test_update_hides_non_vuln_finding_via_is_false_positive(self):
		# A subdomain that no longer resolves: the monitor retires it via the generic hide-flag
		# (no dedicated tool for non-vuln types). Server-derived, recoverable, reason-stamped.
		e = self._engine({'_uuid': 's1', '_type': 'subdomain', 'host': 'gone.example.com'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 's1',
			 'fields': {'is_false_positive': True},
			 'extra_data': {'false_positive_reason': 'attack-surface-monitor: not reproduced 2026-10-05'}},
			self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertTrue(set_arg['is_false_positive'])
		self.assertEqual(set_arg['extra_data.false_positive_reason'],
		                 'attack-surface-monitor: not reproduced 2026-10-05')
		self.assertTrue(any(isinstance(o, Ai) and o.ai_type == 'update_finding' for o in out))

	def test_update_vuln_still_drops_is_false_positive(self):
		# A vulnerability keeps using the dedicated mark_vuln_false_positive tool, so the generic
		# path must still strip is_false_positive for vulns (policy unchanged).
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'severity': 'low'})
		list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1',
			 'fields': {'severity': 'high', 'is_false_positive': True}}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['severity'], 'high')
		self.assertNotIn('is_false_positive', set_arg)

	def test_update_errors_hiding_type_without_flag(self):
		# Hiding a type that has no is_false_positive field must refuse, not write a phantom
		# field. Pick such a type dynamically: once the finding-verdict-fields schema change
		# lands, EVERY editable finding type carries the flag and this guard is defensive-only,
		# so skip rather than asserting on a type that no longer lacks it.
		from secator.output_types import FINDING_TYPES
		fieldless = next((c for c in FINDING_TYPES
		                  if 'is_false_positive' not in getattr(c, '__dataclass_fields__', {})
		                  and c.get_name() != 'ai'), None)
		if fieldless is None:
			self.skipTest('every finding type now carries is_false_positive')
		e = self._engine({'_uuid': 'c1', '_type': fieldless.get_name(), 'name': 'x', 'host': 'x'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'c1', 'fields': {'is_false_positive': True}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_update_confidence_downgrade_recomputes_nb(self):
		# Degraded (not gone): downgrade confidence. Where the type carries confidence_nb the
		# derived sort key is recomputed so the downgrade actually re-prioritizes.
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'confidence': 'high'})
		list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {'confidence': 'low'}}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['confidence'], 'low')
		self.assertEqual(set_arg['confidence_nb'], 3)

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

	def test_update_refuses_non_finding_record(self):
		# CWE-862: a known _uuid must not let the agent edit an internal record (ai/error/…).
		e = self._engine({'_uuid': 'u1', '_type': 'ai', 'content': 'x'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {'content': 'evil'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		e.update.assert_not_called()

	def test_update_validates_field_shapes(self):
		# A wrong-shaped value (tags as a string where a list is required) is rejected, not $set raw.
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'severity': 'low'})
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1', 'fields': {'tags': 'xss'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) and 'tags' in o.message for o in out))
		e.update.assert_not_called()

	def test_update_fields_extra_data_merges_dotted(self):
		# extra_data passed inside `fields` must merge via dotted keys (not a whole-object $set
		# that clobbers existing keys / conflicts with extra_data.* on Mongo).
		e = self._engine({'_uuid': 'u1', '_type': 'vulnerability', 'severity': 'low'})
		list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'u1',
			 'fields': {'severity': 'high', 'extra_data': {'note': 'x'}}}, self._ctx(e)))
		set_arg = e.update.call_args[0][1]['$set']
		self.assertEqual(set_arg['severity'], 'high')
		self.assertEqual(set_arg['extra_data.note'], 'x')  # dotted
		self.assertNotIn('extra_data', set_arg)            # never a whole-object $set


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestExploitAttempt(unittest.TestCase):
	"""The append-only ExploitAttempt model: each mark_vuln_* records an attempt and the vuln's
	status/poc are DERIVED from the whole set (success sticky), across all occurrences."""

	VULN = {'_uuid': 'v1', '_type': 'vulnerability', 'name': 'SQLi', 'id': 'CVE-1', 'matched_at': 'http://x'}

	def _ctx(self, engine):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws', 'session_id': 's1'})
		ctx._query_engine = engine
		return ctx

	def _dispatch(self, e, action):
		"""Dispatch + simulate the pipeline persisting the yielded attempt (so the NEXT rollup sees it)."""
		out = list(dispatch_action(action, self._ctx(e)))
		e.persist([o for o in out if isinstance(o, ExploitAttempt)])
		return out

	def test_type_registered_and_dedup_exempt(self):
		self.assertEqual(ExploitAttempt.get_name(), 'exploit_attempt')
		a = ExploitAttempt(name='t', vuln_id='CVE-1', session_id='s', command='c', _timestamp=1.0)
		b = ExploitAttempt(name='t', vuln_id='CVE-1', session_id='s', command='c', _timestamp=2.0)
		self.assertNotEqual(a._compare_key(), b._compare_key())  # distinct history, never merged by dedup

	def test_success_is_sticky_over_later_failures(self):
		e = FakeEngine([dict(self.VULN)])
		self._dispatch(e, {'action': 'mark_vuln_exploit_failed', '_uuid': 'v1', 'reason': 'waf'})
		self.assertEqual(e.search({'_uuid': 'v1'})[0]['status'], 'EXPLOIT FAILED')
		self._dispatch(e, {'action': 'mark_vuln_exploited', '_uuid': 'v1', 'poc': '### Description\nwin'})
		self.assertEqual(e.search({'_uuid': 'v1'})[0]['status'], 'EXPLOITED')
		# a later failure must NOT downgrade an already-EXPLOITED vuln
		self._dispatch(e, {'action': 'mark_vuln_exploit_failed', '_uuid': 'v1', 'reason': 'flaky'})
		v = e.search({'_uuid': 'v1'})[0]
		self.assertEqual(v['status'], 'EXPLOITED')
		self.assertTrue(v['verified'])
		self.assertIn('win', v['poc'])  # derived poc comes from the successful attempt
		self.assertEqual(v['extra_data']['exploit_attempts'],
						 {'success': 1, 'failed': 2, 'partial': 0, 'false_positive': 0})

	def test_success_then_failed_order_independent(self):
		e = FakeEngine([dict(self.VULN)])
		self._dispatch(e, {'action': 'mark_vuln_exploited', '_uuid': 'v1', 'poc': 'win'})
		self._dispatch(e, {'action': 'mark_vuln_exploit_failed', '_uuid': 'v1'})
		self.assertEqual(e.search({'_uuid': 'v1'})[0]['status'], 'EXPLOITED')

	def test_rollup_updates_all_occurrences(self):
		ident = {'_type': 'vulnerability', 'name': 'SQLi', 'id': 'CVE-1', 'matched_at': 'http://x'}
		e = FakeEngine([{'_uuid': 'v1', **ident}, {'_uuid': 'v2', '_duplicate': True, **ident}])
		self._dispatch(e, {'action': 'mark_vuln_exploited', '_uuid': 'v1', 'poc': 'win'})
		self.assertEqual(e.search({'_uuid': 'v1'})[0]['status'], 'EXPLOITED')
		self.assertEqual(e.search({'_uuid': 'v2'})[0]['status'], 'EXPLOITED')  # the duplicate stays consistent

	def test_add_finding_exploit_attempt_rejected(self):
		e = FakeEngine([])
		out = list(dispatch_action(
			{'action': 'add_finding', '_type': 'exploit_attempt',
			 'fields': {'name': 'forged', 'verdict': 'success'}}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		self.assertFalse([o for o in out if isinstance(o, ExploitAttempt)])

	def test_false_positive_recorded_as_attempt(self):
		# mark_vuln_false_positive records a 'false_positive' attempt + the recap, and keeps
		# the vuln hidden (is_false_positive) — NOT re-derived as EXPLOITED/EXPLOIT FAILED.
		e = FakeEngine([dict(self.VULN)])
		self._dispatch(e, {'action': 'mark_vuln_false_positive', '_uuid': 'v1', 'reason': 'not reachable'})
		att = [d for d in e.docs if d.get('_type') == 'exploit_attempt']
		self.assertEqual(len(att), 1)
		self.assertEqual(att[0]['verdict'], 'false_positive')
		v = e.search({'_uuid': 'v1'})[0]
		self.assertTrue(v['is_false_positive'])
		self.assertEqual(v['status'], 'FALSE_POSITIVE')
		self.assertEqual(v['extra_data']['exploit_attempts']['false_positive'], 1)

	def test_update_finding_rejects_exploit_attempt(self):
		# append-only: update_finding must refuse to edit an attempt's evidence
		att = {'_uuid': 'a1', '_type': 'exploit_attempt', 'name': 'x', 'verdict': 'failed'}
		e = FakeEngine([att])
		out = list(dispatch_action(
			{'action': 'update_finding', '_uuid': 'a1', 'fields': {'verdict': 'success', 'poc': 'forged'}},
			self._ctx(e)))
		self.assertTrue(any(isinstance(o, Error) for o in out))
		self.assertEqual(e.search({'_uuid': 'a1'})[0]['verdict'], 'failed')  # unchanged

	def test_legacy_exploited_not_downgraded_by_failure(self):
		# a vuln already EXPLOITED (pre-ExploitAttempt model / before backfill) must NOT be
		# downgraded to EXPLOIT FAILED by a new failed attempt — its poc is preserved too.
		vuln = {'_uuid': 'v1', '_type': 'vulnerability', 'name': 'SQLi', 'id': 'CVE-1', 'matched_at': 'http://x',
		        'status': 'EXPLOITED', 'verified': True, 'poc': 'legacy win'}
		e = FakeEngine([vuln])
		self._dispatch(e, {'action': 'mark_vuln_exploit_failed', '_uuid': 'v1', 'reason': 'flaky'})
		v = e.search({'_uuid': 'v1'})[0]
		self.assertEqual(v['status'], 'EXPLOITED')
		self.assertTrue(v['verified'])
		self.assertEqual(v['poc'], 'legacy win')
		self.assertEqual(v['extra_data']['exploit_attempts']['failed'], 1)

	def test_rollup_lock_is_per_identity(self):
		from secator.ai.actions import _rollup_lock
		self.assertIs(_rollup_lock(('n', 'i', 'm')), _rollup_lock(('n', 'i', 'm')))
		self.assertIsNot(_rollup_lock(('n', 'i', 'm')), _rollup_lock(('n', 'i', 'OTHER')))


if __name__ == '__main__':
	unittest.main()

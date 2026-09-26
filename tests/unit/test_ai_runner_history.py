"""Tests for the AI list_runners tool + runner_history helpers (time windows, filtering, handler)."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai import runner_history as rh
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Info

NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRunnerHistoryHelpers(unittest.TestCase):

	def test_parse_dt_epoch_and_iso(self):
		self.assertEqual(rh.parse_dt(0), datetime(1970, 1, 1, tzinfo=timezone.utc))
		self.assertEqual(rh.parse_dt('1970-01-01T00:00:00Z'), datetime(1970, 1, 1, tzinfo=timezone.utc))
		self.assertEqual(rh.parse_dt('0'), datetime(1970, 1, 1, tzinfo=timezone.utc))  # stringified epoch
		self.assertIsNone(rh.parse_dt(None))
		self.assertIsNone(rh.parse_dt('not-a-date'))

	def test_parse_dt_naive_assumed_utc(self):
		self.assertEqual(rh.parse_dt(datetime(2020, 1, 1)), datetime(2020, 1, 1, tzinfo=timezone.utc))

	def test_parse_since_windows(self):
		from datetime import timedelta as _td
		self.assertEqual(rh.parse_since("24h", now=NOW), NOW - _td(days=1))
		self.assertEqual((NOW - rh.parse_since('30m', now=NOW)).total_seconds(), 1800)
		self.assertEqual((NOW - rh.parse_since('2w', now=NOW)).days, 14)
		self.assertIsNone(rh.parse_since('', now=NOW))
		self.assertIsNone(rh.parse_since(None, now=NOW))

	def test_parse_since_absolute_iso(self):
		self.assertEqual(rh.parse_since('2026-09-20', now=NOW),
		                 datetime(2026, 9, 20, tzinfo=timezone.utc))

	def test_filter_by_window_and_sort_newest_first(self):
		runners = [
			{'name': 'old', '_type': 'scans', 'status': 'SUCCESS', 'start_time': (NOW.timestamp() - 3 * 86400)},
			{'name': 'recent', '_type': 'scans', 'status': 'SUCCESS', 'start_time': (NOW.timestamp() - 3600)},
			{'name': 'mid', '_type': 'scans', 'status': 'FAILURE', 'start_time': (NOW.timestamp() - 5 * 3600)},
		]
		out = rh.filter_runners(runners, since='24h', now=NOW)
		self.assertEqual([r['name'] for r in out], ['recent', 'mid'])  # old dropped, newest first
		self.assertEqual(out[0]['_type'], 'scan')  # plural trimmed

	def test_filter_by_status(self):
		runners = [
			{'name': 'a', 'status': 'SUCCESS', 'start_time': NOW.timestamp()},
			{'name': 'b', 'status': 'FAILURE', 'start_time': NOW.timestamp()},
		]
		out = rh.filter_runners(runners, status='failure', now=NOW)
		self.assertEqual([r['name'] for r in out], ['b'])

	def test_filter_drops_untimed_when_since_set(self):
		runners = [{'name': 'notime', 'status': 'SUCCESS'}]
		self.assertEqual(rh.filter_runners(runners, since='24h', now=NOW), [])
		self.assertEqual(len(rh.filter_runners(runners, now=NOW)), 1)  # kept without a window

	def test_summary_is_compact(self):
		runner = {'name': 'x', 'status': 'SUCCESS', 'start_time': NOW.timestamp(), '_type': 'scans',
		          'config': {'huge': 'blob'}, 'results': list(range(999)), '_id': 'scans/3'}
		out = rh.filter_runners([runner], now=NOW)[0]
		self.assertNotIn('config', out)
		self.assertNotIn('results', out)
		self.assertEqual(out['_id'], 'scans/3')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestListRunnersTool(unittest.TestCase):

	def _ctx(self, engine):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		ctx._query_engine = engine
		return ctx

	def test_tool_exposed_in_modes(self):
		for mode in ('attack', 'chat', 'exploit'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			self.assertIn('list_runners', names, mode)

	def test_tool_call_maps_to_action(self):
		a = tool_call_to_action('list_runners', {'runner_type': 'scan', 'since': '24h'})
		self.assertEqual(a['action'], 'list_runners')
		self.assertEqual(a['runner_type'], 'scan')

	def test_guardrails_auto_allow(self):
		engine = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		self.assertEqual(engine.check_action({'action': 'list_runners'}).decision, 'allow')

	def test_handler_lists_and_marks_observation_only(self):
		e = MagicMock()
		e.backend.name = 'mongodb'
		e.list_runners.return_value = [
			{'name': 's1', 'status': 'SUCCESS', '_type': 'scans', 'start_time': datetime.now(timezone.utc).timestamp()},
		]
		out = list(dispatch_action({'action': 'list_runners', 'runner_type': 'scan', 'since': '24h'}, self._ctx(e)))
		# top-level runs only by default
		self.assertEqual(e.list_runners.call_args.kwargs['has_parent'], False)
		self.assertEqual(e.list_runners.call_args.kwargs['runner_type'], 'scan')
		ai = [o for o in out if isinstance(o, Ai)]
		self.assertEqual(ai[0].ai_type, 'list_runners')
		self.assertEqual(ai[0].extra_data['count'], 1)
		dict_rows = [o for o in out if isinstance(o, dict)]
		self.assertTrue(dict_rows and dict_rows[0]['_context']['ai_query_result'])

	def test_handler_include_children_opens_filter(self):
		e = MagicMock()
		e.backend.name = 'mongodb'
		e.list_runners.return_value = []
		list(dispatch_action({'action': 'list_runners', 'include_children': True}, self._ctx(e)))
		self.assertIsNone(e.list_runners.call_args.kwargs['has_parent'])

	def test_handler_empty_yields_info(self):
		e = MagicMock()
		e.backend.name = 'mongodb'
		e.list_runners.return_value = []
		out = list(dispatch_action({'action': 'list_runners', 'runner_type': 'scan'}, self._ctx(e)))
		self.assertTrue(any(isinstance(o, Info) for o in out))


if __name__ == '__main__':
	unittest.main()

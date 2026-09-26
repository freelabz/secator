"""Tests for the AI web_search tool: keyless engines, orchestration, handler, guardrails."""

import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai import web_search as ws
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error, Info


_DDG_HTML = '''
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa">First &amp; title</a>
<a class="result__snippet">Snippet <b>one</b></a>
<a class="result__a" href="https://example.org/b">Second</a>
<a class="result__snippet">Snippet two</a>
'''


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestWebSearchEngines(unittest.TestCase):

	def _resp(self, *, text=None, json_data=None):
		r = MagicMock()
		r.raise_for_status.return_value = None
		if text is not None:
			r.text = text
		if json_data is not None:
			r.json.return_value = json_data
		return r

	def test_duckduckgo_parses_and_unwraps(self):
		with patch.object(ws.requests, 'post', return_value=self._resp(text=_DDG_HTML)):
			results = ws.duckduckgo_search('log4shell', max_results=5)
		self.assertEqual(len(results), 2)
		# uddg-wrapped URL is unwrapped to the real target; entities unescaped
		self.assertEqual(results[0]['url'], 'https://example.com/a')
		self.assertEqual(results[0]['title'], 'First & title')
		self.assertEqual(results[0]['snippet'], 'Snippet one')
		self.assertEqual(results[1]['url'], 'https://example.org/b')

	def test_duckduckgo_respects_max_results(self):
		with patch.object(ws.requests, 'post', return_value=self._resp(text=_DDG_HTML)):
			results = ws.duckduckgo_search('x', max_results=1)
		self.assertEqual(len(results), 1)

	def test_duckduckgo_fails_soft(self):
		with patch.object(ws.requests, 'post', side_effect=Exception('network down')):
			results = ws.duckduckgo_search('x')
		self.assertEqual(results, [])  # no raise

	def test_sploitus_parses(self):
		payload = {'exploits': [
			{'title': 'PoC A', 'href': 'https://github.com/x/a', 'score': 9.8, 'type': 'exploit'},
			{'title': 'PoC B', 'href': 'https://github.com/x/b', 'score': 5.0, 'type': 'exploit'},
		]}
		with patch.object(ws.requests, 'post', return_value=self._resp(json_data=payload)):
			results = ws.sploitus_search('log4shell', max_results=10)
		self.assertEqual(len(results), 2)
		self.assertEqual(results[0]['_type'], 'exploit_result')
		self.assertEqual(results[0]['score'], 9.8)

	def test_web_search_exploit_mode_uses_sploitus(self):
		with patch.object(ws, 'sploitus_search', return_value=[{'_type': 'exploit_result'}]) as sp:
			results, engine = ws.web_search('cve', mode='exploit')
		self.assertEqual(engine, 'sploitus')
		sp.assert_called_once()

	def test_web_search_answer_falls_back_to_ddg_without_key(self):
		with patch.object(ws, 'duckduckgo_search', return_value=[{'_type': 'web_result'}]) as dd:
			results, engine = ws.web_search('q', mode='answer')
		self.assertEqual(engine, 'duckduckgo')
		dd.assert_called_once()

	def test_web_search_answer_uses_tavily_when_key_set(self):
		cfg = MagicMock()
		cfg.tavily_api_key = 'tvly-xxx'
		with patch.object(ws.CONFIG.addons.ai, 'web_search', cfg, create=True), \
			patch.object(ws, 'tavily_search', return_value=[{'_type': 'web_answer'}]) as tv:
			results, engine = ws.web_search('q', mode='answer')
		self.assertEqual(engine, 'tavily')
		tv.assert_called_once()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestWebSearchTool(unittest.TestCase):

	def test_tool_exposed_in_modes(self):
		for mode in ('attack', 'chat', 'exploit'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			self.assertIn('web_search', names, mode)

	def test_tool_call_maps_to_action(self):
		action = tool_call_to_action('web_search', {'query': 'cve', 'mode': 'exploit'})
		self.assertEqual(action['action'], 'web_search')
		self.assertEqual(action['query'], 'cve')

	def test_guardrails_allow_without_target_check(self):
		# scope set -> a task/shell would be gated, but web_search must pass unchecked.
		engine = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []},
		                          in_scope=['only.example.com'])
		result = engine.check_action({'action': 'web_search', 'query': 'anything'})
		self.assertEqual(result.decision, 'allow')

	def test_handler_yields_ai_and_hits(self):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		hits = [{'_type': 'web_result', 'title': 'T', 'url': 'https://e.com', 'snippet': 's'}]
		with patch('secator.ai.web_search.web_search', return_value=(hits, 'duckduckgo')):
			out = list(dispatch_action({'action': 'web_search', 'query': 'cve', 'mode': 'links'}, ctx))
		ai = [o for o in out if isinstance(o, Ai)]
		self.assertEqual(len(ai), 1)
		self.assertEqual(ai[0].ai_type, 'web_search')
		self.assertEqual(ai[0].extra_data['engine'], 'duckduckgo')
		# the hit is surfaced to the model as an observation-only dict
		dict_hits = [o for o in out if isinstance(o, dict) and o.get('_type') == 'web_result']
		self.assertEqual(len(dict_hits), 1)
		self.assertTrue(dict_hits[0]['_context']['ai_query_result'])

	def test_handler_empty_query_errors(self):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		out = list(dispatch_action({'action': 'web_search', 'query': '   '}, ctx))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_handler_no_results_yields_info(self):
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		with patch('secator.ai.web_search.web_search', return_value=([], 'duckduckgo')):
			out = list(dispatch_action({'action': 'web_search', 'query': 'cve'}, ctx))
		self.assertTrue(any(isinstance(o, Info) for o in out))


if __name__ == '__main__':
	unittest.main()

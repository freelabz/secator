"""Tests for the AI screenshot tool: scope gating, GCS-hook stripping, PNG embed, handler."""

import base64
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai import actions as A
	from secator.ai.actions import ActionContext, dispatch_action, _strip_gcs_hooks
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error, Url
	from secator.runners import Task


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestScreenshotWiring(unittest.TestCase):

	def test_tool_exposed_attack_exploit(self):
		for mode in ('attack', 'exploit'):
			self.assertIn('screenshot', [s['function']['name'] for s in build_tool_schemas(mode)], mode)

	def test_tool_call_mapping(self):
		self.assertEqual(tool_call_to_action('screenshot', {'url': 'https://x'})['action'], 'screenshot')

	def test_url_is_scope_gated_like_a_target(self):
		# screenshot touches the target, so the URL flows through the target layer: in-scope is
		# allowed, out-of-scope is gated (ask, like run_task), and an explicit deny blocks.
		e = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['*.example.com'])
		self.assertEqual(e.check_action({'action': 'screenshot', 'url': 'https://app.example.com'}).decision, 'allow')
		self.assertEqual(e.check_action({'action': 'screenshot', 'url': 'https://evil.other.com'}).decision, 'ask')
		e2 = PermissionEngine(config={'allow': [], 'deny': ['target(blocked.com)'], 'ask': []})
		self.assertEqual(e2.check_action({'action': 'screenshot', 'url': 'https://blocked.com'}).decision, 'deny')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStripGcsHooks(unittest.TestCase):

	def test_strips_only_gcs_on_item(self):
		def gcs_fn(self, item):
			return item
		gcs_fn.__module__ = 'secator.hooks.gcs'

		def mongo_fn(self, item):
			return item
		mongo_fn.__module__ = 'secator.hooks.mongodb'

		hooks = {Task: {'on_item': [gcs_fn, mongo_fn], 'on_end': [mongo_fn]}}
		out = _strip_gcs_hooks(hooks)
		self.assertEqual(out[Task]['on_item'], [mongo_fn])   # gcs dropped
		self.assertEqual(out[Task]['on_end'], [mongo_fn])    # untouched


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestScreenshotHandler(unittest.TestCase):

	def _ctx(self):
		return ActionContext(targets=[], model='m', context={'workspace_id': 'ws'}, silent=True)

	def _fake_runner(self, url_item):
		# A runner is iterable, yielding OutputTypes.
		class _R:
			def __iter__(_self):
				return iter([url_item] if url_item is not None else [])
		return _R()

	def test_captures_and_embeds_png(self):
		tmp = tempfile.mkdtemp()
		png = os.path.join(tmp, 'shot.png')
		open(png, 'wb').write(b'\x89PNG\r\n\x1a\nDATA')
		url_finding = Url(url='https://app.example.com', screenshot_path=png)
		with patch.object(A, '_child_preamble', return_value=({}, None)), \
			patch.object(A, 'TemplateLoader', return_value=MagicMock()), \
			patch.object(A, 'Task', return_value=self._fake_runner(url_finding)):
			out = list(dispatch_action(
				{'action': 'screenshot', 'url': 'https://app.example.com'}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'screenshot']
		self.assertEqual(len(ai), 1)
		uri = ai[0].extra_data['screenshot_data_uri']
		self.assertTrue(uri.startswith('data:image/png;base64,'))
		self.assertEqual(base64.b64decode(uri.split(',', 1)[1]), b'\x89PNG\r\n\x1a\nDATA')
		# observation-only result for the model, no bytes
		obs = [o for o in out if isinstance(o, dict) and o.get('_type') == 'screenshot']
		self.assertTrue(obs and obs[0]['captured'] and obs[0]['_context']['ai_query_result'])

	def test_no_image_errors(self):
		with patch.object(A, '_child_preamble', return_value=({}, None)), \
			patch.object(A, 'TemplateLoader', return_value=MagicMock()), \
			patch.object(A, 'Task', return_value=self._fake_runner(None)):
			out = list(dispatch_action(
				{'action': 'screenshot', 'url': 'https://app.example.com'}, self._ctx()))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_missing_url_errors(self):
		self.assertTrue(any(isinstance(o, Error) for o in dispatch_action({'action': 'screenshot'}, self._ctx())))

	def test_large_png_not_embedded(self):
		tmp = tempfile.mkdtemp()
		png = os.path.join(tmp, 'big.png')
		open(png, 'wb').write(b'x' * (A._MAX_SCREENSHOT_EMBED_BYTES + 10))
		url_finding = Url(url='https://app.example.com', screenshot_path=png)
		with patch.object(A, '_child_preamble', return_value=({}, None)), \
			patch.object(A, 'TemplateLoader', return_value=MagicMock()), \
			patch.object(A, 'Task', return_value=self._fake_runner(url_finding)):
			out = list(dispatch_action(
				{'action': 'screenshot', 'url': 'https://app.example.com'}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'screenshot'][0]
		self.assertEqual(ai.extra_data['screenshot_data_uri'], "")  # not embedded
		self.assertIn('too large', ai.content)


if __name__ == '__main__':
	unittest.main()

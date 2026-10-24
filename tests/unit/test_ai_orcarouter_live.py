# tests/unit/test_ai_orcarouter_live.py
"""Live OrcaRouter checks through the provider code path.

Runs only when ``ORCAROUTER_API_KEY`` is set in the environment (the verification
harness supplies it for live checks only). Everything goes through the provider
preset implemented in ``secator/ai/providers.py`` and ``call_llm`` — no direct
HTTP call from the test, so a green run proves the integration, not curl.

The key is never printed; only model ids and counts are asserted/logged.
"""
import os
import unittest

from secator.ai import providers

LIVE_KEY = (os.environ.get('ORCAROUTER_API_KEY') or '').strip()


@unittest.skipUnless(LIVE_KEY, 'ORCAROUTER_API_KEY not set: live OrcaRouter checks skipped')
class TestOrcaRouterLive(unittest.TestCase):
	def setUp(self):
		providers.reset_caches()

	def test_live_catalog_through_provider(self):
		result = providers.get_catalog(LIVE_KEY, provider_id='orcarouter', force=True)
		self.assertEqual(result.source, 'live', msg=f'catalog degraded: {result.error}')
		self.assertFalse(result.degraded)
		self.assertGreater(len(result.models), 0)

		# Every offered option must prove text-chat support; non-text-dedicated
		# models (image/video/rerank) must not leak into the chat selector.
		for model in result.models:
			self.assertTrue(model.supports_text, model.id)
			self.assertFalse(
				set(model.endpoint_types) and set(model.endpoint_types) <= providers.NON_TEXT_ENDPOINT_TYPES,
				model.id,
			)
		ids = {m.id for m in result.models}
		self.assertTrue(all('/' in mid for mid in ids), 'catalog ids keep the vendor namespace')

		# Metadata extracted from the live catalog is retained.
		with_context = [m for m in result.models if m.context_length > 0]
		self.assertTrue(with_context, 'at least some catalog entries advertise a context window')
		for m in with_context:
			self.assertEqual(providers.get_known_context_window(m.id), m.context_length)

		print(f'[live] OrcaRouter chat catalog: {len(result.models)} models')

	def test_live_chat_completion_through_call_llm(self):
		result = providers.get_catalog(LIVE_KEY, provider_id='orcarouter', force=True)
		if result.degraded:
			self.skipTest(f'catalog unavailable: {result.error}')

		ids = [m.id for m in result.models]
		# Per-key model scopes differ, and the catalog is workspace-wide: a listed
		# model is not necessarily callable by this key. Try a small preferred set
		# first and skip only when the key cannot call any of them.
		preferred = [
			'deepseek/deepseek-v4-pro', 'orcarouter/fusion',
			'orca/orcacyber-ultra-1.0', 'deepseek/deepseek-v4-flash',
		]
		order = [m for m in preferred if m in ids] + [m for m in ids if m not in preferred]

		from secator.ai.utils import call_llm
		response = None
		model = None
		last_error = None
		for candidate in order[:6]:
			try:
				response = call_llm(
					[{'role': 'user', 'content': 'Reply with only: OK'}],
					candidate,
					temperature=0,
					provider='orcarouter',
					api_key=LIVE_KEY,
				)
				model = candidate
				break
			except Exception as e:  # only a per-key model scope is retryable here
				if 'does not have access' in str(e).lower():
					last_error = e
					continue
				raise
		if response is None:
			self.skipTest(f'API key has no access to the tried catalog models: {last_error}')

		self.assertIn('content', response)
		self.assertTrue((response.get('content') or '').strip(), 'expected a non-empty completion')
		self.assertIsNotNone(response.get('usage'), 'a real completion must report usage')
		print(f'[live] OrcaRouter chat completion via call_llm: model={model}, '
			  f'tokens={response.get("usage", {}).get("tokens") if response.get("usage") else "n/a"}')


if __name__ == '__main__':
	unittest.main()

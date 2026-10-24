# tests/unit/test_ai_orcarouter_provider.py
"""Tests for the named OrcaRouter provider preset.

Covers the provider registry, base-URL/key resolution, the bounded live model
catalog, capability filtering (text + fail-closed multimodal), the verified
fallback seed and every catalog error class. No real network and no real key:
the HTTP layer is a fake session and every key used here is a fake literal.
"""
import json
import unittest

from secator.ai import providers


FAKE_KEY = 'sk-orca-test-not-a-real-key-0000'
AUTH_BASE = 'https://www.orcarouter.ai'
API_BASE = 'https://api.orcarouter.ai/v1'


CATALOG_FIXTURE = [
	{
		'id': 'openai/gpt-5.5',
		'context_length': 400000,
		'architecture': {'input_modalities': ['text', 'image'], 'output_modalities': ['text']},
		'supported_endpoint_types': ['openai'],
		'reasoning': True,
		'reasoning_efforts': ['low', 'medium', 'high', 'xhigh'],
	},
	{
		'id': 'anthropic/claude-opus-4.8',
		'context_length': 200000,
		'architecture': {'input_modalities': ['text', 'image']},
		'supported_endpoint_types': ['anthropic'],
	},
	{
		'id': 'acme/text-only',
		'context_length': 32000,
		'architecture': {'input_modalities': ['text']},
		'supported_endpoint_types': ['openai'],
	},
	{
		'id': 'acme/vision-chat',
		'context_length': 128000,
		'architecture': {'input_modalities': ['text', 'image']},
		'supported_endpoint_types': ['openai'],
	},
	{'id': 'acme/gemini-chat', 'supported_endpoint_types': ['gemini']},
	{'id': 'acme/embedding', 'supported_endpoint_types': ['embeddings']},
	{'id': 'acme/image-gen', 'supported_endpoint_types': ['image-generation']},
	{'id': 'acme/video', 'supported_endpoint_types': ['openai-video']},
	{'id': 'acme/rerank', 'supported_endpoint_types': ['jina-rerank']},
	{'id': ''},
	{'not-a-record': True},
]

CHAT_IDS = [
	'acme/gemini-chat', 'acme/text-only', 'acme/vision-chat',
	'anthropic/claude-opus-4.8', 'openai/gpt-5.5',
]


class FakeResponse:
	def __init__(self, status_code=200, payload=None, headers=None, chunks=None):
		self.status_code = status_code
		self.headers = headers or {}
		self._payload = payload
		self._chunks = chunks
		self.closed = False

	def iter_content(self, chunk_size=65536):
		if self._chunks is not None:
			for chunk in self._chunks:
				yield chunk
			return
		if self._payload is not None:
			yield self._payload

	def close(self):
		self.closed = True


class FakeSession:
	"""Minimal requests.Session stand-in that records every call."""

	def __init__(self, payload=None, status_code=200, exc=None, headers=None, chunks=None):
		self.payload = payload if payload is not None else {'data': CATALOG_FIXTURE}
		self.status_code = status_code
		self.exc = exc
		self.headers = headers
		self.chunks = chunks
		self.calls = []

	def get(self, url, **kwargs):
		self.calls.append({'url': url, **kwargs})
		if self.exc:
			raise self.exc
		body = self.payload if isinstance(self.payload, bytes) else json.dumps(self.payload).encode()
		return FakeResponse(
			status_code=self.status_code, payload=body,
			headers=self.headers, chunks=self.chunks,
		)


class FakeTimeout(Exception):
	pass


class BaseProviderTest(unittest.TestCase):
	def setUp(self):
		providers.reset_caches()

	def tearDown(self):
		providers.reset_caches()


class TestProviderRegistry(BaseProviderTest):
	def test_registry_exposes_orcarouter_as_first_class(self):
		spec = providers.get_provider('orcarouter')
		self.assertIsNotNone(spec)
		self.assertEqual(spec.id, 'orcarouter')
		self.assertEqual(spec.label, 'OrcaRouter')
		self.assertEqual(spec.default_api_base, API_BASE)
		self.assertEqual(spec.env_key, 'ORCAROUTER_API_KEY')
		self.assertEqual(spec.key_prefix, 'sk-orca-')

	def test_registry_lookup_is_case_insensitive(self):
		self.assertEqual(providers.get_provider('OrcaRouter').id, 'orcarouter')

	def test_unknown_provider_is_rejected(self):
		self.assertIsNone(providers.get_provider('nope'))
		with self.assertRaises(providers.ProviderConfigError):
			providers.require_provider('nope')

	def test_model_namespace_is_preserved_for_the_openai_adapter(self):
		# outer prefix selects the OpenAI-compatible adapter; the catalog's own
		# vendor namespace must survive on the wire.
		self.assertEqual(
			providers.to_litellm_model('orcarouter', 'deepseek/deepseek-v4-pro'),
			'openai/deepseek/deepseek-v4-pro',
		)
		self.assertEqual(
			providers.to_litellm_model('orcarouter', 'orca/orcacyber-ultra-1.0'),
			'openai/orca/orcacyber-ultra-1.0',
		)

	def test_model_mapping_is_identity_without_a_provider(self):
		self.assertEqual(providers.to_litellm_model(None, 'claude-sonnet-4-6'), 'claude-sonnet-4-6')
		self.assertEqual(providers.to_litellm_model('', 'gpt-4o'), 'gpt-4o')

	def test_model_mapping_does_not_double_prefix(self):
		self.assertEqual(
			providers.to_litellm_model('orcarouter', 'openai/deepseek/deepseek-v4-pro'),
			'openai/deepseek/deepseek-v4-pro',
		)


class TestApiBaseResolution(BaseProviderTest):
	def test_default_is_the_official_inference_origin(self):
		self.assertEqual(providers.resolve_api_base('orcarouter', '', env={}), API_BASE)

	def test_explicit_config_wins_over_every_override(self):
		env = {'ORCA_API_BASE_URL': 'https://api-alt.example/v1', 'ORCA_BASE_URL': 'https://shared.example'}
		self.assertEqual(
			providers.resolve_api_base('orcarouter', 'https://configured.example/v1', env=env),
			'https://configured.example/v1',
		)

	def test_explicit_api_override_wins_over_shared_base(self):
		env = {'ORCA_API_BASE_URL': 'https://api-alt.example/v1', 'ORCA_BASE_URL': 'https://shared.example'}
		self.assertEqual(providers.resolve_api_base('orcarouter', '', env=env), 'https://api-alt.example/v1')

	def test_shared_self_hosted_base_gets_v1_appended_once(self):
		self.assertEqual(
			providers.resolve_api_base('orcarouter', '', env={'ORCA_BASE_URL': 'https://shared.example'}),
			'https://shared.example/v1',
		)
		self.assertEqual(
			providers.resolve_api_base('orcarouter', '', env={'ORCA_BASE_URL': 'https://shared.example/v1/'}),
			'https://shared.example/v1',
		)

	def test_https_is_required_for_remote_hosts(self):
		with self.assertRaises(providers.ProviderConfigError):
			providers.resolve_api_base('orcarouter', 'http://api.example.com/v1', env={})

	def test_http_is_allowed_only_for_loopback(self):
		self.assertEqual(
			providers.resolve_api_base('orcarouter', 'http://127.0.0.1:8080/v1', env={}),
			'http://127.0.0.1:8080/v1',
		)
		self.assertEqual(
			providers.resolve_api_base('orcarouter', 'http://localhost:8080/v1', env={}),
			'http://localhost:8080/v1',
		)

	def test_rejects_embedded_credentials_and_query_strings(self):
		for bad in (
			'https://user:pass@api.example.com/v1',
			'https://api.example.com/v1?token=x',
			'https://api.example.com/v1#frag',
			'not-a-url',
		):
			with self.assertRaises(providers.ProviderConfigError, msg=bad):
				providers.resolve_api_base('orcarouter', bad, env={})

	def test_authentication_origin_is_never_derived_from_the_api_origin(self):
		# The API base resolves to api.orcarouter.ai; nothing in the inference path
		# may produce the www (auth) origin.
		base = providers.resolve_api_base('orcarouter', '', env={})
		self.assertEqual(base, 'https://api.orcarouter.ai/v1')
		self.assertNotIn('www.', base)


class TestApiKeyResolution(BaseProviderTest):
	def test_config_key_wins_over_environment(self):
		key = providers.resolve_api_key('orcarouter', 'sk-orca-config', env={'ORCAROUTER_API_KEY': 'sk-orca-env'})
		self.assertEqual(key, 'sk-orca-config')

	def test_environment_key_is_the_fallback(self):
		key = providers.resolve_api_key('orcarouter', '', env={'ORCAROUTER_API_KEY': 'sk-orca-env'})
		self.assertEqual(key, 'sk-orca-env')

	def test_missing_key_is_empty_not_an_error(self):
		self.assertEqual(providers.resolve_api_key('orcarouter', '', env={}), '')

	def test_mask_hides_the_secret(self):
		masked = providers.mask_api_key(FAKE_KEY)
		self.assertNotIn(FAKE_KEY, masked)
		self.assertIn('sk-orca-', masked)
		self.assertEqual(providers.mask_api_key(''), '')
		self.assertEqual(providers.mask_api_key('short'), '…')

	def test_prefix_is_a_hint_only(self):
		self.assertTrue(providers.key_prefix_matches('orcarouter', 'sk-orca-abc'))
		self.assertFalse(providers.key_prefix_matches('orcarouter', 'sk-ant-abc'))
		self.assertFalse(providers.key_prefix_matches('orcarouter', ''))


class TestCatalogParsingAndCapabilities(BaseProviderTest):
	def test_parse_keeps_catalog_metadata(self):
		model = providers.parse_model_record(CATALOG_FIXTURE[0])
		self.assertEqual(model.id, 'openai/gpt-5.5')
		self.assertEqual(model.context_length, 400000)
		self.assertEqual(model.input_modalities, ('text', 'image'))
		self.assertEqual(model.endpoint_types, ('openai',))
		self.assertTrue(model.reasoning)
		self.assertEqual(model.reasoning_efforts, ('low', 'medium', 'high', 'xhigh'))

	def test_parse_drops_unusable_records(self):
		self.assertIsNone(providers.parse_model_record({'id': ''}))
		self.assertIsNone(providers.parse_model_record({'not-a-record': True}))
		self.assertIsNone(providers.parse_model_record('nope'))

	def test_chat_filter_keeps_only_text_chat_models(self):
		models = [providers.parse_model_record(r) for r in CATALOG_FIXTURE]
		models = [m for m in models if m is not None]
		kept = [m.id for m in providers.chat_models(models)]
		self.assertEqual(kept, CHAT_IDS)
		for excluded in ('acme/embedding', 'acme/image-gen', 'acme/video', 'acme/rerank'):
			self.assertNotIn(excluded, kept)

	def test_capability_filters_are_independent(self):
		models = [providers.parse_model_record(r) for r in CATALOG_FIXTURE]
		models = [m for m in models if m is not None]
		self.assertEqual([m.id for m in providers.filter_models(models, capability='embedding')], ['acme/embedding'])
		self.assertEqual([m.id for m in providers.filter_models(models, capability='image')], ['acme/image-gen'])
		self.assertEqual([m.id for m in providers.filter_models(models, capability='video')], ['acme/video'])
		self.assertEqual([m.id for m in providers.filter_models(models, capability='rerank')], ['acme/rerank'])

	def test_multimodal_filter_fails_closed(self):
		models = [providers.parse_model_record(r) for r in CATALOG_FIXTURE]
		models = [m for m in models if m is not None]
		with_image = [m.id for m in providers.filter_models(models, 'chat', input_modalities=['image'])]
		# Only models that explicitly declare image input survive; undeclared
		# capabilities are never inferred from the model name.
		self.assertEqual(with_image, ['acme/vision-chat', 'anthropic/claude-opus-4.8', 'openai/gpt-5.5'])
		self.assertNotIn('acme/text-only', with_image)

	def test_unknown_capability_is_rejected(self):
		with self.assertRaises(ValueError):
			providers.filter_models([], capability='telepathy')


class TestLiveCatalog(BaseProviderTest):
	def test_request_shape_and_filtering(self):
		session = FakeSession()
		models = providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual([m.id for m in models], CHAT_IDS)

		self.assertEqual(len(session.calls), 1)
		call = session.calls[0]
		self.assertEqual(call['url'], f'{API_BASE}/models')
		self.assertEqual(call['params'], {'capability': 'chat'})
		self.assertEqual(call['headers']['Authorization'], f'Bearer {FAKE_KEY}')
		self.assertIn('timeout', call)

	def test_live_result_is_authoritative_and_seed_is_not_mixed_in(self):
		session = FakeSession()
		result = providers.get_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(result.source, 'live')
		self.assertFalse(result.degraded)
		ids = [m.id for m in result.models]
		self.assertEqual(ids, CHAT_IDS)
		self.assertNotIn('orcarouter/fusion', ids)

	def test_context_windows_from_the_catalog_are_remembered(self):
		providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=FakeSession())
		self.assertEqual(providers.get_known_context_window('openai/gpt-5.5'), 400000)
		self.assertEqual(providers.get_known_context_window('openai/openai/gpt-5.5'), 400000)

	def test_catalog_cache_avoids_a_second_request(self):
		session = FakeSession()
		providers.get_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		providers.get_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(len(session.calls), 1)

	def test_cache_keys_never_contain_the_api_key(self):
		providers.get_catalog(FAKE_KEY, api_base=API_BASE, session=FakeSession())
		self.assertTrue(providers._CATALOG_CACHE)
		for key in providers._CATALOG_CACHE:
			self.assertNotIn(FAKE_KEY, key)

	def test_max_items_bounds_the_parsed_records(self):
		session = FakeSession()
		models = providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session, max_items=2)
		self.assertLessEqual(len(models), 2)

	def test_no_key_is_refused_before_any_request(self):
		session = FakeSession()
		with self.assertRaises(providers.ProviderConfigError):
			providers.fetch_catalog('', api_base=API_BASE, session=session)
		self.assertEqual(session.calls, [])

	def test_auth_error_is_actionable_and_never_echoes_the_key(self):
		session = FakeSession(status_code=401)
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'auth')
		self.assertEqual(ctx.exception.status, 401)
		self.assertIn(AUTH_BASE, str(ctx.exception))
		self.assertNotIn(FAKE_KEY, str(ctx.exception))

	def test_rate_limit_error(self):
		session = FakeSession(status_code=429)
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'rate_limit')

	def test_network_error(self):
		session = FakeSession(exc=ConnectionError('boom'))
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'network')
		self.assertNotIn(FAKE_KEY, str(ctx.exception))

	def test_timeout_error(self):
		session = FakeSession(exc=FakeTimeout('read timed out'))
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'timeout')

	def test_malformed_json(self):
		session = FakeSession(payload=b'{not json')
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'invalid_response')

	def test_unexpected_shape(self):
		session = FakeSession(payload={'data': 'nope'})
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'invalid_response')

	def test_empty_catalog(self):
		session = FakeSession(payload={'data': [{'id': 'acme/embedding', 'supported_endpoint_types': ['embeddings']}]})
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'empty')

	def test_oversized_response_is_refused(self):
		session = FakeSession(chunks=[b'x' * (providers.MAX_CATALOG_BYTES + 1)])
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'invalid_response')

	def test_content_length_above_the_limit_is_refused_before_reading(self):
		session = FakeSession(headers={'Content-Length': str(providers.MAX_CATALOG_BYTES + 1)})
		with self.assertRaises(providers.CatalogError) as ctx:
			providers.fetch_catalog(FAKE_KEY, api_base=API_BASE, session=session)
		self.assertEqual(ctx.exception.kind, 'invalid_response')


class TestFallbacks(BaseProviderTest):
	def test_last_known_good_is_reused_after_a_failure(self):
		providers.get_catalog(FAKE_KEY, api_base=API_BASE, session=FakeSession())
		result = providers.get_catalog(FAKE_KEY, api_base=API_BASE, force=True,
									   session=FakeSession(status_code=500))
		self.assertEqual(result.source, 'last_known_good')
		self.assertTrue(result.degraded)
		self.assertEqual([m.id for m in result.models], CHAT_IDS)
		self.assertIsNotNone(result.error)

	def test_verified_fallback_seed_on_a_cold_failure(self):
		result = providers.get_catalog(FAKE_KEY, api_base=API_BASE,
									   session=FakeSession(exc=ConnectionError('down')))
		self.assertEqual(result.source, 'fallback')
		self.assertTrue(result.degraded)
		ids = [m.id for m in result.models]
		# The seed is presented in its declared order (the first entry is the
		# recommended default), so compare as a set-shaped sorted list.
		self.assertEqual(
			sorted(ids),
			['deepseek/deepseek-v4-flash', 'deepseek/deepseek-v4-pro',
			 'orca/orcacyber-ultra-1.0', 'orcarouter/fusion'],
		)

	def test_fallback_seed_preserves_verified_metadata(self):
		by_id = {m.id: m for m in providers.VERIFIED_FALLBACK_MODELS}
		fusion = by_id['orcarouter/fusion']
		self.assertEqual(fusion.context_length, 1_000_000)
		self.assertEqual(
			fusion.endpoint_types, ('openai', 'openai-response', 'anthropic', 'gemini')
		)
		self.assertTrue(fusion.supports_text)
		# The live record declares no image/audio/video input, so the seed must
		# not claim any (fail-closed consumers rely on this).
		self.assertEqual(fusion.input_modalities, ('text',))
		for model in providers.VERIFIED_FALLBACK_MODELS:
			self.assertGreater(model.context_length, 0, model.id)
			self.assertTrue(model.supports_text, model.id)

	def test_seed_metadata_is_available_before_any_live_call(self):
		self.assertEqual(providers.get_known_context_window('orcarouter/fusion'), 1_000_000)
		self.assertEqual(providers.get_known_context_window('deepseek/deepseek-v4-pro'), 1_048_576)

	def test_describe_model_exposes_metadata(self):
		model = providers.CatalogModel(
			id='vendor/reasoner', context_length=128000,
			input_modalities=('text', 'image'), reasoning=True,
			reasoning_efforts=('low', 'high'),
		)
		label = providers.describe_model(model)
		self.assertIn('vendor/reasoner', label)
		self.assertIn('ctx', label)
		self.assertIn('input text,image', label)
		self.assertIn('reasoning low/high', label)


if __name__ == '__main__':
	unittest.main()

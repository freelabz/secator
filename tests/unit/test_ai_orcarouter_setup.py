# tests/unit/test_ai_orcarouter_setup.py
"""Tests for the OrcaRouter wiring: setup flow, request routing, credentials.

These exercise the code paths a user actually goes through
(``secator x ai setup`` and ``call_llm``) with a fake catalog and a fake
litellm completion. No real key and no real network.
"""
import io
import os
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from secator.ai import providers
from secator.definitions import ADDONS_ENABLED


FAKE_KEY = 'sk-orca-test-not-a-real-key-0000'
API_BASE = 'https://api.orcarouter.ai/v1'

# Never let a real environment key or self-hosted override leak into these
# non-live tests: they must run on fake credentials only.
CLEAN_ENV = {'ORCAROUTER_API_KEY': '', 'ORCA_API_BASE_URL': '', 'ORCA_BASE_URL': ''}

CHAT_FIXTURES = (
	providers.CatalogModel(
		id='acme/text-only', context_length=32000,
		input_modalities=('text',), endpoint_types=('openai',),
	),
	providers.CatalogModel(
		id='openai/gpt-5.5', context_length=400000,
		input_modalities=('text', 'image'), endpoint_types=('openai',),
		reasoning=True, reasoning_efforts=('low', 'medium', 'high', 'xhigh'),
	),
)

NON_CHAT_MODEL = providers.CatalogModel(
	id='acme/image-gen', context_length=0,
	input_modalities=('text',), output_modalities=('image',),
	endpoint_types=('image-generation',),
)


def _config_mock(default_model='', api_key='', api_base=''):
	cfg = MagicMock()
	cfg.addons.ai.default_model = default_model
	cfg.addons.ai.intent_model = ''
	cfg.addons.ai.api_key = api_key
	cfg.addons.ai.api_base = api_base
	cfg.addons.ai.provider = ''
	cfg.validate.return_value = True
	return cfg


class _SetupTestBase(unittest.TestCase):
	def setUp(self):
		providers.reset_caches()
		self.output = io.StringIO()
		env = patch.dict(os.environ, CLEAN_ENV, clear=False)
		env.start()
		self.addCleanup(env.stop)

	# console is a rich Console(stderr=True, record=True); capture() is the
	# supported way to read what the wizard printed.
	def _run_setup(self, answers, catalog_result, cfg):
		import secator.ai.utils as utils
		from secator.rich import console

		with ExitStack() as stack:
			stack.enter_context(patch.object(utils, 'CONFIG', cfg))
			stack.enter_context(patch('rich.prompt.Prompt.ask', side_effect=answers))
			stack.enter_context(patch.object(providers, 'get_catalog', return_value=catalog_result))
			stack.enter_context(patch.object(utils, 'call_llm', return_value={'content': 'OK'}))
			capture = stack.enter_context(console.capture())
			result = utils.setup_ai()
		return result, capture.get()


class TestOrcaRouterSetup(_SetupTestBase):
	def test_setup_lists_the_live_catalog_and_persists_provider(self):
		cfg = _config_mock()
		live = providers.CatalogResult(models=CHAT_FIXTURES, source='live', degraded=False)
		selected, out = self._run_setup(['orcarouter', FAKE_KEY, '1'], live, cfg)

		# The selector only ever offers catalog ids (sorted), never free text.
		self.assertEqual(selected, 'acme/text-only')
		self.assertIn('openai/gpt-5.5', out)
		self.assertIn('acme/text-only', out)
		self.assertNotIn('acme/image-gen', out)

		set_calls = dict(call.args for call in cfg.set.call_args_list)
		self.assertEqual(set_calls['addons.ai.provider'], 'orcarouter')
		self.assertEqual(set_calls['addons.ai.default_model'], 'acme/text-only')
		self.assertEqual(set_calls['addons.ai.intent_model'], 'acme/text-only')
		self.assertEqual(set_calls['addons.ai.api_key'], FAKE_KEY)
		cfg.save.assert_called()

	def test_setup_verifies_through_the_orcarouter_provider_path(self):
		cfg = _config_mock()
		live = providers.CatalogResult(models=CHAT_FIXTURES, source='live', degraded=False)
		import secator.ai.utils as utils
		from secator.rich import console

		with ExitStack() as stack:
			stack.enter_context(patch.object(utils, 'CONFIG', cfg))
			stack.enter_context(patch('rich.prompt.Prompt.ask', side_effect=['orcarouter', FAKE_KEY, '1']))
			stack.enter_context(patch.object(providers, 'get_catalog', return_value=live))
			call_llm = stack.enter_context(patch.object(utils, 'call_llm', return_value={'content': 'OK'}))
			stack.enter_context(console.capture())
			utils.setup_ai()

		kwargs = call_llm.call_args.kwargs
		self.assertEqual(kwargs['provider'], 'orcarouter')
		self.assertEqual(kwargs['api_base'], API_BASE)
		self.assertEqual(kwargs['api_key'], FAKE_KEY)

	def test_degraded_fallback_is_explicit_and_still_selectable(self):
		cfg = _config_mock()
		fallback = providers.CatalogResult(
			models=providers.VERIFIED_FALLBACK_MODELS, source='fallback',
			degraded=True, error='Could not reach the OrcaRouter model catalog (network).',
		)
		selected, out = self._run_setup(['orcarouter', FAKE_KEY, '1'], fallback, cfg)

		self.assertEqual(selected, 'deepseek/deepseek-v4-pro')
		self.assertIn('Live model catalog unavailable', out)
		self.assertIn('verified fallback', out)
		self.assertIn('degraded', out)
		# Only verified seed ids are offered; no free-form model string.
		self.assertIn('deepseek/deepseek-v4-pro', out)
		self.assertNotIn('acme/text-only', out)

	def test_saved_model_missing_from_catalog_is_reported_not_silently_kept(self):
		cfg = _config_mock(default_model='openai/removed-model')
		live = providers.CatalogResult(models=CHAT_FIXTURES, source='live', degraded=False)
		selected, out = self._run_setup(['orcarouter', FAKE_KEY, '1'], live, cfg)

		self.assertIn('not in the current', out)
		self.assertNotEqual(selected, 'openai/removed-model')

	def test_quitting_the_selector_saves_nothing(self):
		cfg = _config_mock()
		live = providers.CatalogResult(models=CHAT_FIXTURES, source='live', degraded=False)
		selected, _ = self._run_setup(['orcarouter', FAKE_KEY, 'q'], live, cfg)

		self.assertIsNone(selected)
		# Only the key prompt may have updated config; the provider/model were not
		# switched until a catalog model is chosen.
		self.assertNotIn('addons.ai.provider', [c.args[0] for c in cfg.set.call_args_list])
		self.assertNotIn('addons.ai.default_model', [c.args[0] for c in cfg.set.call_args_list])

	def test_secret_is_masked_and_never_printed(self):
		cfg = _config_mock(api_key=FAKE_KEY)
		live = providers.CatalogResult(models=CHAT_FIXTURES, source='live', degraded=False)
		_, out = self._run_setup(['orcarouter', '', '1'], live, cfg)

		self.assertNotIn(FAKE_KEY, out)
		self.assertIn('sk-orca-', out)  # masked form only

	def test_switching_back_to_litellm_clears_the_preset(self):
		cfg = _config_mock()
		cfg.addons.ai.provider = 'orcarouter'
		import secator.ai.utils as utils
		from secator.rich import console

		with ExitStack() as stack:
			stack.enter_context(patch.object(utils, 'CONFIG', cfg))
			litellm_flow = stack.enter_context(
				patch.object(utils, '_setup_litellm_models', return_value=None)
			)
			stack.enter_context(patch('rich.prompt.Prompt.ask', return_value='litellm'))
			stack.enter_context(console.capture())
			utils.setup_ai()

		litellm_flow.assert_called_once()
		self.assertIn(
			('addons.ai.provider', ''), [c.args for c in cfg.set.call_args_list]
		)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestProviderRequestRouting(unittest.TestCase):
	def setUp(self):
		env = patch.dict(os.environ, CLEAN_ENV, clear=False)
		env.start()
		self.addCleanup(env.stop)

	def test_orcarouter_uses_the_inference_origin_and_openai_adapter(self):
		import secator.ai.utils as utils

		completion = MagicMock()
		completion.return_value.choices = [MagicMock()]
		completion.return_value.choices[0].message.content = 'OK'
		completion.return_value.choices[0].message.tool_calls = None
		completion.return_value.usage = None

		with ExitStack() as stack:
			stack.enter_context(patch('litellm.completion', completion))
			init_llm = stack.enter_context(patch.object(utils, 'init_llm'))
			stack.enter_context(patch('litellm.token_counter', return_value=1))
			result = utils.call_llm(
				[{'role': 'user', 'content': 'hi'}], 'openai/gpt-5.5',
				api_key=FAKE_KEY, provider='orcarouter',
			)

		self.assertEqual(result['content'], 'OK')
		kwargs = completion.call_args.kwargs
		self.assertEqual(kwargs['model'], 'openai/openai/gpt-5.5')
		self.assertEqual(kwargs['api_base'], API_BASE)
		init_llm.assert_called_once_with(api_key=FAKE_KEY)

	def test_key_falls_back_to_the_orcarouter_environment_variable(self):
		import secator.ai.utils as utils

		completion = MagicMock()
		completion.return_value.choices = [MagicMock()]
		completion.return_value.choices[0].message.content = 'OK'
		completion.return_value.choices[0].message.tool_calls = None
		completion.return_value.usage = None

		with ExitStack() as stack:
			stack.enter_context(patch.dict(os.environ, {'ORCAROUTER_API_KEY': FAKE_KEY}))
			stack.enter_context(patch('litellm.completion', completion))
			init_llm = stack.enter_context(patch.object(utils, 'init_llm'))
			stack.enter_context(patch('litellm.token_counter', return_value=1))
			utils.call_llm([{'role': 'user', 'content': 'hi'}], 'orcarouter/auto',
						   api_key=None, provider='orcarouter')

		init_llm.assert_called_once_with(api_key=FAKE_KEY)

	def test_litellm_native_calls_are_unchanged(self):
		import secator.ai.utils as utils

		completion = MagicMock()
		completion.return_value.choices = [MagicMock()]
		completion.return_value.choices[0].message.content = 'OK'
		completion.return_value.choices[0].message.tool_calls = None
		completion.return_value.usage = None

		with ExitStack() as stack:
			stack.enter_context(patch('litellm.completion', completion))
			init_llm = stack.enter_context(patch.object(utils, 'init_llm'))
			stack.enter_context(patch('litellm.token_counter', return_value=1))
			utils.call_llm([{'role': 'user', 'content': 'hi'}], 'claude-sonnet-4-6',
						   api_key='sk-ant-fake')

		kwargs = completion.call_args.kwargs
		self.assertEqual(kwargs['model'], 'claude-sonnet-4-6')
		self.assertIsNone(kwargs['api_base'])
		init_llm.assert_called_once_with(api_key='sk-ant-fake')


class TestCredentialResolution(unittest.TestCase):
	def setUp(self):
		env = patch.dict(os.environ, CLEAN_ENV, clear=False)
		env.start()
		self.addCleanup(env.stop)

	def test_provider_supplies_base_and_env_key(self):
		from secator.tasks.ai import resolve_llm_credentials

		with patch.dict(os.environ, {'ORCAROUTER_API_KEY': FAKE_KEY}, clear=False):
			base, key, error = resolve_llm_credentials('', '', '', '', provider='orcarouter')
		self.assertEqual(base, API_BASE)
		self.assertEqual(key, FAKE_KEY)
		self.assertIsNone(error)

	def test_caller_overrides_still_win(self):
		from secator.tasks.ai import resolve_llm_credentials

		base, key, error = resolve_llm_credentials(
			'http://127.0.0.1:9/v1', 'sk-orca-caller', 'https://cfg/v1', 'sk-orca-cfg',
			provider='orcarouter',
		)
		self.assertEqual(base, 'http://127.0.0.1:9/v1')
		self.assertEqual(key, 'sk-orca-caller')
		self.assertIsNone(error)

	def test_unknown_provider_returns_an_error_instead_of_raising(self):
		from secator.tasks.ai import resolve_llm_credentials

		base, key, error = resolve_llm_credentials('', '', '', '', provider='bogus')
		self.assertIsNone(key)
		self.assertIn('bogus', error)

	def test_custom_base_guard_still_applies(self):
		from secator.tasks.ai import resolve_llm_credentials

		_, key, error = resolve_llm_credentials(
			'https://custom.example/v1', '', 'https://cfg/v1', 'sk-orca-cfg',
			disallow_config_token=True, provider='orcarouter',
		)
		self.assertIsNone(key)
		self.assertIn('custom api_base', error)


class TestConfigValidation(unittest.TestCase):
	def test_unknown_provider_is_rejected_by_config(self):
		from pydantic import ValidationError
		from secator.config import AiAddon

		with self.assertRaises(ValidationError):
			AiAddon(provider='bogus')

	def test_remote_http_base_is_rejected_for_a_named_provider(self):
		from pydantic import ValidationError
		from secator.config import AiAddon

		with self.assertRaises(ValidationError):
			AiAddon(provider='orcarouter', api_base='http://api.example.com/v1')

	def test_https_base_is_accepted_for_a_named_provider(self):
		from secator.config import AiAddon

		addon = AiAddon(provider='orcarouter', api_base=API_BASE)
		self.assertEqual(addon.provider, 'orcarouter')
		self.assertEqual(addon.api_base, API_BASE)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestProviderContextWindow(unittest.TestCase):
	def test_catalog_context_window_wins_over_litellm(self):
		from secator.ai.history import get_context_window
		providers.reset_caches()
		with patch('litellm.get_model_info', side_effect=AssertionError('litellm must not be consulted')):
			self.assertEqual(get_context_window('deepseek/deepseek-v4-pro'), 1_048_576)


if __name__ == '__main__':
	unittest.main()

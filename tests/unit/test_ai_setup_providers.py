"""Tests for the custom-provider / OpenAI-compatible `ai setup` helpers."""

import json
from unittest.mock import patch, MagicMock

import pytest

from secator.config import CONFIG
from secator.ai import utils as u


class TestNormalizeApiBase:

	def test_https_ok_strips_trailing_slash(self):
		assert u._normalize_api_base('https://api.x.ai/v1/') == ('https://api.x.ai/v1', None)

	def test_empty_rejected(self):
		base, err = u._normalize_api_base('   ')
		assert base == '' and err

	def test_non_https_rejected(self):
		base, err = u._normalize_api_base('http://api.x.ai/v1')
		assert base == '' and 'https' in err

	def test_localhost_http_allowed(self):
		assert u._normalize_api_base('http://localhost:8080/v1')[1] is None
		assert u._normalize_api_base('http://127.0.0.1/v1')[1] is None

	def test_http_localhost_with_userinfo_rejected(self):
		# `http://localhost@evil` resolves to host `evil`; userinfo must not sneak past
		# the localhost exception (would leak the Bearer key over cleartext to a remote).
		assert u._normalize_api_base('http://localhost@evil.example/v1')[0] == ''
		assert u._normalize_api_base('http://user:pass@localhost/v1')[0] == ''


class TestFetchModels:

	def _resp(self, payload, raise_exc=None):
		r = MagicMock()
		if raise_exc:
			r.raise_for_status.side_effect = raise_exc
		else:
			r.raise_for_status.return_value = None
		r.json.return_value = payload
		return r

	def test_parses_sorts_ids_and_skips_malformed(self):
		payload = {'data': [{'id': 'z-model'}, {'id': 'a-model'}, {'no_id': 1}, 'junk']}
		with patch('secator.requests.requests.get', return_value=self._resp(payload)):
			assert u.fetch_openai_compatible_models('https://g/v1', 'k') == ['a-model', 'z-model']

	def test_v1_fallback_when_base_lacks_v1(self):
		# base without /v1: {base}/models fails, {base}/v1/models succeeds.
		ok = self._resp({'data': [{'id': 'm'}]})
		bad = self._resp({}, raise_exc=Exception('404'))
		with patch('secator.requests.requests.get', side_effect=[bad, ok]) as g:
			assert u.fetch_openai_compatible_models('https://g', 'k') == ['m']
			assert [c.args[0] for c in g.call_args_list] == ['https://g/models', 'https://g/v1/models']

	def test_raises_when_all_candidates_fail(self):
		with patch('secator.requests.requests.get', side_effect=Exception('boom')):
			with pytest.raises(Exception):
				u.fetch_openai_compatible_models('https://g/v1', 'k')

	def test_verify_true_by_default(self, monkeypatch):
		monkeypatch.delenv('SSL_VERIFY', raising=False)
		with patch('secator.requests.requests.get', return_value=self._resp({'data': [{'id': 'm'}]})) as g:
			u.fetch_openai_compatible_models('https://g/v1', 'k')
		assert g.call_args.kwargs.get('verify') is True

	def test_honors_ssl_verify_false_env(self, monkeypatch):
		# A self-signed gateway that runs the AI task with SSL_VERIFY=False must also list models.
		monkeypatch.setenv('SSL_VERIFY', 'false')
		with patch('secator.requests.requests.get', return_value=self._resp({'data': [{'id': 'm'}]})) as g:
			u.fetch_openai_compatible_models('https://g/v1', 'k')
		assert g.call_args.kwargs.get('verify') is False


class TestSslVerify:

	def test_default_verifies(self, monkeypatch):
		monkeypatch.delenv('SSL_VERIFY', raising=False)
		assert u._ssl_verify() is True

	@pytest.mark.parametrize('val', ['false', 'False', 'FALSE', '0', 'no', 'off'])
	def test_falsey_disables(self, monkeypatch, val):
		monkeypatch.setenv('SSL_VERIFY', val)
		assert u._ssl_verify() is False

	@pytest.mark.parametrize('val', ['true', '1', 'yes'])
	def test_truthy_verifies(self, monkeypatch, val):
		monkeypatch.setenv('SSL_VERIFY', val)
		assert u._ssl_verify() is True


class TestLoadProviders:

	def test_bundled_registry_is_data_only(self):
		# Adding a provider is a JSON entry, not code — the bundled file ships examples.
		names = [p['name'] for p in u.load_ai_providers()]
		assert 'orcarouter' in names
		assert all(p.get('api_base') for p in u.load_ai_providers())

	def test_user_file_overrides_and_adds(self, tmp_path, monkeypatch):
		monkeypatch.setattr(CONFIG.dirs, 'data', str(tmp_path))
		(tmp_path / 'ai_providers.json').write_text(json.dumps({
			'providers': [
				{'name': 'orcarouter', 'label': 'mine', 'api_base': 'https://my.orca/v1'},
				{'name': 'acme', 'label': 'Acme', 'api_base': 'https://acme/v1'},
			]
		}))
		by_name = {p['name']: p for p in u.load_ai_providers()}
		assert by_name['orcarouter']['api_base'] == 'https://my.orca/v1'  # user overrides bundled
		assert 'acme' in by_name  # user-added

	def test_malformed_user_file_is_skipped_not_fatal(self, tmp_path, monkeypatch):
		monkeypatch.setattr(CONFIG.dirs, 'data', str(tmp_path))
		(tmp_path / 'ai_providers.json').write_text('{ not json')
		assert any(p['name'] == 'orcarouter' for p in u.load_ai_providers())

	def test_insecure_registry_base_is_rejected(self, tmp_path, monkeypatch):
		# A registry entry must pass the same https-or-localhost rule as a typed base.
		monkeypatch.setattr(CONFIG.dirs, 'data', str(tmp_path))
		(tmp_path / 'ai_providers.json').write_text(json.dumps({
			'providers': [
				{'name': 'insecure', 'label': 'X', 'api_base': 'http://remote.example/v1'},
				{'name': 'ok', 'label': 'OK', 'api_base': 'https://ok.example/v1/'},
			]
		}))
		by_name = {p['name']: p for p in u.load_ai_providers()}
		assert 'insecure' not in by_name  # cleartext remote rejected
		assert by_name['ok']['api_base'] == 'https://ok.example/v1'  # kept + normalized


def _asker(answers):
	"""Prompt.ask stub: answers is a list of (label prefix, reply), consumed in order.

	Like rich, an empty reply returns the prompt's default."""
	pending = list(answers)

	def ask(prompt, *args, **kwargs):
		label = prompt.replace('[bold cyan]', '').strip()
		for i, (prefix, reply) in enumerate(pending):
			if label.startswith(prefix):
				del pending[i]
				return reply or kwargs.get('default') or ''
		raise AssertionError(f'unexpected prompt: {label}')
	return ask


GW = 'https://gw.example/v1'
OAUTH = {
	'api_base': GW, 'default_model': 'openai/a', 'intent_model': 'openai/b', 'oauth2_client_id': 'cid',
	'oauth2_client_secret': 'cs-saved-secret-0123456789', 'oauth2_endpoint': 'https://gw.example/oauth2/token',
}


def _token_endpoint(status=200, token='tok-1'):
	"""Mocked OAuth2 token endpoint (patches the `requests.post` the token fetch uses)."""
	resp = MagicMock(status_code=status)
	resp.json.return_value = {'access_token': token, 'expires_in': 3600}
	return patch('requests.post', return_value=resp)


def _run_wizard(monkeypatch, tmp_path, answers, config=None, **patches):
	"""Run `ai setup` with scripted answers; Config is patched on the CLASS so nothing is written.

	Returns (result, {config key: value set}, save mock, call_llm mock, printed text)."""
	from rich.console import Console
	monkeypatch.setattr(CONFIG.dirs, 'data', str(tmp_path))  # bundled registry only
	# Pin the saved AI config so the run does not depend on the local config file.
	saved_config = {
		'default_model': '', 'intent_model': '', 'api_key': '', 'api_base': '', 'oauth2_endpoint': '',
		'oauth2_client_id': '', 'oauth2_client_secret': '', 'oauth2_scope': '', **(config or {}),
	}
	for name, value in saved_config.items():
		monkeypatch.setitem(CONFIG.addons.ai, name, value)
	rec = Console(record=True, width=200)
	cfg = 'secator.config.Config'
	with patch.object(u, 'console', rec), \
		patch('rich.prompt.Prompt.ask', side_effect=_asker(answers)), \
		patch.object(u, 'call_llm', patches.pop('call_llm', MagicMock(return_value={'content': 'OK'}))) as llm, \
		patch(f'{cfg}.set') as cfg_set, patch(f'{cfg}.validate', return_value=True), \
		patch(f'{cfg}.save') as cfg_save:
		for name, value in patches.items():
			monkeypatch.setattr(u, name, value)
		result = u.setup_ai()
	saved = {c.args[0]: c.args[1] for c in cfg_set.call_args_list}
	return result, saved, cfg_save, llm, rec.export_text()


class TestProviderPicker:

	def test_gateway_named_like_litellm_provider_listed_once(self, tmp_path, monkeypatch):
		# openrouter is both a LiteLLM provider and a registry gateway: list it once, as the gateway.
		import litellm
		assert 'openrouter' in litellm.models_by_provider  # else this test proves nothing
		result, saved, save, _, text = _run_wizard(monkeypatch, tmp_path, [('Provider', 'q')])
		assert result is None and not saved
		save.assert_not_called()
		openrouter = [line for line in text.splitlines() if 'OpenRouter' in line or 'Openrouter' in line]
		assert len(openrouter) == 1
		assert 'gateway' in openrouter[0]

	@pytest.mark.parametrize('pick,expected,base', [
		# native route: priced by LiteLLM
		('OpenRouter', 'openrouter/anthropic/claude-x', 'https://openrouter.ai/api/v1'),
		# generic OpenAI-compatible base
		('OrcaRouter', 'openai/anthropic/claude-x', 'https://api.orcarouter.ai/v1'),
	])
	def test_gateway_model_prefix(self, tmp_path, monkeypatch, pick, expected, base):
		answers = [('Provider', pick), ('Choice', ''), ('API key', 'sk-test'), ('Model', '1'), ('Intent model', '')]
		result, saved, save, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers,
			fetch_openai_compatible_models=MagicMock(return_value=['anthropic/claude-x']))
		assert result == expected
		save.assert_called_once()
		assert saved['addons.ai.default_model'] == saved['addons.ai.intent_model'] == expected
		assert saved['addons.ai.api_base'] == base  # the gateway base is saved
		assert llm.call_args.args[1] == expected


class TestSetupWizard:

	def test_unpriced_live_models_are_listed_and_selectable(self, tmp_path, monkeypatch):
		# A live model LiteLLM has no price for is still shown (with dashes) and can be picked.
		live = MagicMock(return_value=['anthropic/claude-opus-5-5', 'anthropic/claude-zz-unpriced-9'])
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-test'), ('Model', 'unpriced'), ('Intent model', '')]
		result, saved, _, _, text = _run_wizard(monkeypatch, tmp_path, answers, _list_provider_models=live)
		assert result == 'anthropic/claude-zz-unpriced-9'
		assert saved['addons.ai.api_key'] == 'sk-ant-test'
		assert '2 models' in text
		live.assert_called_once_with('anthropic', 'sk-ant-test')

	def test_model_table_shows_dash_for_unknown_price(self):
		from rich.console import Console
		rec = Console(record=True, width=150)
		with patch.object(u, 'console', rec):
			u._print_models(['anthropic/claude-zz-unpriced-9'])
		row = next(line for line in rec.export_text().splitlines() if 'claude-zz-unpriced-9' in line)
		assert row.count('—') == 5

	def test_live_listing_falls_back_to_bundled_list(self, tmp_path, monkeypatch):
		# Provider without live listing (None): the bundled LiteLLM catalog is offered.
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-test'), ('Model', '1'), ('Intent model', '')]
		result, _, _, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=None))
		assert result in u._provider_catalog('anthropic')
		assert "bundled list" in text

	def test_bad_key_gives_clear_message_and_saves_nothing(self, tmp_path, monkeypatch):
		err = RuntimeError('Failed to get models: HTTP 401 {"error": "invalid x-api-key sk-ant-bad-key-0123456789"}')
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-bad-key-0123456789'), ('Try again?', 'y'),
		           ('API key', 'q')]
		result, saved, save, llm, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(side_effect=err))
		assert result is None and not saved
		save.assert_not_called()
		llm.assert_not_called()
		assert 'Key rejected by Anthropic (401)' in text
		assert 'sk-ant-bad-key-0123456789' not in text
		assert 'Traceback' not in text

	def test_failed_verify_saves_nothing(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-test'), ('Model', '1'), ('Intent model', ''),
		           ('Pick something else?', 'n'), ('Save anyway?', '')]
		result, saved, save, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']),
			call_llm=MagicMock(side_effect=RuntimeError('AuthenticationError: bad key')))
		assert result is None and not saved
		save.assert_not_called()
		assert 'saved setup is unchanged' in text

	def test_failed_verify_can_save_anyway(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '1'), ('Intent model', ''),
		           ('Pick something else?', 'n'), ('Save anyway?', 'y')]
		result, saved, save, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']),
			call_llm=MagicMock(side_effect=RuntimeError('down')))
		assert result == 'anthropic/m' and saved['addons.ai.api_key'] == 'k'
		save.assert_called_once()

	def test_back_returns_to_previous_step(self, tmp_path, monkeypatch):
		# b at the model step goes back to the credentials step, b again to the provider step.
		answers = [('Provider', 'Anthropic'), ('API key', 'k1'), ('Model', 'b'), ('API key', 'b'),
		           ('Provider', 'OrcaRouter'), ('Choice', ''), ('API key', 'k2'), ('Model', '1'), ('Intent model', '')]
		result, saved, _, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers,
			_list_provider_models=MagicMock(return_value=['anthropic/m']),
			fetch_openai_compatible_models=MagicMock(return_value=['g-model']))
		assert result == 'openai/g-model'
		assert saved['addons.ai.api_key'] == 'k2'

	@pytest.mark.parametrize('answers', [
		[('Provider', 'q')],
		[('Provider', 'Anthropic'), ('API key', 'q')],
		[('Provider', 'Anthropic'), ('API key', 'k'), ('Model', 'quit')],
		[('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '1'), ('Intent model', 'q')],
		[('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '1'), ('Intent model', ''), ('Pick something else?', 'q')],
	])
	def test_quit_at_every_step_saves_nothing(self, tmp_path, monkeypatch, answers):
		result, saved, save, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']),
			call_llm=MagicMock(side_effect=RuntimeError('down')))
		assert result is None and not saved
		save.assert_not_called()
		assert 'nothing saved' in text

	def test_separate_intent_model(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', 'big'), ('Intent model', 'small')]
		_, saved, _, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers,
			_list_provider_models=MagicMock(return_value=['anthropic/big-1', 'anthropic/small-1']))
		assert saved['addons.ai.default_model'] == 'anthropic/big-1'
		assert saved['addons.ai.intent_model'] == 'anthropic/small-1'
		assert [c.args[1] for c in llm.call_args_list] == ['anthropic/big-1', 'anthropic/small-1']

	def test_saved_key_never_offered_to_another_provider(self, tmp_path, monkeypatch):
		# The saved key belongs to another endpoint: switching provider must not resend it.
		old = {'api_key': 'sk-old-gateway-key-123456', 'api_base': 'https://old.example/v1', 'default_model': 'openai/x'}
		answers = [('Choice', '2'), ('Provider', 'Anthropic'), ('API key', ''), ('Model', '1'), ('Intent model', '')]
		_, saved, _, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers, config=old,
			_list_provider_models=MagicMock(return_value=['anthropic/m']))
		assert llm.call_args.kwargs['api_key'] == ''
		assert saved['addons.ai.api_key'] == '' and saved['addons.ai.api_base'] == ''

	def test_saved_key_not_reused_across_openai_gateways(self, tmp_path, monkeypatch):
		# Two gateways share the `openai/` route but not the base: the saved key stays with its base.
		(tmp_path / 'ai_providers.json').write_text(json.dumps(
			{'providers': [{'name': 'acme', 'label': 'Acme', 'api_base': 'https://acme.example/v1'}]}))
		fetch = MagicMock(return_value=['m'])
		answers = [('Choice', '2'), ('Provider', 'Acme'), ('Choice', ''), ('API key', ''), ('API key', 'k2'),
		           ('Model', '1'), ('Intent model', '')]
		_, saved, _, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, fetch_openai_compatible_models=fetch,
			config={'api_key': 'sk-orca-saved-1234567890', 'api_base': 'https://api.orcarouter.ai/v1',
			        'default_model': 'openai/m'})
		assert 'needs an API key' in text
		fetch.assert_called_once_with('https://acme.example/v1', 'k2')
		assert saved['addons.ai.api_key'] == 'k2'

	def test_unlisted_model_id_can_be_typed(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', 'claude-brand-new-9'),
		           ('No model matches', 'y'), ('Intent model', '')]
		result, _, _, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']))
		assert result == 'anthropic/claude-brand-new-9'

	def test_no_list_at_all_asks_for_an_id(self, tmp_path, monkeypatch):
		# A plain gateway whose listing fails has no bundled list (not OpenAI's): ask for the id.
		answers = [('Provider', 'OrcaRouter'), ('Choice', ''), ('API key', 'k'), ('Try again?', 'n'),
		           ('Model id', 'my-model'), ('Intent model id', '')]
		result, saved, _, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, fetch_openai_compatible_models=MagicMock(side_effect=OSError('down')))
		assert result == 'openai/my-model'
		assert saved['addons.ai.intent_model'] == 'openai/my-model'
		assert 'bundled list' not in text

	def test_numbers_and_filter_text(self, tmp_path, monkeypatch):
		# An out-of-range number filters ("405"); in the intent step, numbers refer to the model table.
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '405'), ('Intent model', '1')]
		_, saved, _, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers,
			_list_provider_models=MagicMock(return_value=['anthropic/m', 'anthropic/llama-405b']))
		assert saved['addons.ai.default_model'] == 'anthropic/llama-405b'
		assert saved['addons.ai.intent_model'] == 'anthropic/llama-405b'  # row 1, newest-first order

	def test_same_named_model_on_a_gateway_gets_the_gateway_route(self, tmp_path, monkeypatch):
		# The saved `claude-sonnet-4-6` routes to Anthropic: on a gateway it must be saved with its route.
		answers = [('Provider', 'OrcaRouter'), ('Choice', ''), ('API key', 'k'), ('Model', 'claude-sonnet-4-6'),
		           ('Intent model', '')]
		result, saved, _, llm, text = _run_wizard(
			monkeypatch, tmp_path, answers, config={'default_model': 'claude-sonnet-4-6', 'intent_model': 'claude-sonnet-4-6'},
			fetch_openai_compatible_models=MagicMock(return_value=['claude-sonnet-4-6']))
		assert result == saved['addons.ai.default_model'] == 'openai/claude-sonnet-4-6'
		assert saved['addons.ai.intent_model'] == 'openai/claude-sonnet-4-6'
		assert llm.call_args.args[1] == 'openai/claude-sonnet-4-6'
		assert '● current' not in text

	def test_intent_numbers_follow_the_filtered_table(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', 'beta'), ('Model', '2'), ('Intent model', '1')]
		_, saved, _, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers,
			_list_provider_models=MagicMock(return_value=['anthropic/alpha-1', 'anthropic/beta-1', 'anthropic/beta-2']))
		assert saved['addons.ai.default_model'] == 'anthropic/beta-1'
		assert saved['addons.ai.intent_model'] == 'anthropic/beta-2'  # row 1 of the "beta" table

	def test_failed_main_model_goes_back_to_the_model_step(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '1'), ('Intent model', ''),
		           ('Pick something else?', 'y'), ('Model', 'q')]
		result, saved, _, _, _ = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']),
			call_llm=MagicMock(side_effect=RuntimeError('down')))
		assert result is None and not saved

	def test_arrow_menu_keeps_the_default_and_ctrl_c_quits(self, monkeypatch):
		from secator import rich as srich
		monkeypatch.setattr(u, '_tty', lambda: True)
		with patch.object(srich.InteractiveMenu, 'show', autospec=True,
		                  side_effect=lambda self: (self.selected, None)) as show:
			assert u._choose('Pick', ['a', 'b'], default=1) == 1  # opened on the default
		assert show.call_count == 1

		def interrupted(self):
			self.interrupted = True
		with patch.object(srich.InteractiveMenu, 'show', autospec=True, side_effect=interrupted):
			with pytest.raises(u._Quit):
				u._choose('Pick', ['a', 'b'])
		with patch.object(srich.InteractiveMenu, 'show', autospec=True, return_value=None):  # Esc
			with pytest.raises(u._Back):
				u._choose('Pick', ['a', 'b'])

	def test_markup_in_model_ids_does_not_crash(self):
		from rich.console import Console
		rec = Console(record=True, width=150)
		with patch.object(u, 'console', rec):
			u._print_models(['openai/weird[/]id', 'openai/[bold]x'])
		assert 'weird[/]id' in rec.export_text()


class TestOAuth2Setup:

	def test_first_run_with_oauth2(self, tmp_path, monkeypatch):
		fetch = MagicMock(return_value=['m'])
		answers = [('Provider', 'Custom'), ('API base URL', GW), ('Choice', '2'), ('Client ID', 'cid'),
		           ('Client secret', 'cs-new-secret-0123456789'), ('Token URL', ''), ('Model', '1'), ('Intent model', '')]
		with _token_endpoint() as post:
			result, saved, save, llm, text = _run_wizard(
				monkeypatch, tmp_path, answers, fetch_openai_compatible_models=fetch)
		# Default token URL: the origin of the base + /oauth2/token.
		assert post.call_args.args[0] == 'https://gw.example/oauth2/token'
		assert post.call_args.kwargs['auth'] == ('cid', 'cs-new-secret-0123456789')
		fetch.assert_called_once_with(GW, 'tok-1')
		assert llm.call_args.kwargs['api_key'] == 'tok-1'  # verified with the OAuth2 token
		assert result == 'openai/m'
		assert saved['addons.ai.oauth2_client_id'] == 'cid'
		assert saved['addons.ai.oauth2_client_secret'] == 'cs-new-secret-0123456789'
		assert saved['addons.ai.oauth2_endpoint'] == 'https://gw.example/oauth2/token'
		assert 'addons.ai.api_key' not in saved
		assert 'cs-new-secret-0123456789' not in text and 'tok-1' not in text  # masked in the summary

	def test_bad_client_secret_saves_nothing(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Custom'), ('API base URL', GW), ('Choice', '2'), ('Client ID', 'cid'),
		           ('Client secret', 'cs-wrong-secret-0123456789'), ('Token URL', ''), ('Try again?', 'n'),
		           ('Model id', 'q')]
		with _token_endpoint(status=401):
			result, saved, save, llm, text = _run_wizard(
				monkeypatch, tmp_path, answers, fetch_openai_compatible_models=MagicMock())
		assert result is None and not saved
		save.assert_not_called()
		assert 'Client ID / secret rejected by the token URL (401)' in text
		assert 'cs-wrong-secret-0123456789' not in text

	@pytest.mark.parametrize('answer,cleared', [('y', True), ('n', False)])
	def test_switch_to_oauth2_removes_key_only_on_confirmation(self, tmp_path, monkeypatch, answer, cleared):
		config = {'api_base': GW, 'api_key': 'sk-gw-saved-0123456789', 'default_model': 'openai/m'}
		answers = [('Choice', '3'), ('Choice', '2'), ('Client ID', 'cid'), ('Client secret', 'cs-0123456789abcdefgh'),
		           ('Token URL', ''), ('Remove the saved API key?', answer)]
		with _token_endpoint():
			_, saved, save, llm, text = _run_wizard(
				monkeypatch, tmp_path, answers, config=config,
				fetch_openai_compatible_models=MagicMock(return_value=['m']))
		assert llm.call_args.kwargs['api_key'] == 'tok-1'
		if cleared:
			assert saved == {
				'addons.ai.api_key': '', 'addons.ai.oauth2_client_id': 'cid',
				'addons.ai.oauth2_client_secret': 'cs-0123456789abcdefgh',
				'addons.ai.oauth2_endpoint': 'https://gw.example/oauth2/token'}
		else:  # the key keeps winning at runtime, so the OAuth2 settings are not saved
			assert not saved and 'stays in use' in text

	def test_switching_to_an_api_key_clears_oauth2(self, tmp_path, monkeypatch):
		answers = [('Choice', '3'), ('Choice', '1'), ('API key', 'sk-gw-new-0123456789')]
		_, saved, _, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers, config=OAUTH, fetch_openai_compatible_models=MagicMock(return_value=['a']))
		assert saved == {
			'addons.ai.api_key': 'sk-gw-new-0123456789', 'addons.ai.oauth2_client_id': '',
			'addons.ai.oauth2_client_secret': '', 'addons.ai.oauth2_endpoint': ''}
		assert llm.call_args.kwargs['api_key'] == 'sk-gw-new-0123456789'

	def test_failed_oauth2_check_cannot_be_saved_anyway(self, tmp_path, monkeypatch):
		# No "Save anyway?" prompt: the stub would fail on it.
		answers = [('Provider', 'Custom'), ('API base URL', GW), ('Choice', '2'), ('Client ID', 'cid'),
		           ('Client secret', 'cs-new-secret-0123456789'), ('Token URL', ''), ('Model', '1'), ('Intent model', ''),
		           ('Pick something else?', 'n')]
		with _token_endpoint():
			result, saved, save, _, _ = _run_wizard(
				monkeypatch, tmp_path, answers, fetch_openai_compatible_models=MagicMock(return_value=['m']),
				call_llm=MagicMock(side_effect=RuntimeError('model not found')))
		assert result is None and not saved
		save.assert_not_called()

	def test_token_url_is_always_saved_explicitly(self, tmp_path, monkeypatch):
		# An older OAuth2 setup without oauth2_endpoint: the next save writes the default it used.
		config = {**OAUTH, 'oauth2_endpoint': ''}
		answers = [('Choice', ''), ('Model', 'openai/c')]
		with _token_endpoint() as post:
			_, saved, _, _, _ = _run_wizard(
				monkeypatch, tmp_path, answers, config=config,
				fetch_openai_compatible_models=MagicMock(return_value=['a', 'c']))
		assert post.call_args.args[0] == 'https://gw.example/oauth2/token'
		assert saved['addons.ai.oauth2_endpoint'] == 'https://gw.example/oauth2/token'


class TestReRun:

	def test_switch_only_the_model_keeps_everything_else(self, tmp_path, monkeypatch):
		fetch = MagicMock(return_value=['a', 'c'])
		answers = [('Choice', ''), ('Model', 'openai/c')]
		with _token_endpoint():
			result, saved, save, llm, text = _run_wizard(
				monkeypatch, tmp_path, answers, config=OAUTH, fetch_openai_compatible_models=fetch)
		assert result == 'openai/c'
		assert saved == {'addons.ai.default_model': 'openai/c'}  # base, OAuth2 and intent untouched
		fetch.assert_called_once_with(GW, 'tok-1')
		assert [c.args[1] for c in llm.call_args_list] == ['openai/c']  # only what changed is verified
		save.assert_called_once()
		assert 'cs-saved-secret-0123456789' not in text and 'cs-sa' in text  # masked in the panels

	def test_switch_model_with_a_saved_key(self, tmp_path, monkeypatch):
		live = MagicMock(return_value=['anthropic/claude-x', 'anthropic/claude-y'])
		answers = [('Choice', ''), ('Model', 'claude-y')]
		_, saved, _, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=live,
			config={'api_key': 'sk-ant-saved-key-1234567890', 'default_model': 'anthropic/claude-x'})
		live.assert_called_once_with('anthropic', 'sk-ant-saved-key-1234567890')
		assert llm.call_args.kwargs['api_key'] == 'sk-ant-saved-key-1234567890'
		assert saved == {'addons.ai.default_model': 'anthropic/claude-y'}

	@pytest.mark.parametrize('answers', [
		[('Choice', ''), ('Model', '')],
		[('Choice', '2'), ('Provider', ''), ('API base URL', ''), ('Choice', ''), ('Client ID', ''), ('Client secret', ''),
		 ('Token URL', ''), ('Model', ''), ('Intent model', '')],
		[('Choice', '3'), ('Choice', ''), ('Client ID', ''), ('Client secret', ''), ('Token URL', '')],
		[('Choice', '4'), ('Intent model', '')],
		[('Choice', 'Done')],
	])
	def test_enter_everywhere_changes_nothing(self, tmp_path, monkeypatch, answers):
		with _token_endpoint():
			result, saved, save, llm, text = _run_wizard(
				monkeypatch, tmp_path, answers, config=OAUTH,
				fetch_openai_compatible_models=MagicMock(return_value=['a', 'b', 'c']))
		assert result is None and not saved
		save.assert_not_called()
		llm.assert_not_called()
		assert 'Nothing changed' in text

	def test_failed_model_switch_keeps_the_old_model(self, tmp_path, monkeypatch):
		answers = [('Choice', ''), ('Model', 'openai/c'), ('Pick something else?', 'y'), ('Model', 'q')]
		with _token_endpoint():
			result, saved, save, _, text = _run_wizard(
				monkeypatch, tmp_path, answers, config=OAUTH,
				fetch_openai_compatible_models=MagicMock(return_value=['a', 'c']),
				call_llm=MagicMock(side_effect=RuntimeError('model not found')))
		assert result is None and not saved
		save.assert_not_called()
		assert 'saved setup is unchanged' in text


class TestListers:

	@pytest.mark.parametrize('provider', ['vertex_ai', 'groq'])
	def test_providers_without_a_listing_return_none(self, provider):
		# vertex_ai has a lister class whose listing raises NotImplementedError; groq has none.
		assert u._list_provider_models(provider, 'k') is None

	def test_short_error_reads_json_body_and_masks_key(self):
		e = Exception('401 Client Error')
		e.response = MagicMock()
		e.response.json.return_value = {'error': {'message': 'bad key sk-secret-value-123456789 [x]'}}
		msg = u._short_error(e, 'sk-secret-value-123456789')
		assert 'bad key' in msg and 'sk-secret-value-123456789' not in msg
		assert '\\[x]' in msg  # escaped for rich markup


class TestPrettyProvider:

	@pytest.mark.parametrize('pid,expected', [
		('openai', 'Openai'),
		('groq', 'Groq'),
		('vertex_ai', 'Vertex AI'),
		('together_ai', 'Together AI'),
		('fireworks_ai', 'Fireworks AI'),
		('text-completion-openai', 'Text Completion Openai'),
	])
	def test_snake_to_title_with_acronyms(self, pid, expected):
		assert u.pretty_provider(pid) == expected


if __name__ == '__main__':
	pytest.main([__file__, '-q'])

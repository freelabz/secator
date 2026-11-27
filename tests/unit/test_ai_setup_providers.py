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
	"""Prompt.ask stub: answers is a list of (label prefix, reply), consumed in order."""
	pending = list(answers)

	def ask(prompt, *args, **kwargs):
		label = prompt.replace('[bold cyan]', '').strip()
		for i, (prefix, reply) in enumerate(pending):
			if label.startswith(prefix):
				del pending[i]
				return reply
		raise AssertionError(f'unexpected prompt: {label}')
	return ask


def _run_wizard(monkeypatch, tmp_path, answers, **patches):
	"""Run `ai setup` with scripted answers; Config is patched on the CLASS so nothing is written."""
	monkeypatch.setattr(CONFIG.dirs, 'data', str(tmp_path))  # bundled registry only
	printed = MagicMock()
	cfg = 'secator.config.Config'
	with patch.object(u, 'console', printed), \
		patch('rich.prompt.Prompt.ask', side_effect=_asker(answers)), \
		patch.object(u, 'call_llm', patches.pop('call_llm', MagicMock(return_value={'content': 'OK'}))) as llm, \
		patch(f'{cfg}.set') as cfg_set, patch(f'{cfg}.validate', return_value=True), \
		patch(f'{cfg}.save') as cfg_save:
		for name, value in patches.items():
			monkeypatch.setattr(u, name, value)
		result = u.setup_ai()
	text = '\n'.join(str(c.args[0]) for c in printed.print.call_args_list if c.args and isinstance(c.args[0], str))
	saved = {c.args[0]: c.args[1] for c in cfg_set.call_args_list}
	return result, saved, cfg_save, llm, text


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
		assert 'OpenAI-compatible gateway' in openrouter[0]

	@pytest.mark.parametrize('pick,expected,base', [
		# native route: priced by LiteLLM
		('OpenRouter', 'openrouter/anthropic/claude-x', 'https://openrouter.ai/api/v1'),
		# generic OpenAI-compatible base
		('OrcaRouter', 'openai/anthropic/claude-x', 'https://api.orcarouter.ai/v1'),
	])
	def test_gateway_model_prefix(self, tmp_path, monkeypatch, pick, expected, base):
		answers = [('Provider', pick), ('API key', 'sk-test'), ('Model', '1'), ('Intent model', '')]
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
		printed = MagicMock()
		with patch.object(u, 'console', printed):
			u._print_models(['anthropic/claude-zz-unpriced-9'])
		from rich.console import Console
		rec = Console(record=True, width=120)
		rec.print(printed.print.call_args_list[1].args[0])
		row = rec.export_text().splitlines()[-1]
		assert 'claude-zz-unpriced-9' in row and row.count('—') == 5

	def test_live_listing_falls_back_to_bundled_list(self, tmp_path, monkeypatch):
		# Provider without live listing (None): the bundled LiteLLM catalog is offered.
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-test'), ('Model', '1'), ('Intent model', '')]
		result, _, _, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=None))
		assert result in u._provider_catalog('anthropic')
		assert "bundled list" in text

	def test_bad_key_gives_clear_message_and_saves_nothing(self, tmp_path, monkeypatch):
		err = RuntimeError('Failed to get models: {"error": "invalid x-api-key sk-ant-bad"}')
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-bad'), ('Try another key?', 'y'),
		           ('API key', 'q')]
		result, saved, save, llm, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(side_effect=err))
		assert result is None and not saved
		save.assert_not_called()
		llm.assert_not_called()
		assert 'Could not list models from Anthropic' in text and 'invalid x-api-key' in text
		assert 'sk-ant-bad' not in text  # the key itself is masked out of the provider message
		assert 'Traceback' not in text

	def test_failed_verify_saves_nothing(self, tmp_path, monkeypatch):
		answers = [('Provider', 'Anthropic'), ('API key', 'sk-ant-test'), ('Model', '1'), ('Intent model', ''),
		           ('Save anyway?', '')]
		result, saved, save, _, text = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']),
			call_llm=MagicMock(side_effect=RuntimeError('AuthenticationError: bad key')))
		assert result is None and not saved
		save.assert_not_called()
		assert 'Nothing saved' in text

	def test_back_returns_to_previous_step(self, tmp_path, monkeypatch):
		# b at the model step goes back to the key step, b again to the provider step.
		answers = [('Provider', 'Anthropic'), ('API key', 'k1'), ('Model', 'b'), ('API key', 'b'),
		           ('Provider', 'OrcaRouter'), ('API key', 'k2'), ('Model', '1'), ('Intent model', '')]
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
		[('Provider', 'Anthropic'), ('API key', 'k'), ('Model', '1'), ('Intent model', ''), ('Save anyway?', 'q')],
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
		# The saved key belongs to another provider: Enter must clear it, not resend it.
		monkeypatch.setattr(CONFIG.addons.ai, 'api_key', 'sk-old-gateway-key-123456')
		monkeypatch.setattr(CONFIG.addons.ai, 'api_base', 'https://old.example/v1')
		monkeypatch.setattr(CONFIG.addons.ai, 'default_model', 'openai/x')
		answers = [('Provider', 'Anthropic'), ('API key', ''), ('Model', '1'), ('Intent model', '')]
		_, saved, _, llm, _ = _run_wizard(
			monkeypatch, tmp_path, answers, _list_provider_models=MagicMock(return_value=['anthropic/m']))
		assert llm.call_args.kwargs['api_key'] == ''
		assert saved['addons.ai.api_key'] == '' and saved['addons.ai.api_base'] == ''


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

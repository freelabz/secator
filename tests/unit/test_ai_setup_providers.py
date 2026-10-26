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
		assert any(p['name'] == 'openrouter' for p in u.load_ai_providers())


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

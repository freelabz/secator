"""OAuth2 client-credentials token for the configured LLM endpoint (call_llm)."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import litellm
import pytest

from secator.config import CONFIG
from secator.ai import utils as u

BASE = 'https://llm.example.com/v1'
TOKEN_URL = 'https://auth.example.com/oauth2/token'
SECRET = 's3cr3t-client-value'


def _token_resp(token, expires_in=300, status=200):
	r = MagicMock(status_code=status)
	r.json.return_value = {'access_token': token, 'expires_in': expires_in, 'token_type': 'Bearer'}
	return r


def _llm_resp():
	msg = SimpleNamespace(content='ok', tool_calls=None)
	usage = SimpleNamespace(total_tokens=2, prompt_tokens=1, completion_tokens=1)
	return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason='stop')], usage=usage)


def _auth_error():
	return litellm.AuthenticationError(message='401 invalid token', llm_provider='openai', model='openai/m')


@pytest.fixture
def oauth2(monkeypatch):
	monkeypatch.setattr(u, '_oauth2_tokens', u.OAuth2TokenCache())
	clock = [1000.0]
	monkeypatch.setattr('time.monotonic', lambda: clock[0])
	monkeypatch.setattr('time.sleep', lambda s: None)
	cfg = {
		'api_base': BASE, 'api_key': '', 'oauth2_endpoint': TOKEN_URL,
		'oauth2_client_id': 'client-1', 'oauth2_client_secret': SECRET, 'oauth2_scope': '',
	}
	# patch.dict restores every key on exit, including ones a test reassigns.
	with patch.dict(CONFIG.addons.ai, cfg), patch('requests.post') as post, patch('litellm.completion') as completion:
		completion.return_value = _llm_resp()
		yield SimpleNamespace(post=post, completion=completion, clock=clock)


def _call(api_base=BASE, api_key=None):
	return u.call_llm([{'role': 'user', 'content': 'hi'}], 'openai/m', api_base=api_base, api_key=api_key)


def test_first_fetch_sends_client_credentials(oauth2):
	oauth2.post.return_value = _token_resp('tok-1')
	_call()
	args, kwargs = oauth2.post.call_args
	assert args[0] == TOKEN_URL
	assert kwargs['data'] == {'grant_type': 'client_credentials'}
	assert kwargs['auth'] == ('client-1', SECRET)
	assert kwargs['allow_redirects'] is False
	assert oauth2.completion.call_args.kwargs['api_key'] == 'tok-1'


def test_cached_token_reused(oauth2):
	oauth2.post.return_value = _token_resp('tok-1')
	_call()
	oauth2.clock[0] += 200
	_call()
	assert oauth2.post.call_count == 1
	assert oauth2.completion.call_args.kwargs['api_key'] == 'tok-1'


def test_refresh_before_expiry(oauth2):
	oauth2.post.side_effect = [_token_resp('tok-1'), _token_resp('tok-2')]
	_call()
	oauth2.clock[0] += 300 - 29  # inside the refresh margin
	_call()
	assert oauth2.post.call_count == 2
	assert oauth2.completion.call_args.kwargs['api_key'] == 'tok-2'


def test_refetch_and_retry_once_on_401(oauth2):
	oauth2.post.side_effect = [_token_resp('tok-1'), _token_resp('tok-2')]
	oauth2.completion.side_effect = [_auth_error(), _llm_resp()]
	assert _call()['content'] == 'ok'
	assert oauth2.post.call_count == 2
	assert [c.kwargs['api_key'] for c in oauth2.completion.call_args_list] == ['tok-1', 'tok-2']


def test_second_401_raises(oauth2):
	oauth2.post.side_effect = [_token_resp('tok-1'), _token_resp('tok-2')]
	oauth2.completion.side_effect = [_auth_error(), _auth_error()]
	with pytest.raises(litellm.AuthenticationError):
		_call()
	assert oauth2.completion.call_count == 2


def test_config_change_refetches(oauth2):
	oauth2.post.side_effect = [_token_resp('tok-1'), _token_resp('tok-2')]
	_call()
	CONFIG.addons.ai.oauth2_client_secret = 'rotated'
	_call()
	assert oauth2.completion.call_args.kwargs['api_key'] == 'tok-2'


@pytest.mark.parametrize('resp', [
	_token_resp('tok-1', status=400),
	_token_resp(''),  # empty token would let litellm fall back to another key
	_token_resp('tok-1', expires_in='soon'),
])
def test_bad_token_response_raises(oauth2, resp):
	oauth2.post.return_value = resp
	with pytest.raises(RuntimeError, match='OAuth2'):
		_call()
	oauth2.completion.assert_not_called()


def test_scope_sent_when_set(oauth2):
	CONFIG.addons.ai.oauth2_scope = 'llm.invoke'
	oauth2.post.return_value = _token_resp('tok-1')
	_call()
	assert oauth2.post.call_args.kwargs['data']['scope'] == 'llm.invoke'


@pytest.mark.parametrize('api_base,api_key', [
	('https://other.example.com/v1', None),  # caller-supplied base: token never sent there
	(BASE, 'caller-key'),  # explicit key wins
])
def test_token_only_for_configured_base_without_key(oauth2, api_base, api_key):
	_call(api_base=api_base, api_key=api_key)
	oauth2.post.assert_not_called()
	assert 'api_key' not in oauth2.completion.call_args.kwargs


def test_http_token_endpoint_rejected(oauth2):
	CONFIG.addons.ai.oauth2_endpoint = 'http://auth.example.com/token'
	with pytest.raises(ValueError, match='https'):
		_call()
	oauth2.post.assert_not_called()


def test_secret_and_token_never_logged(oauth2, caplog):
	printed = []
	oauth2.post.side_effect = [_token_resp('tok-SECRET-1'), _token_resp('tok-SECRET-2'), _token_resp('x', status=401)]
	oauth2.completion.side_effect = [_auth_error(), _auth_error()]
	with caplog.at_level(logging.DEBUG), patch.object(u.console, 'print', side_effect=lambda *a, **k: printed.append(a)):
		with pytest.raises(litellm.AuthenticationError):
			_call()
		with pytest.raises(RuntimeError) as exc:
			u._oauth2_tokens.get(force=True)
	output = caplog.text + repr(printed) + str(exc.value)
	for value in (SECRET, 'tok-SECRET-1', 'tok-SECRET-2'):
		assert value not in output

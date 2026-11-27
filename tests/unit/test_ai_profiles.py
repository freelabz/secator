"""AI model profiles: config fallback, run selection, per-mode profiles, /model switching, usage per model."""
import contextlib
import types
from unittest.mock import MagicMock, patch

import pytest

from secator.config import CONFIG
from secator.definitions import ADDONS_ENABLED

pytestmark = pytest.mark.skipif(not ADDONS_ENABLED.get('ai', False), reason='ai addon required')

TOP = {
	'profile': '', 'default_model': 'top-model', 'intent_model': 'top-intent', 'api_base': '',
	'api_key': 'sk-top-key-0123456789abcdef', 'oauth2_endpoint': '', 'oauth2_client_id': '',
	'oauth2_client_secret': '', 'oauth2_scope': '', 'custom_disallow_config_token': False, 'mode_profiles': {},
}
GW = 'https://gw.example/v1'
PROFILES = {
	'fast': {'model': 'fast-model'},
	'big': {'model': 'big-model', 'intent_model': 'big-intent'},
	'gw': {'model': 'openai/gw-model', 'api_base': GW, 'api_key': 'sk-gw-key-0123456789abcdef'},
	'nokey': {'model': 'openai/x', 'api_base': GW},
}


@pytest.fixture
def cfg(monkeypatch):
	"""Pinned addons.ai settings (patched in memory: nothing is read from or written to a config file)."""
	for name, value in {**TOP, 'profiles': PROFILES}.items():
		monkeypatch.setitem(CONFIG.addons.ai, name, value)
	return CONFIG.addons.ai


def _task(**opts):
	"""An `ai` task after _init_options, with the given run options (heavy collaborators stubbed)."""
	from secator.tasks.ai import ai
	task = ai.__new__(ai)
	task.context, task.run_opts, task.inputs = {}, {}, []
	task._view = lambda *a, **kw: []
	task._reports_folder = None
	task.sync = True
	values = {'mode': 'chat', 'max_tokens_total': 100000, 'max_workers': 1, 'max_iterations': 10,
	          'temperature': 0.7, 'interactive': 'auto', **opts}
	task.get_opt_value = values.get
	with contextlib.ExitStack() as stack:
		stack.enter_context(patch('secator.tasks.ai.PermissionEngine'))
		stack.enter_context(patch('secator.tasks.ai.create_backend'))
		stack.enter_context(patch.object(type(task), 'reports_folder', property(lambda self: None)))
		stack.enter_context(patch.object(type(task), 'id', 'task-id', create=True))
		task._init_options()
	return task


# ---- config resolution ----

def test_old_config_without_profiles_behaves_as_before(cfg, monkeypatch):
	from secator.ai.utils import resolve_ai_profile
	monkeypatch.setitem(CONFIG.addons.ai, 'profiles', {})
	assert resolve_ai_profile() == {
		'name': 'default', 'model': 'top-model', 'intent_model': 'top-intent', 'api_base': '',
		'api_key': TOP['api_key'], 'oauth2_endpoint': '', 'oauth2_client_id': '', 'oauth2_client_secret': '',
		'oauth2_scope': ''}
	task = _task()
	assert (task.model, task.intent_model, task.api_base, task.api_key) == ('top-model', 'top-intent', '', TOP['api_key'])
	assert task.ai_profile == 'default' and task._credential_error is None
	assert task.context['ai_model'] == 'top-model'
	# The custom-base rule is unchanged.
	monkeypatch.setitem(CONFIG.addons.ai, 'custom_disallow_config_token', True)
	assert _task(api_base='https://other.example/v1')._credential_error == (
		'A custom api_base requires you to provide your own api_key.')


def test_profile_falls_back_to_top_level_fields(cfg):
	from secator.ai.utils import resolve_ai_profile
	fast = resolve_ai_profile('fast')
	assert fast['model'] == 'fast-model'
	assert fast['intent_model'] == 'top-intent'
	assert fast['api_key'] == TOP['api_key']


def test_profile_on_another_base_inherits_no_credentials(cfg, monkeypatch):
	from secator.ai.utils import resolve_ai_profile
	monkeypatch.setitem(CONFIG.addons.ai, 'oauth2_client_secret', 'top-secret-0123456789')
	gw = resolve_ai_profile('gw')
	assert (gw['api_base'], gw['api_key'], gw['intent_model']) == (GW, PROFILES['gw']['api_key'], 'openai/gw-model')
	nokey = resolve_ai_profile('nokey')
	assert nokey['api_key'] == '' and nokey['oauth2_client_secret'] == ''


def test_unknown_profile(cfg):
	from secator.ai.utils import resolve_ai_profile
	with pytest.raises(ValueError, match='Unknown AI profile "nope"'):
		resolve_ai_profile('nope')
	assert 'Unknown AI profile "nope"' in _task(profile='nope')._credential_error


def test_active_profile_is_the_default(cfg, monkeypatch):
	monkeypatch.setitem(CONFIG.addons.ai, 'profile', 'fast')
	task = _task()
	assert (task.ai_profile, task.model, task.api_key) == ('fast', 'fast-model', TOP['api_key'])


def test_profile_secrets_are_masked(cfg):
	from secator.config import mask_secrets
	masked = mask_secrets({'profiles': PROFILES}, ('addons', 'ai'))
	assert masked['profiles']['gw']['api_key'] != PROFILES['gw']['api_key']
	assert masked['profiles']['gw']['api_base'] == GW


# ---- run selection ----

def test_profile_flag_and_explicit_model(cfg):
	task = _task(profile='gw')
	assert (task.model, task.api_base, task.api_key) == ('openai/gw-model', GW, PROFILES['gw']['api_key'])
	# An explicit --model / --api_base / --api_key wins over the profile's.
	task = _task(profile='gw', model='openai/explicit')
	assert (task.model, task.api_base, task.api_key) == ('openai/explicit', GW, PROFILES['gw']['api_key'])
	task = _task(profile='gw', api_base='https://other.example/v1', api_key='sk-caller')
	assert (task.api_base, task.api_key) == ('https://other.example/v1', 'sk-caller')


def test_mode_profile_applies_at_run_start(cfg, monkeypatch):
	monkeypatch.setitem(CONFIG.addons.ai, 'mode_profiles', {'exploit': 'big'})
	task = _task(mode='exploit')
	assert task.model == 'top-model'  # the mode profile waits for the run's resolved mode
	items = list(task._apply_mode_profile())
	assert (task.ai_profile, task.model, task.intent_model) == ('big', 'big-model', 'big-intent')
	assert task.context['ai_model'] == 'big-model'
	assert 'using AI profile "big"' in items[0].message
	# Explicit --profile or --model: the mode profile is skipped.
	for opts in ({'profile': 'fast'}, {'model': 'explicit'}):
		task = _task(mode='exploit', **opts)
		assert list(task._apply_mode_profile()) == []
		assert task.ai_profile != 'big'


def test_unknown_mode_profile_warns_and_keeps_profile(cfg, monkeypatch):
	monkeypatch.setitem(CONFIG.addons.ai, 'mode_profiles', {'chat': 'nope'})
	task = _task()
	items = list(task._apply_mode_profile())
	assert items[0]._type == 'warning' and task.model == 'top-model'


def test_auto_mode_profile_and_intent_usage(cfg, monkeypatch):
	"""Auto mode: the intent call is billed under the intent model, then the detected mode's profile runs the loop."""
	from secator.tasks.ai import ai
	monkeypatch.setitem(CONFIG.addons.ai, 'mode_profiles', {'exploit': 'big'})
	runner = ai([], prompt='do the thing', interactive='auto')
	seen = {}

	def fake_loop():
		seen.update(model=runner.model, mode=runner.mode)
		return iter(())
	intent = {'content': 'exploit', 'usage': {'tokens': 7, 'prompt_tokens': 5, 'completion_tokens': 2}}
	with patch('secator.tasks.ai.fast_detect_mode', return_value=None), \
		patch('secator.tasks.ai.call_llm', return_value=intent) as llm, \
		patch.object(runner, '_verify_model', lambda: iter(())), \
		patch.object(runner, '_system_prompt_for', lambda mode: 'SYS'), \
		patch.object(runner, '_run_loop', fake_loop), \
		patch.object(runner, '_mark_turn_completed', lambda: None):
		list(runner.yielder())
	assert llm.call_args.args[1] == 'top-intent'
	assert seen == {'model': 'big-model', 'mode': 'exploit'}
	usage = {'top-intent': {'prompt_tokens': 5, 'completion_tokens': 2, 'cached_tokens': 0}}
	assert runner.context['ai_usage_by_model'] == usage
	# Persisted like any context field: every driver stores the runner's toDict().
	assert runner.toDict()['context']['ai_usage_by_model'] == usage


def test_subagent_inherits_the_profile():
	from secator.ai.actions import ActionContext
	ctx = ActionContext(targets=[], model='m', profile='gw')
	assert ctx.profile == 'gw'


# ---- /model switch + usage per model ----

def _loop_task(model='top-model'):
	from secator.tasks.ai import ai
	from secator.ai.history import ChatHistory
	from secator.ai.interactivity import create_backend
	task = ai.__new__(ai)
	task.context = {}
	task.is_subagent = False
	task._init_usage_counters()
	task.history = ChatHistory()
	task.history.set_system('SYS')
	task.history.add_user('hello')
	for name, value in dict(
			inputs=[], in_scope=[], out_of_scope=[], model=model, intent_model=model, temp=0.7, api_base='',
			api_key='sk-top', ai_profile='default', max_iterations=3, max_tokens_total=100000, max_workers=1,
			verbose=False, dry_run=False, mode='chat', scope='workspace', encryptor=None, tool_schemas=[],
			permission_engine=None, dangerous=True, interactive='auto', _sync=True, session_id='s',
			_reports_folder=None).items():
		setattr(task, name, value)
	task._view = lambda *a, **kw: []
	task.debug = lambda *a, **k: None
	task.add_result = lambda *a, **k: None
	task.get_opt_value = lambda key: None
	task.backend = create_backend('auto')
	return task


def test_model_switch_keeps_history_and_splits_usage(cfg):
	from secator.tasks.ai import ai
	task = _loop_task()
	controls = iter([{}, {'profile': 'gw'}, {}])
	tui = types.SimpleNamespace(tui_poll_control=lambda: next(controls), tui_set_meta=lambda **k: None)
	sent = []

	def fake_llm(messages, model, *args, **kwargs):
		sent.append((model, [dict(m) for m in messages], kwargs.get('profile')))
		usage = {'tokens': 15, 'prompt_tokens': 10, 'completion_tokens': 5, 'cached_tokens': 4}
		return {'content': f'reply from {model}', 'tool_calls': [], 'usage': usage}
	turns = {'n': 0}

	def next_turn(choices, **kwargs):
		turns['n'] += 1
		if turns['n'] >= 2:
			return None
		task.history.add_user('and now?')
		return []
	with patch('secator.tasks.ai.call_llm', fake_llm), \
		patch('secator.rich.get_tui', return_value=tui), \
		patch('secator.tasks.ai.get_context_window', return_value=200000), \
		patch('secator.ai.history.get_context_window', return_value=200000), \
		patch('secator.tasks.ai.save_history'), \
		patch.object(ai, 'reports_folder', property(lambda self: None)), \
		patch.object(ai, '_summarize_auto', return_value=iter(())), \
		patch.object(ai, '_summarize_user', return_value=iter(())), \
		patch.object(ai, '_prompt_and_redetect', side_effect=next_turn):
		items = list(task._run_loop())
	(m1, msgs1, p1), (m2, msgs2, p2) = sent
	assert (m1, p1, m2, p2) == ('top-model', 'default', 'openai/gw-model', 'gw')
	# The second model gets the whole conversation, the first model's reply included.
	turns_of = lambda msgs: [(m['role'], m['content']) for m in msgs if m['role'] != 'system']  # noqa: E731
	assert turns_of(msgs2) == turns_of(msgs1) + [('assistant', 'reply from top-model'), ('user', 'and now?')]
	# Only provider-neutral keys reach it (plus secator's own `_` bookkeeping, stripped by call_llm).
	assert all(set(k for k in m if not k.startswith('_')) <= {'role', 'content', 'tool_calls'} for m in msgs2)
	assert (task.api_base, task.api_key, task.context['ai_model']) == (GW, PROFILES['gw']['api_key'], 'openai/gw-model')
	assert any(getattr(i, 'ai_type', '') == 'note' and 'gw' in i.content for i in items)
	row = {'prompt_tokens': 10, 'completion_tokens': 5, 'cached_tokens': 4}
	assert task.context['ai_usage_by_model'] == {'top-model': row, 'openai/gw-model': row}
	# The run totals are unchanged.
	assert (task.context['ai_tokens'], task.context['ai_prompt_tokens']) == (30, 20)


def test_model_switch_to_unknown_profile_warns(cfg):
	task = _loop_task()
	tui = types.SimpleNamespace(tui_poll_control=lambda: {'profile': 'nope'})
	with patch('secator.rich.get_tui', return_value=tui):
		items = list(task._apply_tui_control())
	assert items[0]._type == 'warning' and task.model == 'top-model'


def test_subagent_starts_with_empty_usage_by_model():
	from secator.ai.actions import ActionContext, _get_result_context
	parent = _loop_task()
	parent._account_usage({'prompt_tokens': 3, 'completion_tokens': 1}, 'm')
	ctx = ActionContext(targets=[], model='m', context=parent.context)
	assert 'ai_usage_by_model' not in _get_result_context({'name': 'ai'}, ctx)


def test_call_llm_reports_cached_tokens():
	from secator.ai import utils as u
	usage = types.SimpleNamespace(
		total_tokens=12, prompt_tokens=10, completion_tokens=2,
		prompt_tokens_details=types.SimpleNamespace(cached_tokens=6))
	msg = types.SimpleNamespace(content='ok', tool_calls=None)
	resp = types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg, finish_reason='stop')], usage=usage)
	with patch('litellm.completion', return_value=resp), patch('litellm.completion_cost', return_value=0.0):
		assert u.call_llm([{'role': 'user', 'content': 'hi'}], 'm', api_key='k')['usage']['cached_tokens'] == 6


# ---- OAuth2 per profile ----

def test_oauth2_uses_the_profile_settings(cfg, monkeypatch):
	from secator.ai import utils as u
	monkeypatch.setattr(u, '_oauth2_tokens', u.OAuth2TokenCache())
	profiles = {**PROFILES, 'sso': {
		'model': 'openai/m', 'api_base': GW, 'oauth2_endpoint': 'https://auth.example/oauth2/token',
		'oauth2_client_id': 'cid', 'oauth2_client_secret': 'profile-secret-0123456789'}}
	monkeypatch.setitem(CONFIG.addons.ai, 'profiles', profiles)
	token = MagicMock(status_code=200)
	token.json.return_value = {'access_token': 'tok-sso', 'expires_in': 300}
	msg = types.SimpleNamespace(content='ok', tool_calls=None)
	resp = types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg, finish_reason='stop')], usage=None)
	with patch('requests.post', return_value=token) as post, patch('litellm.completion', return_value=resp) as llm, \
		patch.object(u, '_estimate_usage', return_value={'tokens': 0}):
		u.call_llm([{'role': 'user', 'content': 'hi'}], 'openai/m', api_base=GW, profile='sso')
		assert post.call_args.kwargs['auth'] == ('cid', 'profile-secret-0123456789')
		assert llm.call_args.kwargs['api_key'] == 'tok-sso'
		# The default profile has no OAuth2: no token request for it.
		post.reset_mock()
		u.call_llm([{'role': 'user', 'content': 'hi'}], 'openai/m', api_base=GW, profile='default')
		post.assert_not_called()


# ---- TUI /model ----

async def _tui_model_body(cfg):
	from secator.tui.ai import AITUI
	from secator.tui.widgets import PromptInput
	app = AITUI(None)
	app.tui_set_model_source(lambda: {'messages': [], 'encrypted': False, 'profile': 'fast', 'model': 'fast-model'})
	async with app.run_test(size=(100, 30)) as pilot:
		inp = app.query_one('#prompt-input', PromptInput)
		for text in ('/model', '/model gw', '/model nope'):
			inp.focus()
			inp.text = text
			await pilot.press('enter')
			for _ in range(3):
				await pilot.pause()
		notes = [str(n.render()) for n in app._convo().query('.note')]
		control = app.tui_poll_control()
	return notes, control


def test_tui_model_lists_profiles_and_queues_the_switch(cfg):
	import asyncio
	pytest.importorskip('textual')
	notes, control = asyncio.run(_tui_model_body(cfg))
	listing = next(n for n in notes if 'AI profiles' in n)
	for name, model in (('default', 'top-model'), ('fast', 'fast-model'), ('gw', 'openai/gw-model')):
		assert name in listing and model in listing
	assert '● fast' in listing  # the profile in use
	assert any('switching to AI profile gw' in n for n in notes)
	assert any('Unknown AI profile "nope"' in n for n in notes)
	assert control == {'profile': 'gw'}  # only the valid switch reaches the runner

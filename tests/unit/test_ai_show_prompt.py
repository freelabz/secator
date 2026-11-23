"""Tests for `ai --show-prompt`: the rendered system prompt goes to stdout verbatim."""
import re
from unittest.mock import patch

import pytest

from secator.definitions import ADDONS_ENABLED

pytestmark = pytest.mark.skipif(not ADDONS_ENABLED['ai'], reason='ai addon not installed')

# Brackets / emoji codes / long lines that Rich would interpret, strip or wrap.
PROMPT = (
	'<persona>\n[scan] keep [bold]this[/bold] and [/x] as-is :warning:\n</persona>\n'
	+ 'x' * 300 + '\n<rule:rules/a.md>\nbody with ```code``` fences\n</rule>'
)


def _plain(text):
	"""Drop ANSI styling (the stderr header may be colored when color is forced)."""
	return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _run(run_opts, prompt=PROMPT, credential_error=None):
	from secator.tasks.ai import ai
	runner = ai([], show_prompt=True, **run_opts)
	seen = {}
	init_options = runner._init_options

	def _init():
		init_options()
		if credential_error:
			runner._credential_error = credential_error

	def _fake_prompt(mode):
		seen['mode'] = mode
		return prompt
	with patch.object(runner, '_system_prompt_for', _fake_prompt), patch.object(runner, '_init_options', _init), \
		patch.object(runner, '_verify_model', side_effect=AssertionError('model must not be verified')):
		results = list(runner.yielder())
	return results, seen


def test_show_prompt_writes_raw_prompt_to_stdout(capfd):
	results, seen = _run({'mode': 'chat'})
	out, err = capfd.readouterr()
	assert out == PROMPT + '\n'
	assert 'System prompt (chat)' in _plain(err)
	assert 'System prompt' not in out
	assert seen['mode'] == 'chat'
	assert not [r for r in results if r._type == 'error']


def test_show_prompt_defaults_to_scan_mode(capfd):
	_, seen = _run({})
	out, err = capfd.readouterr()
	assert seen['mode'] == 'scan'
	assert 'System prompt (scan)' in _plain(err)
	assert out == PROMPT + '\n'


def test_show_prompt_renders_real_chat_and_scan_prompts(capfd):
	from secator.tasks.ai import ai
	for mode, marker in (('chat', 'CHAT mode'), ('scan', 'SCAN mode')):
		runner = ai([], show_prompt=True, mode=mode)
		list(runner.yielder())
		out, err = capfd.readouterr()
		assert marker in out
		assert out.startswith('<current_mode>')
		assert f'System prompt ({mode})' in _plain(err)


def test_show_prompt_needs_no_llm_credentials(capfd):
	# Unusable LLM credentials refuse a real run, but rendering the prompt doesn't talk
	# to the LLM so it must still work.
	results, _ = _run({'mode': 'chat'}, credential_error='A custom api_base requires you to provide your own api_key.')
	out, _ = capfd.readouterr()
	assert out == PROMPT + '\n'
	assert not [r for r in results if r._type == 'error']


def test_mode_name_as_model_warns():
	results, _ = _run({'mode': 'chat', 'model': 'chat'})
	warnings = [r for r in results if r._type == 'warning']
	assert warnings and '--mode chat' in warnings[0].message


def test_real_model_does_not_warn():
	results, _ = _run({'mode': 'chat', 'model': 'gpt-4o-mini'})
	assert not [r for r in results if r._type == 'warning']

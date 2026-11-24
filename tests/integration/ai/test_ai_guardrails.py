"""G. Guardrails and scope: out-of-scope targets are denied (task, shell, container command),
a retried denial stays denied, and secrets in output are encrypted before the model sees them."""
import pytest

from tests.integration.ai.scripted import call, say, tools

DENIED = '10.255.0.1'


def _scope_denied(text):
	return f'{DENIED}' in text and 'not in the allowed scope (reason: out_of_scope)' in text


# an image that is never pulled: if the scope check ever let these through, nothing leaves the host
NO_PULL = '--rm --pull=never local/none:never'


def _deny_shell(command):
	return lambda: call('run_shell', id='deny', command=command, description='x')


OUT_OF_SCOPE_CALLS = {
	'task': lambda: call('run_task', id='deny', name='httpx', targets=[f'http://{DENIED}/'], description='x'),
	'shell': _deny_shell(f'curl -s http://{DENIED}/'),
	'docker': _deny_shell(f'docker run {NO_PULL} curl http://{DENIED}/'),
	'docker_sh_c': _deny_shell(f'docker run {NO_PULL} sh -c "wget -qO- http://{DENIED}/"'),
	'podman': _deny_shell(f'podman run {NO_PULL} wget http://{DENIED}/'),
}


@pytest.mark.parametrize('kind', list(OUT_OF_SCOPE_CALLS))
def test_out_of_scope_target_is_denied(run_ai, kind, monkeypatch):
	if kind == 'podman':  # not in the default shell allow-list: allow it so the scope check decides
		from secator.config import CONFIG
		monkeypatch.setitem(CONFIG.addons.ai.permissions, 'allow',
		                    CONFIG.addons.ai.permissions['allow'] + ['shell(podman)'])
	run = run_ai(f'guard_scope_{kind}', [
		tools(OUT_OF_SCOPE_CALLS[kind]()),
		tools(call('run_shell', id='ok', command='echo in-scope-work', description='Allowed')),
		say('done'),
	], out_of_scope=[DENIED])
	denial = run.tool_result('deny')
	assert _scope_denied(denial), denial
	assert 'in-scope-work' in run.tool_result('ok')
	# nothing ran for the denied call: only the allowed shell left a runner
	assert [c['name'] for c in run.children()] == ['command']


def test_in_scope_allow_list(run_ai, lab):
	"""in_scope narrows the run: a target outside it is denied, one inside runs."""
	run = run_ai('guard_in_scope', [
		tools(call('run_task', id='in', name='httpx', targets=[lab.url], description='In scope'),
		      call('run_task', id='out', name='httpx', targets=[f'http://{DENIED}/'], description='Out of scope')),
		say('done'),
	], in_scope=['127.0.0.1'])
	assert any(r.get('_type') == 'url' for r in run.tool_json('in')['results'])
	assert 'denied' in run.tool_result('out').lower() and DENIED in run.tool_result('out')


def test_retrying_a_denied_target_stays_denied(run_ai):
	run = run_ai('guard_retry', [
		tools(call('run_shell', id='try1', command=f'curl -s http://{DENIED}/', description='x')),
		tools(call('run_shell', id='try2', command=f'curl -s http://{DENIED}/', description='retry')),
		say('Giving up on that host.'),
	], out_of_scope=[DENIED])
	assert _scope_denied(run.tool_result('try1'))
	assert _scope_denied(run.tool_result('try2'))
	assert len(run.requests) == 3
	assert run.children() == []


def test_unknown_target_without_a_user_is_denied(run_ai, lab):
	"""A non-interactive run cannot ask: a target outside its targets (target(*) = ask) is denied."""
	run = run_ai('guard_ask_auto', [
		tools(call('run_task', id='t', name='httpx', targets=[f'http://localhost:{lab.port}/'], description='x')),
		say('done'),
	])
	assert 'not approved' in run.tool_result('t')


def test_secrets_are_encrypted_before_reaching_the_model(run_ai, lab, model):
	run = run_ai('guard_secrets', [
		tools(call('run_shell', id='leak', command=f'curl -s {lab.url}/leak', description='Read config')),
		say('done'),
	], sensitive=True)
	every_request = '\n'.join(r.text() for r in model.requests)
	assert 'AKIAIOSFODNN7EXAMPLE' not in every_request
	assert 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' not in every_request
	assert 'aws_access_key_id' in run.tool_result('leak')  # the output itself did reach the model

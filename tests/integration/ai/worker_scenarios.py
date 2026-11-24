"""Scripts of the worker-mode scenarios (test_ai_worker.py), built inside the Celery worker.

The ai task runs in the worker, so its model does too: the worker module (worker_app.py) builds
a scenario's turns from its tag ``<name>@<pool>`` with :func:`build`. A subagent's tag is
``<name>.child@<pool>``. The lab URLs come from the worker environment.
"""
import os

from tests.integration.ai.scripted import Turn, call, say, tools

WORKFLOW = 'ai_e2e_probe'
REVOKE_CHILD_S = 20  # how long the children of the revoke scenarios run


def _lab(n=1):
	return os.environ[f'AI_E2E_LAB_URL{"" if n == 1 else n}']


def batch(suffix):
	"""One turn: an in-process task, a shell and a dispatched workflow, run in parallel."""
	return [
		tools(
			call('run_task', id='inproc', name='httpx', targets=[f'{_lab()}/slow?s=3&id=inproc{suffix}'],
			     description='In-process'),
			call('run_shell', id='sh', command=f"curl -s '{_lab()}/slow?s=3&id=sh{suffix}' >/dev/null; echo worker-shell",
			     description='Shell'),
			call('run_workflow', id='wf', name=WORKFLOW, targets=[f'{_lab(2)}/slow?s=3&id=wf{suffix}'],
			     description='Workflow'),
		),
		say('done'),
	]


def chunked(suffix):
	"""A task on 2 targets with input_chunk_size=1: dispatched and split into chunks."""
	return [
		tools(call('run_task', id='chunked', name='httpx', targets=[_lab(), f'{_lab(2)}/login'], description='Chunks')),
		say('done'),
	]


def background(suffix):
	"""Background: a detached (fire-and-forget) dispatched workflow and a chunked task, plus a
	foreground shell in the same turn."""
	return [
		tools(
			call('run_workflow', id='bg_wf', name=WORKFLOW, targets=[f'{_lab()}/slow?s=2'], description='Bg workflow',
			     background=True),
			call('run_task', id='bg_chunked', name='httpx', targets=[f'{_lab()}/slow?s=2', f'{_lab(2)}/slow?s=2'],
			     description='Bg chunked', background=True),
			call('run_shell', id='fg', command='echo fg-while-bg', description='Foreground'),
		),
		tools(call('check_background_jobs', id='chk1', wait=90)),
		tools(call('check_background_jobs', id='chk2', wait=90)),
		say('done'),
	]


def cancel_chunked(suffix):
	return [
		tools(call('run_task', id='bg', name='httpx', targets=[f'{_lab()}/slow?s=40', f'{_lab(2)}/slow?s=40'],
		           description='Long chunks', background=True)),
		Turn(calls=[call('cancel_background_job', id='cancel', job_id='bg-1')], delay=4),
		say('done'),
	]


def subagent_fg(suffix):
	return [
		tools(call('run_subagent', id='sub', objective=f'[scenario:subagent_fg.child{suffix}] Probe the lab.',
		           description='Subagent', background=False)),
		say('done'),
	]


def subagent_fg_child(suffix):
	return [
		tools(call('run_shell', id='c_sh', command='echo child-in-worker', description='Child shell'),
		      call('run_task', id='c_task', name='httpx', targets=[_lab()], description='Child task')),
		say('Child verdict: lab home answers 200.'),
	]


def subagent_bg(suffix):
	return [
		tools(call('run_subagent', id='sub', objective=f'[scenario:subagent_bg.child{suffix}] Probe the lab.',
		           description='Bg subagent')),
		tools(call('run_shell', id='parent', command='echo parent-busy', description='Parent work')),
		tools(call('check_background_jobs', id='chk', wait=90)),
		say('done'),
	]


def subagent_bg_child(suffix):
	return [
		tools(call('run_shell', id='c_sh', command='sleep 2; echo bg-child-own-call', description='Child shell'),
		      call('run_task', id='c_chunked', name='httpx', targets=[_lab(), _lab(2)], description='Child chunks')),
		say('Bg child verdict: done.'),
	]


def revoke(suffix):
	"""Long children the client revokes the ai task under."""
	return [
		tools(
			call('run_shell', id='sh', command=f'sleep {REVOKE_CHILD_S}', description='Long shell'),
			call('run_task', id='chunked', name='httpx',
			     targets=[f'{_lab()}/slow?s={REVOKE_CHILD_S}', f'{_lab(2)}/slow?s={REVOKE_CHILD_S}'],
			     description='Long chunks'),
		),
		say('never reached'),
	]


def revoke_chunked(suffix):
	"""Only a long chunked task (dispatched chunks): the client revokes the ai task under it."""
	return [
		tools(call('run_task', id='chunked', name='httpx', targets=[f'{_lab()}/slow?s=90', f'{_lab(2)}/slow?s=90'],
		           description='Long chunks')),
		say('never reached'),
	]


SCENARIOS = {
	'batch': batch,
	'chunked': chunked,
	'background': background,
	'cancel_chunked': cancel_chunked,
	'subagent_fg': subagent_fg,
	'subagent_fg.child': subagent_fg_child,
	'subagent_bg': subagent_bg,
	'subagent_bg.child': subagent_bg_child,
	'revoke': revoke,
	'revoke_chunked': revoke_chunked,
}


def build(tag):
	name, _, pool = tag.partition('@')
	factory = SCENARIOS.get(name)
	if factory is None:
		return [say(f'(unknown worker scenario {tag})')]
	return factory(f'@{pool}' if pool else '')

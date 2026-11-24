"""Prompts to the user (remote channel on the mongodb driver): answered, timed out, left
pending at run end and answered later (resume), and the permission "ask" path."""
import pytest

from tests.integration.ai.conftest import Answerer, driver_context, store_for
from tests.integration.ai.scripted import call, say, stop, tools


def _ctx(tag):
	return driver_context('mongodb', session_id=f'sess-{tag}')


def _prompt_docs(context, ai_type='stopped'):
	return [d for d in store_for(context).search({'_type': 'ai', '_context.session_id': context['session_id']})
	        if d.get('ai_type') == ai_type]


def test_prompt_answered(run_ai, mongo, remote):
	tag = 'prompt_answered'
	ctx = _ctx(tag)
	# answer the stop's choices only; the final pause is left to time out
	with Answerer(ctx, lambda doc: 'scan more please' if doc.get('choices') else None) as answerer:
		run = run_ai(tag, [
			tools(call('stop', reason='First pass done.', choices=['scan more please', 'stop here'])),
			tools(call('run_shell', id='after', command='echo after-answer', description='Go on')),
			say('Nothing else to do.'),
		], interactive='remote', context=ctx)
	assert [d['content'] for d in answerer.answered] == ['First pass done.']
	assert 'scan more please' in run.requests[1].last_user()
	assert 'after-answer' in run.tool_result('after')
	answered = [d for d in _prompt_docs(ctx) if d.get('status') == 'answered']
	assert [d['answer'] for d in answered] == ['scan more please']


def test_prompt_times_out_and_stays_pending(run_ai, mongo, remote):
	"""Nobody answers: the run ends cleanly and its prompt stays answerable, marked run_ended."""
	tag = 'prompt_timeout'
	ctx = _ctx(tag)
	run = run_ai(tag, [say('What should I scan next?')], interactive='remote', context=ctx)
	assert remote.timeout <= run.elapsed < remote.timeout + 15
	assert run.status in ('SUCCESS', 'FAILURE')
	pending = [d for d in _prompt_docs(ctx) if d.get('status') == 'pending']
	assert len(pending) == 1, _prompt_docs(ctx)
	assert pending[0]['content'] == 'What should I scan next?'
	assert (pending[0].get('extra_data') or {}).get('run_ended') is True


def test_answer_a_pending_prompt_after_the_run_ended(run_ai, mongo, remote):
	"""#1720: a prompt left pending by an ended run is answered later; the next run of the
	session restores the conversation and goes on from that answer."""
	tag = 'prompt_resume'
	ctx = _ctx(tag)
	run_ai(tag, [say('Shall I probe the login page?')], interactive='remote', context=ctx)
	[pending] = [d for d in _prompt_docs(ctx) if d.get('status') == 'pending']
	store_for(ctx).update({'_type': 'ai', '_uuid': pending['_uuid'], 'status': 'pending'},
	                      {'$set': {'status': 'answered', 'answer': 'yes, probe it'}})
	# the respawned run: same session, no new prompt
	run2 = run_ai(tag, [
		tools(call('run_shell', id='resumed', command='echo resumed-work', description='Continue')),
		say('done'),
	], interactive='remote', context=ctx, prompt=None)
	text = run2.requests[0].text()
	assert 'Shall I probe the login page?' in text, 'the restored history lacks the earlier turn'
	assert 'yes, probe it' in text, 'the late answer was not applied'
	assert 'resumed-work' in run2.tool_result('resumed')


@pytest.mark.parametrize('answer,expect', [('allow', 'reached'), ('deny', 'not approved')])
def test_permission_ask(run_ai, mongo, remote, lab, answer, expect):
	"""A target outside the run's targets hits the ``target(*)`` ask rule: the user decides."""
	tag = f'prompt_permission_{answer}'
	ctx = _ctx(tag)
	url = f'http://localhost:{lab.port}/'  # not the run's target (127.0.0.1) -> ask
	with Answerer(ctx, lambda doc: answer if doc.get('ai_type') == 'permission' else None) as answerer:
		run = run_ai(tag, [
			tools(call('run_shell', id='sh', command=f'curl -s {url} >/dev/null && echo reached',
			           description='Fetch')),
			stop('done'),
		], interactive='remote', context=ctx)
	perms = [d for d in answerer.answered if d.get('ai_type') == 'permission']
	assert perms, 'no permission prompt was raised'
	assert 'localhost' in perms[0].get('content', '') + str(perms[0].get('extra_data'))
	assert expect in run.tool_result('sh')

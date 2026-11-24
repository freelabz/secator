"""E'. Background jobs and the end of a turn.

Minimal design: a background job never blocks the turn, the status block of running jobs is
injected at the start of every turn, and new turns only come from the user. While jobs run the
run is not stopped (the idle timeout is frozen); a non-interactive run waits for its jobs, then
gives the model one turn; an explicit stop cancels the jobs.

Event-driven wake (later, 1.0): a job finishing wakes the model too, with its results.

Remote channel on the mongodb driver where a user is involved (an ended turn is a pending
prompt the user can answer).
"""
import time

import pytest

from tests.integration.ai.conftest import Answerer, driver_context, store_for
from tests.integration.ai.scripted import call, say, stop, tools

FROZEN_IDLE = 'minimal background jobs: the idle timeout is not frozen yet while jobs run'
STOP_CANCELS = (
	'minimal background jobs: an explicit stop does not cancel running jobs yet (the run '
	'waits for them, then gives the model another turn)')
EVENT_WAKE = 'event-driven wake, 1.0'


def _ctx(tag):
	return driver_context('mongodb', session_id=f'sess-{tag}')


def _pending(context):
	return [d for d in store_for(context).search({'_type': 'ai', '_context.session_id': context['session_id']})
	        if d.get('ai_type') == 'stopped' and d.get('status') == 'pending']


def _bg(job_id, seconds, out):
	"""A background shell job: sleeps, then prints ``out`` (formatted, so the command text that
	tool results echo back never contains it)."""
	a, b = out.rsplit('-', 1)
	return call('run_shell', id=job_id, command=f"sleep {seconds}; printf '{a}-%s\\n' {b}",
	            description=f'Job {job_id}', background=True)


# ---------------------------------------------------------------------------
# Minimal design
# ---------------------------------------------------------------------------

def test_non_interactive_run_waits_for_jobs_then_gets_one_turn(run_ai):
	"""The model ends its turn with a job running: the run waits for the job, then gives the
	model one more turn, told the job finished; it reads the results with a check."""
	run = run_ai('end_wait_jobs', [
		tools(_bg('bg', 5, 'wait-out-66')),
		say('Waiting for the job.'),
		tools(call('check_background_jobs', id='chk')),
		say('The job is done.'),
	])
	assert len(run.requests) == 4, [r.last_user()[:80] for r in run.requests]
	turn = run.requests[2]
	assert turn.t - run.requests[1].t >= 3, 'the turn came before the job finished'
	assert 'bg-1 [done' in turn.text() and 'FINISHED since you last read them: bg-1' in turn.text()
	assert 'wait-out-66' in run.tool_result('chk')


@pytest.mark.xfail(strict=True, reason=STOP_CANCELS)
def test_explicit_stop_cancels_running_jobs(run_ai):
	"""The model stops the run while a job runs: the job is cancelled, the run ends at once."""
	run = run_ai('end_stop_cancels', [
		tools(_bg('bg', 20, 'stop-out-77')),
		stop('Nothing more to do.'),
		say('(an extra turn: the stop did not end the run)'),
	])
	assert len(run.requests) == 2, 'the model got another turn after its stop'
	assert run.elapsed < 15, 'the run waited for the job'
	jobs = [r for r in run.stored('ai') if r.get('ai_type') == 'background_job']
	assert any((r.get('extra_data') or {}).get('status') == 'cancelled' for r in jobs), jobs


def test_user_message_while_a_job_runs(run_ai, mongo, remote):
	"""The user writes while a job runs: the model gets a turn with the message, the job still
	running (status block); the job is not cancelled by the new turn."""
	tag = 'end_user_message'
	ctx = _ctx(tag)
	remote.set_timeout(3)
	answers = iter(['what about the login page?'])
	with Answerer(ctx, lambda doc: next(answers, None)):
		run = run_ai(tag, [
			tools(_bg('bg', 8, 'msg-out-22')),
			say('Waiting for the job.'),
			say('Looking at the login page while the job runs.'),
			say('The job is done.'),
		], interactive='remote', context=ctx)
	by_message = run.requests[2]
	assert 'what about the login page?' in by_message.last_user()
	assert 'bg-1 [running' in by_message.text(), 'the job did not keep running'
	assert 'msg-out-22' not in by_message.text()


@pytest.mark.xfail(strict=True, reason=FROZEN_IDLE)
def test_idle_timeout_is_frozen_while_jobs_run(run_ai, mongo, remote):
	"""Nobody answers: the idle timeout does not end the run while a job runs; once none runs,
	the timeout applies again and the run ends, its prompt left pending (run_ended). No new
	turn comes from the job finishing (turns only come from the user)."""
	tag = 'end_frozen_idle'
	ctx = _ctx(tag)
	remote.set_timeout(2)
	start = time.monotonic()
	run = run_ai(tag, [
		tools(_bg('bg', 6, 'idle-out-55')),
		say('Waiting for the job.'),
	], interactive='remote', context=ctx)
	elapsed = time.monotonic() - start
	assert 6 <= elapsed < 6 + 2 + 15, f'the run ended after {elapsed:.0f}s'
	assert len(run.requests) == 2
	jobs = [r for r in run.stored('ai') if r.get('ai_type') == 'background_job']
	assert any((r.get('extra_data') or {}).get('status') == 'done' for r in jobs), jobs
	pending = _pending(ctx)
	assert [d['content'] for d in pending] == ['Waiting for the job.'], pending
	assert (pending[0].get('extra_data') or {}).get('run_ended') is True


# ---------------------------------------------------------------------------
# Event-driven wake (1.0)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=EVENT_WAKE)
def test_ended_turn_is_woken_once_when_the_job_finishes(run_ai, mongo, remote):
	"""The model ends its turn with a job running: it is woken exactly once, when the job
	finishes, with the job's results; then the run idles out as usual."""
	tag = 'wake_on_finish'
	ctx = _ctx(tag)
	remote.set_timeout(2)
	run = run_ai(tag, [
		tools(_bg('bg', 5, 'wake-out-11')),
		say('Waiting for the job.'),
		say('The job is done.'),
	], interactive='remote', context=ctx)
	assert len(run.requests) == 3, [r.last_user()[:80] for r in run.requests]
	woken = run.requests[2]
	assert 'wake-out-11' in woken.text(), 'the wake did not carry the job results'
	assert woken.t - run.requests[1].t >= 3, 'woken before the job finished'


@pytest.mark.xfail(strict=True, reason=EVENT_WAKE)
def test_woken_by_a_message_then_again_when_the_job_finishes(run_ai, mongo, remote):
	"""Woken by the user's message while the job runs, then woken again by the job finishing."""
	tag = 'wake_message_then_job'
	ctx = _ctx(tag)
	remote.set_timeout(3)
	answers = iter(['what about the login page?'])
	with Answerer(ctx, lambda doc: next(answers, None)):
		run = run_ai(tag, [
			tools(_bg('bg', 8, 'again-out-23')),
			say('Waiting for the job.'),
			say('Looking at the login page while the job runs.'),
			say('The job is done.'),
		], interactive='remote', context=ctx)
	assert len(run.requests) == 4, [r.last_user()[:80] for r in run.requests]
	assert 'again-out-23' in run.requests[3].text()


@pytest.mark.xfail(strict=True, reason=EVENT_WAKE)
def test_two_jobs_finishing_together_wake_once(run_ai, mongo, remote):
	"""Two jobs finishing at the same time wake the model once, with both results."""
	tag = 'wake_two_jobs'
	ctx = _ctx(tag)
	remote.set_timeout(2)
	run = run_ai(tag, [
		tools(_bg('bg_a', 4, 'two-a-33'), _bg('bg_b', 4, 'two-b-44')),
		say('Waiting for both jobs.'),
		say('Both done.'),
	], interactive='remote', context=ctx)
	assert len(run.requests) == 3, [r.last_user()[:80] for r in run.requests]
	text = run.requests[2].text()
	assert 'two-a-33' in text and 'two-b-44' in text

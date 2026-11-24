"""E. Background jobs: started at once, polled with check_background_jobs, cancelled, torn down;
background subagents; a model that polls in a loop.

Runs in-process (sync). The same scenarios run in a real Celery worker in test_ai_worker.py.
"""
import pytest

from tests.integration.ai.conftest import FINAL_STATUSES
from tests.integration.ai.scripted import Turn, call, say, tools


def _job_status(run, call_id):
	"""(status of the background_job entry, other results) of a check/cancel tool result."""
	results = run.tool_json(call_id)['results']
	jobs = [r for r in results if r.get('_type') == 'background_job' or 'job_id' in r]
	return jobs, [r for r in results if r not in jobs]


def test_background_task_while_the_model_keeps_working(run_ai):
	run = run_ai('bg_one', [
		tools(call('run_shell', id='bg', command='sleep 4; echo bg-finished', description='Long', background=True)),
		tools(call('run_shell', id='fg', command='echo meanwhile', description='Foreground work')),
		tools(call('check_background_jobs', id='chk', job_ids=['bg-1'], wait=20)),
		say('done'),
	])
	r0, r1, r2 = run.requests[:3]
	assert r1.t - r0.t < 3, 'a background call must not block the turn'
	assert 'Started background job bg-1' in r1.tool_result('bg')
	assert 'meanwhile' in r2.tool_result('fg')
	assert '<background_jobs>' in r2.text() and 'bg-1 [running' in r2.text()  # status block each turn
	result = run.tool_result('chk')
	assert 'bg-finished' in result
	assert '"status":"done"' in result.replace(' ', '')
	cmd = run.children('command')
	assert len(cmd) == 2 and all(c['status'] == 'SUCCESS' for c in cmd), cmd
	# the job's transitions are recorded in the run's store
	jobs = [r for r in run.stored('ai') if r.get('ai_type') == 'background_job']
	assert any((r.get('extra_data') or {}).get('status') == 'done' for r in jobs), jobs


def test_two_background_and_one_foreground_in_one_turn(run_ai):
	"""The turn waits for the foreground call only; both background jobs run on."""
	run = run_ai('bg_two_plus_sync', [
		tools(
			call('run_shell', id='bg1', command='sleep 6; echo one', description='Bg 1', background=True),
			call('run_shell', id='bg2', command='sleep 6; echo two', description='Bg 2', background=True),
			call('run_shell', id='fg', command='sleep 2; echo sync-done', description='Sync'),
		),
		# wait returns once ONE of the jobs finished: poll twice to read both
		tools(call('check_background_jobs', id='chk', wait=20)),
		tools(call('check_background_jobs', id='chk2', wait=20)),
		say('done'),
	])
	r0, r1 = run.requests[:2]
	gap = r1.t - r0.t
	assert 2 <= gap < 5, f'turn took {gap:.1f}s: it should wait for the 2s foreground call only'
	assert 'sync-done' in r1.tool_result('fg')
	assert 'bg-1' in r1.tool_result('bg1') and 'bg-2' in r1.tool_result('bg2')
	outputs = [r['content'] for c in ('chk', 'chk2') for r in run.tool_json(c)['results']
	           if r.get('ai_type') == 'shell_output']
	assert set(outputs) == {'one', 'two'}  # each once: see test_finished_job_results_are_reported_once


def test_cancel_background_job(run_ai):
	run = run_ai('bg_cancel', [
		tools(call('run_shell', id='bg', command='sleep 60; echo never', description='Server', background=True)),
		Turn(calls=[call('cancel_background_job', id='cancel', job_id='bg-1')], delay=1),
		tools(call('check_background_jobs', id='chk', job_ids=['bg-1'])),
		say('done'),
	])
	assert run.elapsed < 30, 'the cancelled command kept running'
	assert '"status":"cancelled"' in run.tool_result('cancel').replace(' ', '')
	outputs = [r['content'] for r in run.tool_json('chk')['results'] if r.get('ai_type') == 'shell_output']
	assert all('never' not in o for o in outputs), outputs
	cmd = run.children('command')
	assert cmd and all(c['status'] in FINAL_STATUSES for c in cmd), cmd


@pytest.mark.parametrize('ending', ['max_wait', 'llm_error'])
def test_job_still_running_when_the_run_ends(run_ai, ending):
	"""A job outliving the run is cancelled and its final status recorded.

	max_wait: the model ends its turn, the non-interactive run waits up to background_max_wait
	then cancels the job and gives the model one turn. llm_error: the run dies on a model
	error while the job runs (teardown cancels it)."""
	def boom(req):
		raise RuntimeError('provider exploded')

	turns = [tools(call('run_shell', id='bg', command='sleep 60', description='Long', background=True))]
	if ending == 'max_wait':
		turns += [say('I will stop here.'), say('ok, done')]
	else:
		turns += [boom]
	run = run_ai(f'bg_run_end_{ending}', turns, background_max_wait=2)
	assert run.elapsed < 30
	if ending == 'max_wait':
		assert 'cancelled bg-1' in run.requests[2].text()
	else:
		assert any('provider exploded' in e for e in run.errors())
	jobs = [r for r in run.stored('ai') if r.get('ai_type') == 'background_job']
	assert any((r.get('extra_data') or {}).get('status') == 'cancelled' for r in jobs), jobs
	cmd = run.children('command')
	assert cmd and all(c['status'] in FINAL_STATUSES for c in cmd), cmd


@pytest.mark.parametrize('tool,args,expected', [
	('check_background_jobs', {'job_ids': ['bg-99']}, "Unknown background job(s): ['bg-99']"),
	('cancel_background_job', {'job_id': 'bg-99'}, "Unknown background job 'bg-99'"),
	('check_background_jobs', {}, 'No background jobs.'),
], ids=['check_unknown', 'cancel_unknown', 'check_none'])
def test_unknown_background_job(run_ai, tool, args, expected):
	run = run_ai(f'bg_unknown_{tool}_{len(args)}', [
		tools(call(tool, id='c', **args)),
		say('done'),
	])
	assert expected in run.tool_result('c')


def test_background_job_limit(run_ai):
	run = run_ai('bg_limit', [
		tools(*[call('run_shell', id=f'bg{i}', command='sleep 30', description=f'Bg {i}', background=True)
		        for i in range(3)]),
		tools(call('cancel_background_job', id='c1', job_id='bg-1'), call('cancel_background_job', id='c2', job_id='bg-2')),
		say('done'),
	], background_max_jobs=2)
	assert 'Too many background jobs running (2/2)' in run.tool_result('bg2')
	assert run.elapsed < 25


@pytest.mark.xfail(strict=True, reason=(
	'bug: check_background_jobs re-reads a job\'s findings from the store on every poll and only '
	'dedupes by _uuid, which the job\'s own buffered items do not carry yet: a finished job\'s '
	'output is reported again on the next check, and its stat items leak into the results'))
def test_finished_job_results_are_reported_once(run_ai):
	run = run_ai('bg_report_once', [
		tools(call('run_shell', id='bg', command='sleep 2; echo once', description='Bg', background=True)),
		tools(call('check_background_jobs', id='chk1', wait=20)),
		tools(call('check_background_jobs', id='chk2')),
		say('done'),
	])
	first = run.tool_json('chk1')['results']
	second = run.tool_json('chk2')['results']
	assert [r['content'] for r in first if r.get('ai_type') == 'shell_output'] == ['once']
	assert not [r for r in first + second if r.get('_type') == 'stat']
	assert not [r for r in second if r.get('ai_type') == 'shell_output'], second


@pytest.mark.xfail(strict=True, reason=(
	'bug: a cancelled background job is reported "cancelled" to the model, but the runner it ran '
	'is persisted with status SUCCESS (the killed command / the stopped subagent), not REVOKED'))
@pytest.mark.parametrize('kind', ['shell', 'subagent'])
def test_cancelled_job_runner_is_revoked(run_ai, model, kind):
	tag = f'bg_revoked_{kind}'
	if kind == 'shell':
		spawn = call('run_shell', id='bg', command='sleep 60', description='Server', background=True)
		name = 'command'
	else:
		model.script([tools(call('run_shell', command='sleep 60', description='x')), say('x')], tag=f'{tag}.child')
		spawn = call('run_subagent', id='bg', objective=f'[scenario:{tag}.child] go', description='Sub')
		name = 'ai'
	run = run_ai(tag, [
		tools(spawn),
		Turn(calls=[call('cancel_background_job', id='cancel', job_id='bg-1')], delay=2),
		say('done'),
	])
	assert '"status":"cancelled"' in run.tool_result('cancel').replace(' ', '')
	statuses = [c['status'] for c in run.children(name)]
	assert statuses == ['REVOKED'], statuses


# ---------------------------------------------------------------------------
# Background subagents
# ---------------------------------------------------------------------------

def _spawn(child_tag, call_id='sub', **kw):
	return call('run_subagent', id=call_id, objective=f'[scenario:{child_tag}] Check the lab home page.',
	            description='Subagent', **kw)


def test_background_subagent_handback(run_ai, model):
	"""The parent keeps working while the subagent runs; the handback arrives through the job."""
	model.script([
		Turn(calls=[call('run_shell', id='child_sh', command='sleep 3; echo child-slept', description='Work')]),
		say('Background verdict: inconclusive.'),
	], tag='sub_bg.child')
	run = run_ai('sub_bg', [
		tools(_spawn('sub_bg.child')),  # background by default
		tools(call('run_shell', id='parent_work', command='echo parent-busy', description='Parent work')),
		tools(call('check_background_jobs', id='chk', wait=30)),
		say('done'),
	])
	r0, r1 = run.requests[:2]
	assert r1.t - r0.t < 3, 'a background subagent must not block the parent turn'
	assert 'Started background job bg-1' in r1.tool_result('sub')
	assert 'parent-busy' in run.tool_result('parent_work')
	assert 'Background verdict: inconclusive.' in run.tool_result('chk')
	assert '[subagent handback]' in run.tool_result('chk')


def test_tool_calls_inside_a_background_subagent_run_in_the_foreground(run_ai, model):
	"""The subagent's own calls are foreground for it: its next request carries their output.

	(A subagent running in its parent's background job thread must not hand its own calls to
	the parent's background registry.)"""
	model.script([
		tools(call('run_shell', id='c_sh', command='sleep 1; echo child-own-result', description='Own call'),
		      call('run_task', id='c_task', name='httpx', targets=['http://127.0.0.1:1'], description='Own task')),
		say('child done'),
	], tag='sub_bg_fg.child')
	run = run_ai('sub_bg_fg', [
		tools(_spawn('sub_bg_fg.child')),
		tools(call('check_background_jobs', id='chk', wait=30)),
		say('done'),
	])
	child = model.for_tag('sub_bg_fg.child')
	assert len(child) == 2
	assert 'child-own-result' in child[1].tool_result('c_sh')
	assert 'Started background job' not in child[1].tool_result('c_task')
	assert 'child done' in run.tool_result('chk')


def test_cancel_background_subagent(run_ai, model):
	model.script([
		tools(call('run_shell', id='c_sh', command='sleep 60; echo never', description='Long child work')),
		say('child should never get here'),
	], tag='sub_cancel.child')
	run = run_ai('sub_cancel', [
		tools(_spawn('sub_cancel.child')),
		Turn(calls=[call('cancel_background_job', id='cancel', job_id='bg-1')], delay=2),
		say('done'),
	])
	assert '"status":"cancelled"' in run.tool_result('cancel').replace(' ', '')
	assert run.elapsed < 30, f'cancelled subagent kept the run alive ({run.elapsed:.0f}s)'
	assert len(model.for_tag('sub_cancel.child')) == 1  # it never got another turn
	subs = run.children('ai')
	assert subs and all(c['status'] in FINAL_STATUSES for c in subs), subs


# ---------------------------------------------------------------------------
# A model that polls in a loop
# ---------------------------------------------------------------------------

POLL_JOB_S = 120  # a ~2 min background job
POLL_CAP = 300  # model-side cap on poll turns: bounds the run while there is no poll backoff


def _poll_loop(run_ai, tag):
	"""The model starts a ~2 min background job, then calls check_background_jobs() with no
	wait, again and again, until the job is reported done (or POLL_CAP polls). Returns
	(run, poll_count, poll_timestamps relative to the first poll)."""
	done_marker = 'poll-job-42'  # the output only: the command (echoed in tool results) formats it

	def poll(req):
		last = (req.tool_messages() or [{}])[-1]
		if (last.get('tool_call_id') or '').startswith('poll') and done_marker in (last.get('content') or ''):
			return say('The background job finished.')
		return tools(call('check_background_jobs', id=f'poll{req.index}'))

	run = run_ai(tag, [
		tools(call('run_shell', id='bg', command=f"sleep {POLL_JOB_S}; printf 'poll-job-%s\\n' 42",
		           timeout=POLL_JOB_S + 60, description='Long background job', background=True)),
		*[poll] * POLL_CAP,
		tools(call('cancel_background_job', id='cancel', job_id='bg-1')),
		say('Stopped polling.'),
	], max_iterations=POLL_CAP + 10)
	polls = [r for r in run.requests[1:] if r.tool_messages() and
	         (r.tool_messages()[-1].get('tool_call_id') or '').startswith('poll')]
	t0 = polls[0].t if polls else 0
	return run, len(polls), [round(r.t - t0, 1) for r in polls]


@pytest.fixture(scope='module')
def poll_loop_result():
	return {}


@pytest.fixture
def poll_loop(run_ai, poll_loop_result, record_property):
	"""One poll-loop run shared by the tests below (it lasts up to ~2 min)."""
	if 'run' not in poll_loop_result:
		run, count, stamps = _poll_loop(run_ai, 'bg_poll_loop')
		poll_loop_result.update(run=run, count=count, stamps=stamps)
		print(f'\n[poll loop] {count} check_background_jobs() turns, at t+{stamps[:8]}...{stamps[-3:]}s')
	record_property('poll_turns', poll_loop_result['count'])
	record_property('poll_timestamps', poll_loop_result['stamps'])
	return poll_loop_result


@pytest.mark.slow
def test_model_polling_in_a_loop_current_behaviour(poll_loop):
	"""Current behaviour: each wait-less check returns at once, so the model burns a turn per
	poll - it hits the POLL_CAP before the ~2 min job ends (each turn is a model call + tokens)."""
	assert poll_loop['count'] >= 50, poll_loop['count']
	assert poll_loop['stamps'][-1] < POLL_JOB_S, 'the polls were spread over the whole job'


# The poll-loop job emits these events the model can be woken for: started, finished.
POLL_JOB_EVENTS = 2


@pytest.mark.slow
@pytest.mark.xfail(strict=True, reason='event-driven wake, 1.0')
@pytest.mark.parametrize('job_events', [POLL_JOB_EVENTS])
def test_model_polling_in_a_loop_costs_a_turn_per_job_event(poll_loop, job_events):
	"""Event-driven background jobs: a wait-less check_background_jobs() blocks until a job event
	(a job finishing, or a user message), so a polling loop over a ~2 min job costs at most one
	turn per job event - and the model still sees the job finish."""
	run = poll_loop['run']
	assert poll_loop['count'] <= job_events, (poll_loop['count'], poll_loop['stamps'])
	assert 'poll-job-42' in run.requests[-1].text()

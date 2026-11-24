"""D. Several tool calls in one turn (no background): they run in parallel, each gets its result."""
from tests.integration.ai.conftest import FINAL_STATUSES
from tests.integration.ai.scripted import call, say, tools


def test_batch_runs_in_parallel(run_ai, lab):
	run = run_ai('conc_parallel', [
		tools(
			call('run_task', id='t1', name='httpx', targets=[f'{lab.url}/slow?s=4'], description='Slow 1'),
			call('run_task', id='t2', name='httpx', targets=[f'{lab.url2}/slow?s=4'], description='Slow 2'),
			call('run_shell', id='sh', command='sleep 4; echo slept', description='Sleep'),
		),
		say('done'),
	])
	gap = run.requests[1].t - run.requests[0].t
	assert 4 <= gap < 11, f'batch took {gap:.1f}s: the 3 calls of ~4s did not run in parallel (sequential: 12s+)'
	nxt = run.requests[1]
	titles = {r['title'] for k in ('t1', 't2') for r in nxt.tool_json(k)['results'] if r.get('_type') == 'url'}
	assert titles == {'Slow 4.0'}
	assert len([1 for k in ('t1', 't2') for r in nxt.tool_json(k)['results'] if r.get('_type') == 'url']) == 2
	assert 'slept' in nxt.tool_result('sh')
	assert {c['status'] for c in run.children()} <= set(FINAL_STATUSES)
	assert len(run.children()) == 3


def test_batch_with_a_failing_call(run_ai, lab):
	run = run_ai('conc_mixed', [
		tools(
			call('run_task', id='bad', name='nosuchtask', targets=[lab.url], description='Bad'),
			call('run_shell', id='fail', command='echo nope; exit 1', description='Fails'),
			call('run_task', id='good', name='httpx', targets=[lab.url], description='Good'),
			call('run_shell', id='ok', command='echo ok', description='Ok'),
		),
		say('done'),
	])
	nxt = run.requests[1]
	assert "Task 'nosuchtask' not found" in nxt.tool_result('bad')
	assert 'return code 1' in nxt.tool_result('fail')
	assert any(r.get('_type') == 'url' for r in nxt.tool_json('good')['results'])
	assert 'ok' in nxt.tool_json('ok')['results'][0]['content']
	# one tool result per call, in a single follow-up request
	assert sorted(m['tool_call_id'] for m in nxt.tool_messages()) == ['bad', 'fail', 'good', 'ok']

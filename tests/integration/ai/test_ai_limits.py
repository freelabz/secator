"""C. Timeouts and limits: task / shell timeouts, the iteration cap, usage accounting, compaction."""
import pytest

from tests.integration.ai.conftest import FINAL_STATUSES
from tests.integration.ai.scripted import Turn, call, say, tools


def test_task_longer_than_its_timeout(run_ai, lab, monkeypatch):
	from secator.config import CONFIG
	monkeypatch.setitem(CONFIG.tasks.overrides, 'httpx', {'max_timeout': 2, 'monitor_poll_interval': 0.5})
	run = run_ai('limit_task_timeout', [
		tools(call('run_task', id='slow', name='httpx', targets=[f'{lab.url}/slow?s=12'], description='Slow page')),
		tools(call('run_shell', id='next', command='echo next', description='Carry on')),
		say('done'),
	])
	gap = run.requests[1].t - run.requests[0].t
	assert gap < 10, f'the task was not stopped at its timeout ({gap:.1f}s)'
	assert 'Task timeout 2s exceeded' in run.tool_result('slow')
	assert 'next' in run.tool_result('next')  # the run carried on
	children = run.children('httpx')
	assert children and all(c['status'] in FINAL_STATUSES for c in children), children


def test_shell_timeout(run_ai, monkeypatch):
	from secator.config import CONFIG
	monkeypatch.setattr(CONFIG.security, 'shell_default_timeout', 2)
	run = run_ai('limit_shell_timeout', [
		tools(call('run_shell', id='sh', command='echo begin; sleep 20; echo never', description='Hangs')),
		tools(call('run_shell', id='next', command='echo next', description='Carry on')),
		say('done'),
	])
	gap = run.requests[1].t - run.requests[0].t
	assert gap < 10, f'the command was not killed at its timeout ({gap:.1f}s)'
	output = run.tool_json('sh')['results'][0]['content']
	assert 'begin' in output and 'never' not in output
	assert 'timed out after 2s' in output and 'higher `timeout`' in output
	assert 'next' in run.tool_result('next')


def test_max_iterations_reached(run_ai):
	"""A model that never stops is cut at max_iterations; the run ends cleanly."""
	cap = 6  # above the scan-mode floor (5)
	run = run_ai('limit_max_iter', [
		tools(call('run_shell', id=f'it{i}', command=f'echo it{i}', description='Loop')) for i in range(cap)
	], max_iterations=cap)
	assert len(run.requests) == cap
	assert run.status == 'SUCCESS'
	# each continue prompt tells the model where it stands
	assert f'"iteration":{cap - 1},"max":{cap}' in run.requests[-1].text()
	# the last call ran (its output is in the run), but no request followed it
	assert any('it5' in str(a.toDict()) for a in run.ai('shell_output')), 'the last call did not run'


def test_usage_and_cost_are_accounted(run_ai):
	"""Every model call's tokens and cost land on the run context.

	There is no cost/token budget cap in core today: a run keeps going whatever it spent
	(flagged as unsupported in the PR)."""
	turns = [Turn(calls=[call('run_shell', command='echo x', description='x')], prompt_tokens=10_000,
	              completion_tokens=500, cost=2.5) for _ in range(3)] + [say('done', cost=2.5)]
	run = run_ai('limit_usage', turns)
	ctx = run.task.context
	assert ctx['ai_tokens'] == 3 * 10_500 + 1000 + 50
	assert ctx['ai_prompt_tokens'] == 3 * 10_000 + 1000
	assert ctx['ai_cost'] == pytest.approx(10.0)
	responses = run.ai('response')
	assert [r.extra_data['cost'] for r in responses] == [2.5] * 4


def test_context_compaction(run_ai, monkeypatch):
	"""A long history is summarized by a side call once it nears the context window."""
	from secator.config import CONFIG
	from secator.ai.history import OUTPUT_TOKEN_RESERVATION, COMPACTION_THRESHOLD_PCT

	def shrink_window(req):
		# Size the window off the real prompt: ~3k tokens of headroom before compaction.
		import litellm
		used = litellm.token_counter(model='gpt-4o-mini', messages=req.messages)
		monkeypatch.setattr(CONFIG.addons.ai, 'context_window',
		                    OUTPUT_TOKEN_RESERVATION + int((used + 3000) * 100 / COMPACTION_THRESHOLD_PCT))
		return tools(call('run_shell', id='big0', command='seq 1 1500', description='Big output'))

	turns = [shrink_window] + [
		tools(call('run_shell', id=f'big{i}', command='seq 1 1500', description='Big output')) for i in range(1, 6)
	] + [say('done')]
	run = run_ai('limit_compaction', turns, model='openai/scripted-e2e-model', check_log=True)
	assert run.ai('chat_compacted'), 'history was never compacted'
	summarize_calls = [r for r in run.side_requests if 'summar' in r.text().lower()]
	assert summarize_calls, 'no summarization call reached the model'
	after = run.requests[-1]
	assert any('Summary' in str(m.get('content')) for m in after.messages), 'summary not in the history sent'
	assert len(after.messages) < 2 + 2 * len(run.requests)

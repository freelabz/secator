"""F. Subagents (foreground): their own tool calls and the handback.

A subagent is a nested ai run on the same scripted model: its objective carries its own
``[scenario:<tag>]`` marker, so it gets its own script.
"""
from tests.integration.ai.scripted import call, say, tools


def _spawn(child_tag, call_id='sub', **kw):
	return call('run_subagent', id=call_id, objective=f'[scenario:{child_tag}] Check the lab home page.',
	            description='Subagent', **kw)


def test_foreground_subagent(run_ai, model):
	model.script([
		tools(call('run_shell', id='child_sh', command='echo child-work', description='Child work')),
		say('Lab home checked: nothing to report.'),
	], tag='sub_fg.child')
	run = run_ai('sub_fg', [
		tools(_spawn('sub_fg.child', background=False)),
		say('done'),
	])
	handback = run.tool_result('sub')
	assert 'Lab home checked: nothing to report.' in handback
	assert '[subagent handback]' in handback and 'Persisted: NOTHING' in handback
	child = model.for_tag('sub_fg.child')
	assert len(child) == 2
	assert 'child-work' in child[1].tool_result('child_sh')
	assert 'sub_fg.child' not in model.overruns
	# the child's turns ended before the parent's next request
	assert child[-1].t < run.requests[1].t

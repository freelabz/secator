"""B. Bad input from the model: every malformed call gets a clear error back and the run goes on.

Each scenario sends one bad call, then a good ``run_shell`` call: the model must receive an
explanatory tool result for the bad call AND the good call must still run (the loop survived).
"""
import pytest

from tests.integration.ai.conftest import FINAL_STATUSES
from tests.integration.ai.scripted import Turn, call, raw_call, say, tools


def _then_good(bad):
	return [
		Turn(calls=[bad]),
		tools(call('run_shell', id='good', command='echo still-alive', description='Prove the loop survived')),
		say('done'),
	]


# (bad call, substring of the error the model must receive)
BAD_CALLS = {
	'unknown_task': (lambda lab: call('run_task', id='bad', name='nosuchtask', targets=[lab.url], description='x'),
	                 "Task 'nosuchtask' not found"),
	'workflow_called_as_task': (lambda lab: call('run_task', id='bad', name='url_crawl', targets=[lab.url],
	                                             description='x'),
	                            'IS a workflow'),
	'unknown_workflow': (lambda lab: call('run_workflow', id='bad', name='nosuchwf', targets=[lab.url], description='x'),
	                     "Workflow 'nosuchwf' not found"),
	'option_wrong_type': (lambda lab: call('run_task', id='bad', name='httpx', targets=[lab.url],
	                                       opts={'threads': 'many'}, description='x'),
	                      'invalid value'),
	'malformed_json': (lambda lab: raw_call('run_shell', '{"command": "echo hi"', id='bad'),
	                   'malformed JSON arguments'),
	'empty_payload': (lambda lab: raw_call('run_shell', '', id='bad'),
	                  'malformed JSON arguments'),
	'empty_object': (lambda lab: raw_call('run_task', '{}', id='bad'),
	                 'empty arguments'),
	'missing_command': (lambda lab: call('run_shell', id='bad', description='no command'),
	                    'Empty command'),
	'empty_targets': (lambda lab: call('run_task', id='bad', name='httpx', targets=[], description='x'),
	                  'Input is empty'),
	'unknown_tool': (lambda lab: call('frobnicate', id='bad', x=1),
	                 "unknown tool 'frobnicate'"),
	'query_not_an_object': (lambda lab: call('query_workspace', id='bad', query='not a dict', description='x'),
	                        'query must be a JSON object'),
	'ai_as_task': (lambda lab: call('run_task', id='bad', name='ai', targets=[lab.url], description='x'),
	               'use the run_subagent tool'),
}


@pytest.mark.parametrize('case', list(BAD_CALLS))
def test_bad_call_is_reported_and_run_continues(run_ai, lab, case):
	make_bad, expected = BAD_CALLS[case]
	run = run_ai(f'bad_{case}', _then_good(make_bad(lab)))
	assert expected in run.tool_result('bad')
	# the loop survived: the next call ran and the model was told its output
	assert 'still-alive' in run.tool_result('good')
	assert len(run.requests) == 3
	assert run.status in FINAL_STATUSES


def test_unknown_option_is_ignored(run_ai, lab):
	"""Current behaviour: an option the task does not have is dropped silently, the task runs.

	The model is not told the option was ignored (flagged in the PR: a warning would help)."""
	run = run_ai('bad_unknown_option', [
		tools(call('run_task', id='t', name='httpx', targets=[lab.url], opts={'nosuchopt': 1}, description='x')),
		say('done'),
	])
	data = run.tool_json('t')
	assert data['status'] == 'success'
	assert any(r.get('_type') == 'url' for r in data['results'])


@pytest.mark.parametrize('args', [
	{'name': 'httpx', 'targets': '{url}', 'description': 'targets as a string'},
	{'name': 'httpx', 'targets': '["{url}"]', 'description': 'targets as a JSON string'},
], ids=['string', 'json_string'])
def test_stringified_targets_are_coerced(run_ai, lab, args):
	args = {k: v.replace('{url}', lab.url) for k, v in args.items()}
	run = run_ai(f'bad_targets_{args["description"][-6:]}', [
		tools(call('run_task', id='t', **args)),
		say('done'),
	])
	urls = [r['url'] for r in run.tool_json('t')['results'] if r.get('_type') == 'url']
	assert urls == [lab.url]


def test_text_tool_call_is_dispatched(run_ai):
	"""A tool call written as text (<tool_call> block) by the model runs like a native one."""
	run = run_ai('bad_text_call', [
		Turn(content='<tool_call>{"name": "run_shell", "arguments": '
		             '{"command": "echo from-text", "description": "x"}}</tool_call>'),
		say('done'),
	])
	assert 'from-text' in run.tool_result('textcall_0_run_shell')


def test_parallel_mix_of_bad_and_good_calls(run_ai, lab):
	"""One turn with a malformed call, an unknown tool and a good call: each gets its own result."""
	run = run_ai('bad_mixed_batch', [
		tools(
			raw_call('run_shell', '{"command": ', id='bad_json'),
			call('frobnicate', id='bad_tool', x=1),
			call('run_shell', id='good', command='echo fine', description='ok'),
		),
		say('done'),
	])
	nxt = run.requests[1]
	assert 'malformed JSON' in nxt.tool_result('bad_json')
	assert 'unknown tool' in nxt.tool_result('bad_tool')
	assert 'fine' in nxt.tool_result('good')


@pytest.mark.xfail(strict=True, reason=(
	'bug: list_runners() with no arguments (all of them are optional) is rejected as "empty '
	'arguments": tool_call_to_action only exempts stop and check_background_jobs'))
def test_tool_with_only_optional_args_accepts_no_args(run_ai):
	run = run_ai('bad_list_runners_noargs', [
		tools(call('list_runners', id='lr')),
		say('done'),
	])
	assert 'rejected' not in run.tool_result('lr')


@pytest.mark.xfail(strict=True, reason=(
	'bug: the rejection reason is picked from the arguments alone ("empty arguments" if they are '
	'empty, else "unknown tool"): a known tool sent non-object JSON (an array) is told "unknown '
	'tool \'run_shell\'", and an unknown tool sent no arguments is told "empty arguments"'))
@pytest.mark.parametrize('bad,wrong', [
	(lambda: raw_call('run_shell', '["echo", "hi"]', id='bad'), 'unknown tool'),
	(lambda: call('frobnicate', id='bad'), 'empty arguments'),
], ids=['array_args', 'unknown_tool_no_args'])
def test_rejection_reason_names_the_real_problem(run_ai, bad, wrong):
	run = run_ai(f'bad_reason_{wrong[:5]}', _then_good(bad()))
	assert wrong not in run.tool_result('bad')

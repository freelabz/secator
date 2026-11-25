"""A. Basic tools: each built-in tool family driven end to end by a scripted model.

Every scenario checks what the model was told (the tool result of its call), what the run
persisted (json driver), the child runners' final statuses, and that the run itself ended
cleanly.
"""
import json
from pathlib import Path

import pytest

from tests.integration.ai.conftest import FINAL_STATUSES, install_workflow
from tests.integration.ai.scripted import call, say, tools


def _result_items(run, call_id):
	data = run.tool_json(call_id)
	assert isinstance(data, dict), f'tool result is not JSON: {data!r}'
	return data


def test_httpx_task(run_ai, lab):
	run = run_ai('basic_httpx', [
		tools(call('run_task', id='httpx1', name='httpx', targets=[lab.url], description='Probe the lab')),
		say('The lab answers 200.'),
	])
	assert run.status == 'SUCCESS'
	data = _result_items(run, 'httpx1')
	assert data['status'] == 'success'
	urls = [r for r in data['results'] if r.get('_type') == 'url']
	assert [(u['url'], u['status_code'], u['title']) for u in urls] == [(lab.url, 200, 'Lab home')]
	# the model got the result on its very next request
	assert run.requests[1].tool_result('httpx1') is not None
	# persisted in the run's store
	assert [u['url'] for u in run.stored('url')] == [lab.url]
	children = run.children('httpx')
	assert children and all(c['status'] in FINAL_STATUSES for c in children), children


@pytest.mark.parametrize('command,expect,status', [
	('echo start; sleep 5; echo end', ['start', 'end'], 'SUCCESS'),
	('echo boom; exit 3', ['boom', 'return code 3'], 'FAILURE'),
], ids=['sleep5', 'exit3'])
def test_shell(run_ai, command, expect, status):
	run = run_ai(f'basic_shell_{status}', [
		tools(call('run_shell', id='sh1', command=command, description='Run a command')),
		say('ok'),
	])
	assert run.status == 'SUCCESS'
	output = _result_items(run, 'sh1')['results'][0]['content']
	for text in expect:
		assert text in output
	if 'sleep 5' in command:
		gap = run.requests[1].t - run.requests[0].t
		assert 5 <= gap < 25, f'sleep 5 took {gap:.1f}s'
	children = run.children('command')
	assert [c['status'] for c in children] == [status]


@pytest.mark.xfail(strict=True, reason=(
	'bug: a failed run_shell command hands the model its console error line with ANSI colour '
	'codes ("\\x1b[1;31mERR\\x1b[0m ...") appended to the command output'))
def test_shell_output_has_no_terminal_escapes(run_ai):
	"""The model reads plain text: no ANSI colour codes in a failed command's output."""
	run = run_ai('basic_shell_ansi', [
		tools(call('run_shell', id='sh1', command='echo boom; exit 3', description='Fail')),
		say('ok'),
	])
	output = run.tool_json('sh1')['results'][0]['content']
	assert 'boom' in output
	assert '\x1b[' not in output


WORKFLOW = """type: workflow
name: ai_e2e_probe
description: Probe local URLs
input_types:
  - url
tasks:
  httpx:
    description: Probe URLs
"""


def test_workflow(run_ai, lab):
	install_workflow('ai_e2e_probe', WORKFLOW)
	run = run_ai('basic_workflow', [
		tools(call('run_workflow', id='wf1', name='ai_e2e_probe', targets=[lab.url, lab.url2], description='Probe')),
		say('done'),
	])
	assert run.status == 'SUCCESS'
	data = _result_items(run, 'wf1')
	urls = sorted(r['url'] for r in data['results'] if r.get('_type') == 'url')
	assert urls == sorted([lab.url, lab.url2])
	workflows = run.children('ai_e2e_probe')
	assert workflows and {c['status'] for c in workflows} <= set(FINAL_STATUSES), workflows


def test_query_workspace(run_ai, lab):
	url = f'{lab.url2}/login'  # only this test probes it: the workspace is shared by the session
	run = run_ai('basic_query', [
		tools(call('run_task', id='httpx1', name='httpx', targets=[url], description='Probe')),
		tools(call('query_workspace', id='q1', query={'_type': 'url', 'url': url}, description='Read back')),
		say('done'),
	])
	data = _result_items(run, 'q1')
	assert data['status'] == 'success'
	assert [(r['url'], r['title']) for r in data['results']] == [(url, 'Lab login')]
	assert all(r.get('_uuid') for r in data['results'])  # the handle mark_vuln_* needs


@pytest.mark.xfail(strict=True, reason=(
	'bug: a query_workspace call that matches nothing is answered with a bare '
	'{"status":"acknowledged"} (the result-less tool ack), so the model cannot tell "no match" '
	'from "the tool returned nothing"'))
def test_query_workspace_no_match(run_ai):
	run = run_ai('basic_query_none', [
		tools(call('query_workspace', id='q1', query={'_type': 'url', 'url': 'http://127.0.0.1:1/none'},
		           description='Nothing there')),
		say('done'),
	])
	data = run.tool_json('q1')
	assert data.get('count') == 0, data


def _notes():
	from secator.config import CONFIG
	return [json.loads(line) for path in Path(CONFIG.dirs.reports).glob('**/notes.ndjson')
	        for line in path.read_text().splitlines() if line.strip()]


def _vuln_uuid(req):
	"""Pick the vulnerability _uuid out of the last query_workspace result."""
	for m in reversed(req.tool_messages()):
		data = req.tool_json(m['tool_call_id'])
		if isinstance(data, dict) and data.get('task') == 'query_workspace':
			for r in data.get('results', []):
				if r.get('_type') == 'vulnerability':
					return r['_uuid']
	raise AssertionError('no vulnerability in the query result')


MARKS = {
	'false_positive': (lambda u: call('mark_vuln_false_positive', id='mark', _uuid=u, reason='Not reproducible'),
	                   lambda v: v.get('is_false_positive') is True),
	'exploited': (lambda u: call('mark_vuln_exploited', id='mark', _uuid=u, poc='curl /admin -> 200 with bypass',
	                             impact='admin access', remediation='fix acl'),
	              lambda v: v.get('status', '').upper() == 'EXPLOITED'),
	'exploit_failed': (lambda u: call('mark_vuln_exploit_failed', id='mark', _uuid=u, verdict='inconclusive',
	                                  reason='bypass did not work'),
	                   lambda v: ((v.get('extra_data') or {}).get('exploit_failed_reason') == 'bypass did not work'
	                              and (v['extra_data'].get('exploit_attempts') or {}).get('failed') == 1)),
	# a note goes to the workspace notes store (keyed by the finding's identity), never on the finding
	'note': (lambda u: call('add_note', id='mark', _uuid=u, body='Checked by hand.'),
	         lambda v: any(n.get('body') == 'Checked by hand.' and n.get('target_type') == 'vulnerability'
	                       and v['name'] in json.dumps(n.get('target_key')) for n in _notes())),
}


@pytest.mark.parametrize('mark', list(MARKS))
def test_finding_management(run_ai, lab, mark):
	make_call, check = MARKS[mark]
	url = f'{lab.url}/admin?case={mark}'  # unique per case: the workspace is shared by the session
	run = run_ai(f'basic_mark_{mark}', [
		tools(call('add_finding', id='add', _type='vulnerability',
		           fields={'name': f'Forbidden bypass {mark}', 'matched_at': url, 'severity': 'medium'})),
		tools(call('query_workspace', id='q1', description='Find it',
		           query={'_type': 'vulnerability', 'matched_at': url, 'name': f'Forbidden bypass {mark}'})),
		lambda req: tools(make_call(_vuln_uuid(req))),
		say('done'),
	])
	assert run.status == 'SUCCESS'
	assert _result_items(run, 'add')['status'] == 'success'
	result = run.tool_result('mark')
	assert '"status":"error"' not in result, result
	vulns = [v for v in run.stored('vulnerability') if v.get('matched_at') == url]
	assert len(vulns) == 1, vulns
	assert check(vulns[0]), vulns[0]

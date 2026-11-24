"""I. Lifecycle: start-hook errors, every store driver (json / mongodb / sqlite), session resume."""
import pytest

from tests.integration.ai.conftest import FINAL_STATUSES, WORKSPACE, driver_context, store_for
from tests.integration.ai.scripted import call, say, tools


def test_start_hook_error_is_surfaced(run_ai, model):
	"""#1707: a driver hook failing when the run starts is reported, and the model is never called."""
	from secator.tasks.ai import ai

	def broken_driver(self):
		raise RuntimeError('store unreachable at start')

	run = run_ai('life_start_hook', [say('never')], hooks={ai: {'on_start': [broken_driver]}}, check_log=False)
	errors = run.of_type('error')
	assert any('broken_driver' in e.message and 'store unreachable at start' in (e.traceback or '')
	           for e in errors), [(e.message, e.traceback) for e in errors]
	assert run.status == 'FAILURE'
	assert model.for_tag('life_start_hook') == []
	model.script([], tag='life_start_hook')  # the unused turn is expected


def _runner_doc(store, runner_id):
	"""A runner's persisted doc, through the backend's runner listing (every driver has one)."""
	for doc in store.list_runners(workspace_id=WORKSPACE, runner_type='task') or []:
		ctx = doc.get('context') or {}
		if runner_id in (doc.get('_id'), ctx.get('task_chunk_id'), ctx.get('task_id')):
			return doc
	return None


def test_drivers_persist_runs_and_findings(run_ai, lab, driver):
	"""The same scenario on each store driver: runner docs (final status, #1729 last_updated_db
	stamp) and findings are persisted, and query_workspace reads them back through the driver."""
	tag = f'life_driver_{driver}'
	url = f'{lab.url}/login'
	ctx = driver_context(driver, session_id=f'sess-{tag}')
	run = run_ai(tag, [
		tools(call('run_task', id='t', name='httpx', targets=[url], description='Probe'),
		      call('run_shell', id='sh', command='echo drv', description='Shell')),
		tools(call('add_finding', id='add', _type='vulnerability',
		           fields={'name': f'Login exposed {driver}', 'matched_at': url, 'severity': 'low'})),
		tools(call('query_workspace', id='q', query={'_type': 'vulnerability', 'matched_at': url,
		                                             'name': f'Login exposed {driver}'}, description='Read')),
		say('done'),
	], context=ctx)
	assert run.status == 'SUCCESS', run.errors()
	assert run.task.context['drivers'] == [driver]
	store = store_for(run.task.context)
	# the ai run's own doc
	ai_doc = _runner_doc(store, run.task.id)
	assert ai_doc and ai_doc.get('status') in FINAL_STATUSES, ai_doc
	# child runners: final status + last_updated_db stamped
	runners = [a.extra_data for a in run.ai() if a.ai_type in ('task', 'shell') and a.extra_data.get('runner_id')]
	assert len(runners) == 2, runners
	for r in runners:
		# json: the listing may pick the stale inner report (test_json_child_reports_are_final)
		doc = (next((c for c in run.children() if r['runner_id'] in (c['context'].get('task_chunk_id'),
		                                                             c['context'].get('task_id'))), None)
		       if driver == 'json' else _runner_doc(store, r['runner_id']))
		assert doc, f'{driver}: no runner doc for {r}'
		assert doc.get('status') in FINAL_STATUSES, doc.get('status')
		assert doc.get('last_updated_db'), f'{driver}: last_updated_db not stamped'
	# findings
	urls = store.search({'_type': 'url', 'url': url, '_context.session_id': ctx['session_id']})
	assert [u['url'] for u in urls] == [url]
	vulns = run.tool_json('q')['results']
	assert [v['name'] for v in vulns] == [f'Login exposed {driver}']
	assert run.task.last_updated_db


def test_resume_a_stopped_chat(run_ai, mongo, remote):
	"""A chat that ended (no answer) is resumed by a new message in the same session: the next
	run restores the whole conversation, tool calls and results included."""
	tag = 'life_resume'
	ctx = driver_context('mongodb', session_id=f'sess-{tag}')
	remote.set_timeout(1)
	run_ai(tag, [
		tools(call('run_shell', id='first', command='echo first-run-output', description='First')),
		say('First run finished.'),
	], interactive='remote', context=ctx)
	run2 = run_ai(tag, [say('Second run reply.')], interactive='remote', context=ctx,
	              prompt='and now the follow-up question')
	first = run2.requests[0]
	assert 'first-run-output' in (first.tool_result('first') or ''), 'tool result not restored'
	assert 'First run finished.' in first.text()
	assert 'and now the follow-up question' in first.last_user()
	# a valid transcript: every tool call is answered
	calls = {tc['id'] for m in first.messages for tc in m.get('tool_calls') or []}
	assert calls == {m['tool_call_id'] for m in first.tool_messages()}


@pytest.mark.xfail(strict=True, reason=(
	'bug (json driver): a sync child task run by the ai task leaves a second report file '
	'(report_<task>.json, its inner runner) at status RUNNING with the same task_chunk_id as the '
	'finished task\'s report.json, so a reader of the runner reports (by task id) can see a '
	'finished task as RUNNING, depending on file order'))
def test_json_child_reports_are_final(run_ai, lab):
	ctx = driver_context('json', session_id='sess-life-json-final')
	run = run_ai('life_json_final', [
		tools(call('run_task', id='t', name='httpx', targets=[lab.url], description='Probe')),
		say('done'),
	], context=ctx)
	import glob
	import json
	from pathlib import Path
	[card] = [a.extra_data for a in run.ai('task')]
	statuses = {}
	for path in glob.glob(str(Path(run.children()[0]['_path']).parent / 'report*.json')):
		info = json.loads(Path(path).read_text())['info']
		if card['runner_id'] in ((info.get('context') or {}).get('task_chunk_id'),):
			statuses[Path(path).name] = info['status']
	assert len(statuses) >= 1
	assert set(statuses.values()) <= set(FINAL_STATUSES), statuses

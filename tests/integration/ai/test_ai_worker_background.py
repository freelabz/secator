"""H'. Background jobs in a real Celery worker: detached (fire-and-forget) dispatched jobs,
background chunked tasks and their cancellation, background subagents. Same workers and
harness as test_ai_worker.py."""
import pytest

from tests.integration.ai.conftest import FINAL_STATUSES
from tests.integration.ai import test_ai_worker as harness

pytestmark = [pytest.mark.worker, pytest.mark.slow, pytest.mark.ai_timeout(420)]

# the worker fixtures (module-scoped: this module starts its own workers, per pool)
broker, workers, wrun = harness.broker, harness.workers, harness.wrun


def test_background_jobs_in_worker(wrun, lab):
	"""A detached (fire-and-forget) dispatched workflow and a chunked task in the background, a
	foreground call in the same turn; results read later through the store."""
	run = wrun('background')
	assert run.status == 'SUCCESS', run.summary
	r0, r1 = run.requests[:2]
	assert r1.t - r0.t < 10, 'background calls blocked the turn'
	assert 'fg-while-bg' in r1.tool_result('fg')
	assert 'Started background job bg-1' in r1.tool_result('bg_wf')
	assert 'Started background job bg-2' in r1.tool_result('bg_chunked')
	text = run.tool_result('chk1') + run.tool_result('chk2')
	assert text.count('Slow 2.0') >= 3, text  # the workflow's URL + the 2 chunks' URLs
	assert '"detached":true' in text.replace(' ', ''), 'the workflow job did not take the fire-and-forget path'
	statuses = [c['status'] for c in run.children()]
	assert statuses and set(statuses) <= set(FINAL_STATUSES), statuses


def test_cancel_background_chunked_task(wrun):
	run = wrun('cancel_chunked', check_logs=False, shared=True)
	run.assert_clean_logs(allow_chord_errors=True)
	assert '"status":"cancelled"' in run.tool_result('cancel').replace(' ', '')
	assert run.summary['wall'] < 60, 'the cancelled chunks kept the run alive'


def test_background_subagent_in_worker(wrun):
	"""A background subagent's own calls (incl. a dispatched chunked task) are foreground for it."""
	run = wrun('subagent_bg')
	assert run.status == 'SUCCESS', run.summary
	assert 'Started background job bg-1' in run.tool_result('sub')
	child = run.child_requests('child')
	assert len(child) == 2, [r.tag for r in run.all_requests]
	assert 'bg-child-own-call' in child[1].tool_result('c_sh')
	chunked = child[1].tool_result('c_chunked')
	assert 'Started background job' not in chunked and 'Lab home' in chunked
	assert 'Bg child verdict: done.' in run.tool_result('chk')

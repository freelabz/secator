"""Scheduled runs and the per-driver claim / heartbeat / complete interface (secator.schedule)."""
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from secator import schedule as sched
from secator.schedule import LEASE_TTL, LeaseLost, LocalBackend, SqliteBackend, make_schedule, next_run


def ts(*args):
	return datetime(*args, tzinfo=timezone.utc).timestamp()


T0 = ts(2026, 10, 7, 10, 17)


def _mongo_backend(tmp_path):
	mongomock = pytest.importorskip('mongomock')
	return sched.MongodbBackend(collection=mongomock.MongoClient().main.runner_schedules)


BACKENDS = {
	'local': lambda tmp_path: LocalBackend(path=tmp_path / 'schedules.json'),
	'sqlite': lambda tmp_path: SqliteBackend(db_path=tmp_path / 'secator.db'),
	'mongodb': _mongo_backend,
}


@pytest.fixture(params=sorted(BACKENDS))
def backend(request, tmp_path):
	return BACKENDS[request.param](tmp_path)


def _add(backend, cron='*/15 * * * *', agent=None, now=T0):
	s = make_schedule({'name': 'host_recon', 'type': 'workflow'}, ['10.0.0.1'], {}, {'drivers': []}, cron, agent=agent, now=now)  # noqa: E501
	backend.add_schedule(s)
	return s


def _get(backend, schedule_id):
	return next(s for s in backend.list_schedules() if s['id'] == schedule_id)


# ---- cron ----

def test_next_run():
	assert next_run('*/15 * * * *', T0) == ts(2026, 10, 7, 10, 30)
	assert next_run('*/15 * * * *', ts(2026, 10, 7, 10, 30)) == ts(2026, 10, 7, 10, 45)  # strictly after
	assert next_run('0 3 * * 1', T0) == ts(2026, 10, 12, 3, 0)
	assert next_run('0 0 29 2 *', T0) == ts(2028, 2, 29, 0, 0)
	with pytest.raises(ValueError):
		next_run('0 3 * *', T0)


def test_make_schedule_single_string_target():
	s = make_schedule({'name': 'httpx', 'type': 'task'}, 'http://10.0.0.1:8080/', {}, {}, '0 3 * * *', now=T0)
	assert s['spec']['targets'] == ['http://10.0.0.1:8080/']
	assert s['next_run'] == ts(2026, 10, 8, 3, 0) and s['agent'] is None


# ---- per-driver rules ----

def test_not_due_is_not_claimed(backend):
	_add(backend)
	assert backend.claim('a1', now=T0 + 60) is None


def test_claim_fires_once_between_two_agents(backend):
	s = _add(backend)
	due = s['next_run'] + 1
	job1 = backend.claim('a1', now=due)
	job2 = backend.claim('a2', now=due)
	assert job1 and job1['job_id'] == s['id'] and job1['spec']['targets'] == ['10.0.0.1']
	assert job2 is None
	stored = _get(backend, s['id'])
	assert stored['claimed_by'] == 'a1' and stored['last_status'] == 'RUNNING'


def test_concurrent_claims_fire_once(backend, tmp_path):
	if isinstance(backend, sched.MongodbBackend):
		pytest.skip('mongomock is not thread-safe; the compare-and-set path is covered above')
	s = _add(backend)
	due = s['next_run'] + 1
	results = []
	# Separate backend instances (separate file handles / connections), as separate agent processes would have.
	others = [type(backend)(**({'path': backend.path} if isinstance(backend, LocalBackend) else {'db_path': tmp_path / 'secator.db'})) for _ in range(8)]  # noqa: E501
	threads = [threading.Thread(target=lambda b=b: results.append(b.claim('a', now=due))) for b in others]
	for t in threads:
		t.start()
	for t in threads:
		t.join()
	assert len([r for r in results if r]) == 1


def test_mongodb_claim_is_compare_and_set(tmp_path):
	"""Two agents read the same due schedule; only the first compare-and-set wins."""
	b = _mongo_backend(tmp_path)
	s = _add(b)
	due = s['next_run'] + 1
	stale = list(b.col.find({}))  # agent 2's read, taken before agent 1's claim lands

	class Cursor(list):
		def sort(self, *a, **k):
			return self

	assert b.claim('a1', now=due)
	real_find, first = b.col.find, []

	def find(*args, **kwargs):  # only the claim's candidate read is stale
		if not first:
			first.append(1)
			return Cursor(stale)
		return real_find(*args, **kwargs)

	with patch.object(b.col, 'find', side_effect=find):
		assert b.claim('a2', now=due) is None


def test_missed_fires_roll_forward(backend):
	s = _add(backend)
	late = s['next_run'] + 3 * 3600 + 5  # 12 fires missed
	assert backend.claim('a1', now=late)
	stored = _get(backend, s['id'])
	assert stored['next_run'] == next_run(s['cron'], late) > late  # fired once, rolled forward
	assert backend.claim('a2', now=late + 1) is None  # no catch-up storm


def test_overlap_skips_fires_during_a_run(backend):
	s = _add(backend)
	t = s['next_run'] + 1
	job = backend.claim('a1', now=t)
	# The run outlasts several fire times while heartbeating: never claimed again.
	for k in range(1, 4):
		now = t + k * 900
		backend.heartbeat(job, now=now)
		assert backend.claim('a2', now=now + 1) is None
	end = t + 3 * 900 + 30
	backend.complete(job, 'SUCCESS', exit_code=0, now=end)
	stored = _get(backend, s['id'])
	assert stored['last_status'] == 'SUCCESS' and stored['next_run'] > end  # skipped fires, not queued
	assert backend.claim('a2', now=end + 1) is None


def test_lapsed_lease_is_claimable_and_fences_the_old_run(backend):
	s = _add(backend)
	t = s['next_run'] + 1
	job = backend.claim('a1', now=t)
	later = next_run(s['cron'], t) + LEASE_TTL  # a1 stopped heartbeating
	job2 = backend.claim('a2', now=later)
	assert job2
	with pytest.raises(LeaseLost):
		backend.heartbeat(job, now=later + 1)
	backend.complete(job, 'SUCCESS', now=later + 2)  # stale complete is a no-op
	assert _get(backend, s['id'])['claimed_by'] == 'a2'


def test_agent_label_targeting(backend):
	labelled = _add(backend, agent='dc-paris')
	due = labelled['next_run'] + 1
	assert backend.claim('laptop', now=due) is None
	assert backend.claim('dc-paris', now=due)['job_id'] == labelled['id']
	anyone = _add(backend)
	assert backend.claim('laptop', now=anyone['next_run'] + 1)['job_id'] == anyone['id']


# ---- api backend: protocol mapping ----

def _resp(status=200, body=None):
	r = MagicMock(status_code=status)
	r.json.return_value = body or {}
	return r


def test_api_backend_protocol():
	b = sched.ApiBackend(creds={'url': 'https://server/api/', 'agent_id': 'ag', 'secret': 's3'})
	with patch.object(sched.ApiBackend, 'request', return_value=_resp(204)) as req:
		assert b.claim('ignored') is None
	assert req.call_args.args[:2] == ('POST', 'agent/claim')
	job = {'job_id': 'j1', 'lease_id': 'l1', 'api': {'run_token': 'rt_x'}}
	with patch.object(sched.ApiBackend, 'request', return_value=_resp(200, {'cancel': True})):
		assert b.heartbeat(job) is True
	with patch.object(sched.ApiBackend, 'request', return_value=_resp(409)):
		with pytest.raises(LeaseLost):
			b.heartbeat(job)
	with patch.object(sched.ApiBackend, 'request', return_value=_resp(200)) as req:
		b.complete(job, 'SUCCESS', exit_code=0)
	assert req.call_args.args[:2] == ('POST', 'agent/jobs/j1/complete')
	assert req.call_args.kwargs['json'] == {'lease_id': 'l1', 'exit_code': 0, 'final_status': 'SUCCESS', 'error': None}
	env = b.child_env(job)
	assert env['SECATOR_ADDONS_API_KEY'] == 'rt_x' and env['SECATOR_ADDONS_API_URL'] == 'https://server/api'


def test_api_backend_add_schedule_resolves_site_label():
	b = sched.ApiBackend()
	s = make_schedule({'name': 'httpx', 'type': 'task'}, ['10.0.0.1'], {'rate_limit': 5}, {'workspace_id': 'w1', 'workspace_name': 'ws', 'drivers': ['api']}, '0 3 * * *', agent='dc-paris/agent-1')  # noqa: E501

	def fake(method, endpoint, data=None, **kw):
		return [{'_id': 'site1', 'name': 'dc-paris'}] if endpoint == 'sites' else {'_id': 'sched1'}

	with patch('secator.hooks.api._make_request', side_effect=fake) as req:
		assert b.add_schedule(s) == 'sched1'
	body = req.call_args.args[2]
	assert body['cron'] == '0 3 * * *' and body['frequency'] == 'custom'
	assert body['site_id'] == 'site1' and body['agent_name'] == 'agent-1'
	assert body['context'] == {'workspace_id': 'w1', 'workspace_name': 'ws'}

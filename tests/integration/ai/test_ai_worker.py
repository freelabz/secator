"""H. Worker mode: the ai task runs in a real Celery worker, on each worker pool.

Two workers per pool: the "ai" worker (``-c 1`` on the ``ai`` queue, like the AI pool) runs the
ai task, which runs light children in-process; the "pool" worker serves every other queue for
what it dispatches (workflows, wide/chunked tasks and their chunks). The scripted model lives
in the ai worker (``worker_app.py``), which records its requests to a file read back here.

Broker: a private redis (``$SECATOR_TEST_REDIS_URL``, else a ``redis-server`` binary started on
a free port), or a filesystem broker when redis is unavailable. Nothing shared is touched: the
spawned redis is ours and is shut down at the end; a given ``$SECATOR_TEST_REDIS_URL`` is used
as-is (its own database) and never flushed.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from importlib.util import find_spec
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.integration.ai.conftest import FINAL_STATUSES, LOG_FORBIDDEN, MODEL, children_of, install_workflow
from tests.integration.ai.scripted import load_requests, parse_tool_result
from tests.integration.ai.worker_config import AI_QUEUE, POOL_QUEUES
from tests.integration.ai.worker_scenarios import REVOKE_CHILD_S, WORKFLOW

pytestmark = [pytest.mark.worker, pytest.mark.slow, pytest.mark.ai_timeout(420)]

ROOT = Path(__file__).resolve().parents[3]
# a one-task workflow (built line by line: an indented multi-line string trips flake8's indent check)
WORKFLOW_YAML = '\n'.join([
	'type: workflow',
	f'name: {WORKFLOW}',
	'description: Probe local URLs',
	'input_types:',
	'  - url',
	'tasks:',
	'  httpx:',
	'    description: Probe URLs',
	'',
])

POOLS = ['gevent', 'prefork', 'solo']


def _free_port():
	with socket.socket() as s:
		s.bind(('127.0.0.1', 0))
		return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Broker
# ---------------------------------------------------------------------------

@dataclass
class Broker:
	kind: str
	env: Dict[str, str]
	proc: Any = None


@pytest.fixture(scope='module')
def broker(_ai_dirs):
	data = Path(_ai_dirs) / 'worker-data'
	data.mkdir(exist_ok=True)
	given = os.environ.get('SECATOR_TEST_REDIS_URL')
	has_lib = find_spec('redis') is not None
	if given and has_lib:
		yield Broker('redis', {'SECATOR_CELERY_BROKER_URL': given, 'SECATOR_CELERY_RESULT_BACKEND': given})
		return
	binary = shutil.which('redis-server')
	if binary and has_lib:
		port = _free_port()
		proc = subprocess.Popen(
			[binary, '--port', str(port), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no',
			 '--dir', str(data)],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, start_new_session=True)
		deadline = time.time() + 10
		while time.time() < deadline:
			try:
				socket.create_connection(('127.0.0.1', port), timeout=0.5).close()
				break
			except OSError:
				time.sleep(0.1)
		url = f'redis://127.0.0.1:{port}/0'
		yield Broker('redis', {'SECATOR_CELERY_BROKER_URL': url, 'SECATOR_CELERY_RESULT_BACKEND': url}, proc)
		proc.terminate()
		proc.wait(10)
		return
	if not find_spec('celery'):
		pytest.skip('celery not installed')
	yield Broker('filesystem', {
		'SECATOR_CELERY_BROKER_URL': 'filesystem://',
		'SECATOR_CELERY_RESULT_BACKEND': f'file://{data / "celery" / "results"}',
	})


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------

def _base_env(broker, lab, data_dir, record):
	from secator.config import CONFIG
	inherited = {k: v for k, v in os.environ.items() if not k.startswith(('SECATOR_CELERY_', 'SECATOR_DIRS_'))}
	return {
		**inherited,
		**broker.env,
		'SECATOR_DIRS_DATA': str(data_dir),
		'SECATOR_DIRS_REPORTS': str(CONFIG.dirs.reports),
		'SECATOR_DIRS_TEMPLATES': str(CONFIG.dirs.templates),
		'SECATOR_CELERY_WORKER_KILL_AFTER_TASK': '0',
		'SECATOR_RUNNERS_SKIP_CVE_SEARCH': '1',
		'LITELLM_LOCAL_MODEL_COST_MAP': 'True',
		'PYTHONPATH': os.pathsep.join(filter(None, [str(ROOT), os.environ.get('PYTHONPATH')])),
		'AI_E2E_LAB_URL': lab.url,
		'AI_E2E_LAB_URL2': lab.url2,
		'AI_E2E_RECORD': str(record),
	}


class Worker:
	def __init__(self, name, pool, concurrency, queues, env, folder):
		self.name, self.pool = name, pool
		self.log_path = folder / f'{name}.log'
		self.log = open(self.log_path, 'w+')
		cmd = [
			sys.executable, '-m', 'celery', '-A', 'secator.celery.app', 'worker', '-I', 'tests.integration.ai.worker_app',
			'-P', pool, '-c', str(concurrency), '-Q', queues, '-n', f'{name}@%h',
			'--without-mingle', '--without-gossip', '--without-heartbeat', '-l', 'INFO',
		]
		# stdin=DEVNULL: a child command (httpx) reads an inherited open stdin and hangs on it
		self.proc = subprocess.Popen(cmd, env=env, cwd=folder, stdin=subprocess.DEVNULL, stdout=self.log,
		                             stderr=subprocess.STDOUT, start_new_session=True)

	def text(self):
		self.log.flush()
		return self.log_path.read_text(errors='replace')

	def wait_ready(self, timeout=90):
		deadline = time.time() + timeout
		while time.time() < deadline:
			if 'AI-E2E-WORKER-READY' in self.text():
				return
			if self.proc.poll() is not None:
				break
			time.sleep(0.3)
		raise RuntimeError(f'worker {self.name} did not start:\n{self.text()[-4000:]}')

	def stop(self):
		if self.proc.poll() is None:
			self.proc.send_signal(signal.SIGTERM)
			try:
				self.proc.wait(timeout=20)
			except subprocess.TimeoutExpired:
				os.killpg(self.proc.pid, signal.SIGKILL)  # the whole group: prefork children too
				self.proc.wait()
		self.log.close()


@dataclass
class Workers:
	pool: str
	broker: Broker
	env: Dict[str, str]
	folder: Path
	record: Path
	ai: Worker = None
	children: Worker = None
	runs: Dict[str, Any] = field(default_factory=dict)  # scenario runs shared by several tests

	def logs(self):
		return {w.name: w.text() for w in (self.ai, self.children)}


@pytest.fixture(scope='module', params=POOLS)
def workers(request, broker, lab, _ai_dirs):
	pool = request.param
	if pool == 'gevent' and not find_spec('gevent'):
		pytest.skip('gevent not installed (worker addon)')
	install_workflow(WORKFLOW, WORKFLOW_YAML)
	folder = Path(tempfile.mkdtemp(prefix=f'ai-worker-{pool}-', dir=_ai_dirs))
	data = Path(_ai_dirs) / 'worker-data'
	record = folder / 'requests.jsonl'
	env = _base_env(broker, lab, data, record)
	w = Workers(pool, broker, env, folder, record)
	# The ai worker runs one ai task at a time (-c 1), on each pool.
	# Messages left by an earlier pool's runs (a revoked run's chunks) must not reach these workers.
	subprocess.run([sys.executable, '-m', 'celery', '-A', 'secator.celery.app', 'purge', '-f',
	                '-Q', f'{AI_QUEUE},{POOL_QUEUES}'], env=env, cwd=folder, stdin=subprocess.DEVNULL,
	               capture_output=True, timeout=60)
	# Started one after the other: a first start creates the data dir tree, racing a second one.
	w.ai = Worker(f'ai-{pool}', pool, 1, AI_QUEUE, env, folder)
	request.addfinalizer(w.ai.stop)
	w.ai.wait_ready()
	w.children = Worker(f'pool-{pool}', 'prefork', 4, POOL_QUEUES, env, folder)  # prefork: revoke can terminate
	request.addfinalizer(w.children.stop)
	w.children.wait_ready()
	yield w


# ---------------------------------------------------------------------------
# Run helper
# ---------------------------------------------------------------------------

@dataclass
class WorkerRun:
	tag: str
	summary: Dict
	requests: List[Any]
	all_requests: List[Any]
	logs: Dict[str, str]
	session_id: str
	extra: Dict = field(default_factory=dict)

	@property
	def status(self):
		return self.summary['status']

	def child_requests(self, child):
		name, _, pool = self.tag.partition('@')
		tag = f'{name}.{child}@{pool}'
		return [r for r in self.all_requests if r.tag == tag and not r.side]

	def tool_result(self, call_id, requests=None):
		for r in requests or self.requests:
			res = r.tool_result(call_id)
			if res is not None:
				return res
		raise AssertionError(f'no tool result for {call_id}:\n' + '\n'.join(self.logs.values())[-6000:])

	def tool_json(self, call_id, requests=None):
		return parse_tool_result(self.tool_result(call_id, requests))

	def children(self, name=None):
		return children_of(self.session_id, self.summary.get('id'), name=name)

	def assert_no_network(self):
		"""Neither the workers nor the client tried an outbound connection."""
		for wname, text in self.logs.items():
			assert 'AI-E2E-NETWORK-BLOCKED' not in text, f'blocked connection in {wname}:\n{text[-4000:]}'

	def assert_clean_logs(self, allow_chord_errors=False):
		"""No traceback / error marker in any log. ``allow_chord_errors``: a revoked chunk makes
		Celery log its chord's ChordError, traceback included - expected when chunks are cancelled."""
		self.assert_no_network()
		for wname, text in self.logs.items():
			if allow_chord_errors:
				text = _drop_chord_error_tracebacks(text)
			for marker in LOG_FORBIDDEN + ('AI-E2E-NETWORK-BLOCKED',):
				assert marker not in text, f'{marker!r} in worker {wname} log:\n{text[-6000:]}'


TRACEBACK = 'Traceback (most recent call last)'


def _drop_chord_error_tracebacks(text):
	"""Remove each traceback whose own block (up to the next one) ends on a ChordError."""
	head, *blocks = text.split(TRACEBACK)
	return head + ''.join('' if 'ChordError' in block else TRACEBACK + block for block in blocks)


@pytest.fixture
def wrun(workers):
	def _run(name, targets=None, revoke_when_running=None, timeout=300, check_logs=True, shared=False, **opts):
		"""Run scenario ``name`` once in the workers; ``shared``: reuse the module's earlier run of it."""
		if shared and name in workers.runs:
			return workers.runs[name]
		tag = f'{name}@{workers.pool}'
		session_id = f'sess-{tag}-{uuid.uuid4().hex[:6]}'
		offsets = {w.name: len(w.text()) for w in (workers.ai, workers.children)}
		spec_path = workers.folder / f'{name}.spec.json'
		out_path = workers.folder / f'{name}.out.json'
		run_opts = dict(
			prompt=f'[scenario:{tag}] run the worker scenario', mode='scan', model=MODEL, intent_model=MODEL,
			interactive='auto', sensitive=False, max_iterations=20, print_item=False, print_line=False,
			print_progress=False, print_start=False, print_end=False, print_remote_info=False, sync=False,
		)
		run_opts.update(opts)
		spec_path.write_text(json.dumps({
			'targets': targets or ['127.0.0.1'],
			'opts': run_opts,
			'context': {'drivers': ['json'], 'session_id': session_id},
			'revoke_when_running': revoke_when_running,
			'out': str(out_path),
		}))
		start = time.time()
		client = subprocess.run(
			[sys.executable, '-m', 'tests.integration.ai.worker_client', str(spec_path)],
			env=workers.env, cwd=workers.folder, stdin=subprocess.DEVNULL, capture_output=True, text=True,
			timeout=timeout)
		logs = {w.name: w.text()[offsets[w.name]:] for w in (workers.ai, workers.children)}
		logs['client'] = client.stdout + client.stderr
		assert out_path.exists(), f'client failed ({client.returncode}):\n{logs["client"][-6000:]}'
		summary = json.loads(out_path.read_text())
		summary['wall'] = time.time() - start
		reqs = load_requests(workers.record)
		run = WorkerRun(tag=tag, summary=summary, requests=[r for r in reqs if r.tag == tag and not r.side],
		                all_requests=reqs, logs=logs, session_id=session_id)
		if check_logs:
			run.assert_clean_logs()
		else:
			run.assert_no_network()
		if shared:
			workers.runs[name] = run
		return run
	return _run


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def test_batch_inprocess_and_dispatched(wrun):
	"""In-process task + shell + dispatched workflow in one turn: parallel, all results back."""
	run = wrun('batch')
	assert run.status == 'SUCCESS', run.summary
	r0, r1 = run.requests[:2]
	gap = r1.t - r0.t
	assert 3 <= gap < 25, f'the 3 calls of ~3s took {gap:.1f}s'
	assert 'Slow 3.0' in r1.tool_result('inproc')
	assert 'worker-shell' in r1.tool_result('sh')
	assert 'Slow 3.0' in r1.tool_result('wf')
	statuses = {c['name']: c['status'] for c in run.children()}
	assert statuses.get('httpx') in FINAL_STATUSES and statuses.get(WORKFLOW) in FINAL_STATUSES, statuses


def test_chunked_task(wrun, lab):
	run = wrun('chunked')
	assert run.status == 'SUCCESS', run.summary
	urls = sorted(r['url'] for r in run.tool_json('chunked')['results'] if r.get('_type') == 'url')
	assert urls == sorted([lab.url, f'{lab.url2}/login'])
	children = run.children('httpx')
	assert children and all(c['status'] in FINAL_STATUSES for c in children), children


def test_foreground_subagent_in_worker(wrun):
	run = wrun('subagent_fg')
	assert run.status == 'SUCCESS', run.summary
	assert 'Child verdict: lab home answers 200.' in run.tool_result('sub')
	child = run.child_requests('child')
	assert len(child) == 2
	assert 'child-in-worker' in child[1].tool_result('c_sh')
	assert 'Lab home' in child[1].tool_result('c_task')


def _revoked_run(wrun, workers, name='revoke', running=('command', 'httpx')):
	if workers.broker.kind != 'redis':
		pytest.skip('revoke needs remote control (redis broker)')
	if workers.pool == 'solo':
		pytest.skip('celery limitation: the solo pool cannot terminate a running task')
	run = wrun(name, revoke_when_running=list(running), timeout=200, check_logs=False, shared=True)
	assert run.summary.get('reached_running'), f'{running} never ran: the revoke landed elsewhere'
	return run


def test_revoke_ai_task_mid_run(wrun, workers):
	"""Stopping the client (Ctrl-C) while the ai task waits on a shell and dispatched chunks
	revokes the ai task: the run ends REVOKED and the model is not called again."""
	run = _revoked_run(wrun, workers)
	assert run.summary['wall'] < 120, 'the revoked run kept going'
	errors = [i.get('message') for i in run.summary['items'] if i.get('_type') == 'error']
	assert run.status == 'REVOKED', (run.status, errors)
	# The ai task really stopped in the worker (not just the client giving up on it): had it kept
	# running, it would call the model again once its children end (REVOKE_CHILD_S).
	time.sleep(max(0, REVOKE_CHILD_S + 10 - run.summary['wall']))
	assert len([r for r in load_requests(workers.record) if r.tag == run.tag and not r.side]) == 1, \
		'the model was called after the revoke'


@pytest.mark.xfail(strict=True, reason=(
	'bug: revoking the ai task does not stop its in-process children - the shell command it was '
	'running keeps going (its doc RUNNING) until it ends by itself, then is recorded SUCCESS'))
def test_revoked_ai_task_stops_its_children(wrun, workers):
	"""The in-process shell child of a revoked ai task is stopped with it: its doc ends REVOKED
	(or FAILURE), not RUNNING (still going) nor SUCCESS (ran to completion)."""
	run = _revoked_run(wrun, workers)
	time.sleep(5)
	statuses = {c['name']: c['status'] for c in run.children()}
	assert 'ai' not in statuses, statuses  # only the ai task's children
	assert statuses.get('command') in ('REVOKED', 'FAILURE'), statuses  # the in-process shell child


CANCELLED_CHUNKED_BUG = (
	'bug (pre-existing): a cancelled chunked task\'s runner doc stays RUNNING in the store - its '
	'chunks are revoked, so the chord callback that finalizes the parent task never runs')


# Not strict: the revoke races the chord error path on the pool worker, which sometimes
# finalizes the parent task first.
@pytest.mark.xfail(strict=False, reason=CANCELLED_CHUNKED_BUG + ' (racy)')
def test_cancelled_chunked_task_is_final_in_the_store(wrun, workers):
	"""Ctrl-C while the ai task waits on a dispatched chunked task: the task's doc must end final."""
	run = _revoked_run(wrun, workers, name='revoke_chunked', running=('httpx',))
	assert run.status == 'REVOKED', run.status
	time.sleep(5)
	statuses = [c['status'] for c in run.children('httpx')]
	assert statuses and set(statuses) <= set(FINAL_STATUSES), statuses

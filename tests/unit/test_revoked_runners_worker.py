"""A stopped run finalizes every runner it started, on a real Celery worker.

Each test class starts a worker (``celery worker -P <pool>``) on a filesystem broker in a temporary
folder. A client process (fixtures/revoked_runners/client.py) starts a run and stops it once its
commands run, and every runner doc the json driver wrote must end REVOKED:

- a chunked task: its chunks are revoked, and the task is finalized although its chord callback never runs;
- a task whose child commands run in-process in parallel threads, as the ``ai`` task runs a turn's tool calls.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from importlib.util import find_spec
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'revoked_runners'
FINAL_STATUSES = {'SUCCESS', 'FAILURE', 'REVOKED', 'SKIPPED'}


class _RevokedRunners:
	pool = None

	@classmethod
	def setUpClass(cls):
		cls.tmp = Path(tempfile.mkdtemp(prefix=f'secator-revoke-{cls.pool}-'))
		cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
		data, cls.reports = cls.tmp / 'data', cls.tmp / 'reports'
		for folder in ('celery/data', 'celery/results', 'templates'):
			(data / folder).mkdir(parents=True)
		shutil.copy(FIXTURES / 'revoke_sleep.py', data / 'templates')
		# The worker and the client share this folder's filesystem broker, whatever the caller's env.
		env = {k: v for k, v in os.environ.items() if not k.startswith(('SECATOR_CELERY_', 'SECATOR_DIRS_'))}
		cls.env = {
			**env,
			'SECATOR_DIRS_DATA': str(data),
			'SECATOR_DIRS_REPORTS': str(cls.reports),
			'SECATOR_CELERY_BROKER_URL': 'filesystem://',
			'SECATOR_CELERY_RESULT_BACKEND': f'file://{data}/celery/results',
			'SECATOR_RUNNERS_SKIP_CVE_SEARCH': '1',
			'PYTHONPATH': os.pathsep.join(filter(None, [str(FIXTURES), os.environ.get('PYTHONPATH')])),
		}
		cls.log = cls.tmp / 'worker.log'
		with cls.log.open('w') as log:
			worker = subprocess.Popen(
				[sys.executable, '-m', 'celery', '-A', 'secator.celery.app', 'worker', '-I', 'worker_app',
				 '-P', cls.pool, '-c', '4', '-Q', 'revoke-test,results,celery', '-n', f'revoke-{cls.pool}@%h',
				 '--without-mingle', '--without-gossip', '--without-heartbeat'],
				env=cls.env, cwd=cls.tmp, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
				start_new_session=True)
		cls.addClassCleanup(os.killpg, worker.pid, signal.SIGKILL)  # the pool processes too
		deadline = time.time() + 60
		while 'REVOKE-TEST-WORKER-READY' not in cls.log.read_text():
			if worker.poll() is not None or time.time() > deadline:
				raise RuntimeError(f'worker did not start:\n{cls.log.read_text()}')
			time.sleep(0.3)

	def runner_statuses(self):
		statuses = []
		for path in self.reports.rglob('report*.json'):
			try:
				statuses.append(json.loads(path.read_text())['info']['status'])
			except ValueError:  # being written
				pass
		return statuses

	def _run(self, scenario, count):
		shutil.rmtree(self.reports, ignore_errors=True)
		subprocess.run(
			[sys.executable, FIXTURES / 'client.py', scenario], env=self.env, cwd=self.tmp,
			stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=True)
		deadline = time.time() + 45  # the commands sleep 120s
		statuses = self.runner_statuses()
		while time.time() < deadline and not (len(statuses) == count and set(statuses) <= FINAL_STATUSES):
			time.sleep(0.5)
			statuses = self.runner_statuses()
		self.assertEqual(statuses, ['REVOKED'] * count, self.log.read_text()[-6000:])

	def test_stopped_chunked_task_is_finalized(self):
		self._run('chunked', count=3)  # the task and its 2 chunks

	def test_revoked_task_stops_its_inprocess_children(self):
		self._run('batch', count=2)


class TestRevokedRunnersPrefork(_RevokedRunners, unittest.TestCase):
	pool = 'prefork'


@unittest.skipUnless(find_spec('gevent'), 'gevent not installed (worker addon)')
class TestRevokedRunnersGevent(_RevokedRunners, unittest.TestCase):
	pool = 'gevent'

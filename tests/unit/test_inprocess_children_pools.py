"""A child task run in-process from inside a worker task works under every Celery pool.

The prefork, solo and threads pools flag task joins as blocking, so reading the eager child's
results with ``.get()`` used to fail with "Never call result.get() within a task!". The gevent
pool does not, which is why it was unaffected.

Each test starts a real worker (``celery worker -P <pool>``) on a filesystem broker in a
temporary folder, sends it a task that runs a child task in-process the way the ``ai`` task
does for a light child, and checks the child's results came back.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path

from celery import Celery

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'inprocess_children'
QUEUE = 'inprocess-test'
TIMEOUT = 90


class _PoolWorker:
	"""A real Celery worker subprocess using ``pool``, isolated in its own data folder."""

	def __init__(self, pool):
		self.pool = pool
		self.tmp = Path(tempfile.mkdtemp(prefix=f'secator-inproc-{pool}-'))
		self.data = self.tmp / 'data'
		self.broker_dir = self.data / 'celery' / 'data'
		self.results_dir = self.data / 'celery' / 'results'
		for folder in (self.broker_dir, self.results_dir, self.data / 'templates'):
			folder.mkdir(parents=True, exist_ok=True)
		shutil.copy(FIXTURES / 'inproc_echo.py', self.data / 'templates' / 'inproc_echo.py')
		self.log = open(self.tmp / 'worker.log', 'w+')
		self.proc = None

	def start(self):
		env = {
			**os.environ,
			'SECATOR_DIRS_DATA': str(self.data),
			'SECATOR_CELERY_BROKER_URL': 'filesystem://',
			'SECATOR_CELERY_RESULT_BACKEND': f'file://{self.results_dir}',
			'SECATOR_CELERY_WORKER_KILL_AFTER_TASK': '0',
			'PYTHONPATH': os.pathsep.join(filter(None, [str(FIXTURES), os.environ.get('PYTHONPATH')])),
		}
		cmd = [
			sys.executable, '-m', 'celery', '-A', 'secator.celery.app', 'worker',
			'-I', 'worker_app', '-P', self.pool, '-c', '1', '-Q', QUEUE, '-n', f'inproc-{self.pool}@%h',
			'--without-mingle', '--without-gossip', '--without-heartbeat', '-l', 'INFO',
		]
		self.proc = subprocess.Popen(cmd, env=env, cwd=self.tmp, stdout=self.log, stderr=subprocess.STDOUT)

	def client(self):
		opts = {
			'data_folder_in': str(self.broker_dir),
			'data_folder_out': str(self.broker_dir),
			'control_folder': str(self.broker_dir),
		}
		client = Celery(broker='filesystem://', backend=f'file://{self.results_dir}')
		client.conf.update(
			broker_transport_options=opts,
			task_serializer='pickle',
			result_serializer='pickle',
			accept_content=['application/x-python-serialize'],
			result_accept_content=['application/x-python-serialize'],
		)
		return client

	def run(self, targets):
		result = self.client().send_task('tests.run_inprocess_child', args=[targets], queue=QUEUE)
		return result.get(timeout=TIMEOUT)

	def stop(self):
		if self.proc and self.proc.poll() is None:
			self.proc.send_signal(signal.SIGTERM)
			try:
				self.proc.wait(timeout=20)
			except subprocess.TimeoutExpired:
				self.proc.kill()
				self.proc.wait()
		self.log.close()
		shutil.rmtree(self.tmp, ignore_errors=True)

	def logs(self):
		self.log.flush()
		return (self.tmp / 'worker.log').read_text()[-6000:]


class _InProcessChildren:
	pool = None

	@classmethod
	def setUpClass(cls):
		cls.worker = _PoolWorker(cls.pool)
		cls.worker.start()

	@classmethod
	def tearDownClass(cls):
		cls.worker.stop()

	def _run(self, targets):
		try:
			return self.worker.run(targets)
		except Exception as e:
			self.fail(f'{type(e).__name__}: {e}\n--- worker log ({self.pool}) ---\n{self.worker.logs()}')

	def test_single_target_child(self):
		out = self._run(['alpha'])
		self.assertEqual(out['errors'], [])
		self.assertEqual(out['tags'], ['alpha'])
		self.assertEqual(out['join_will_block'], self.pool != 'gevent')  # guard restored after the child

	def test_chunked_child(self):
		# Two targets with input_chunk_size=1: the eager child replaces itself with a chord.
		out = self._run(['alpha', 'beta'])
		self.assertEqual(out['errors'], [])
		self.assertEqual(out['tags'], ['alpha', 'beta'])


class TestInProcessChildrenPrefork(_InProcessChildren, unittest.TestCase):
	pool = 'prefork'


class TestInProcessChildrenSolo(_InProcessChildren, unittest.TestCase):
	pool = 'solo'


class TestInProcessChildrenThreads(_InProcessChildren, unittest.TestCase):
	pool = 'threads'


@unittest.skipUnless(find_spec('gevent'), 'gevent not installed (worker addon)')
class TestInProcessChildrenGevent(_InProcessChildren, unittest.TestCase):
	pool = 'gevent'

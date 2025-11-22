import os
import unittest
import warnings
import subprocess
import time

from celery import chain, chord

from secator.celery import app, forward_results  # noqa: F401
from secator.config import CONFIG
from secator.utils_test import TEST_TASKS, load_fixture
from secator.runners import Command
from secator.output_types import Url
from tests.integration.inputs import INPUTS_SCANS


INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
OPTS = {
	'ffuf.filter_size': '3748,3106',
	'ffuf.depth': 1,
	'ffuf.follow_redirect': True,
	'ffuf.wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
}
URL_TARGETS = INPUTS_SCANS['url']
URL_RESULTS_COUNT = [14, 1]


class TestRemoteWorker(unittest.TestCase):
	"""Test secator with remote worker running in Docker container."""

	@classmethod
	def setUpClass(cls):
		"""Set up Docker containers with Redis and remote worker."""
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

		# Check if docker compose is available
		result = subprocess.run(
			['docker', 'compose', 'version'],
			capture_output=True,
			text=True
		)
		if result.returncode != 0:
			raise unittest.SkipTest("Docker Compose is not available")

		# Set environment variables for Redis broker
		os.environ['SECATOR_CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
		os.environ['SECATOR_CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

		# Create docker-compose file for remote worker tests
		cls.docker_compose_file = os.path.join(INTEGRATION_DIR, 'docker-compose.remote-worker.yml')
		docker_compose_content = """version: "3.7"

services:
  redis:
    image: redis:latest
    container_name: secator-test-redis
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  worker:
    image: freelabz/secator:latest
    container_name: secator-test-worker
    command: ['worker', '--use-command-runner']
    environment:
      - SECATOR_CELERY_BROKER_URL=redis://redis:6379/0
      - SECATOR_CELERY_RESULT_BACKEND=redis://redis:6379/0
    depends_on:
      redis:
        condition: service_healthy
"""
		with open(cls.docker_compose_file, 'w') as f:
			f.write(docker_compose_content)

		# Start Docker containers
		print("Starting Docker containers for remote worker tests...")
		subprocess.run(
			['docker', 'compose', '-f', cls.docker_compose_file, 'up', '-d'],
			check=True,
			cwd=INTEGRATION_DIR
		)

		# Wait for services to be ready
		print("Waiting for Redis and worker to be ready...")
		time.sleep(10)

		# Verify Redis is accessible
		max_retries = 5
		for i in range(max_retries):
			try:
				result = subprocess.run(
					['docker', 'exec', 'secator-test-redis', 'redis-cli', 'ping'],
					capture_output=True,
					text=True,
					timeout=5
				)
				if result.returncode == 0 and 'PONG' in result.stdout:
					print("Redis is ready")
					break
			except Exception as e:
				print(f"Waiting for Redis (attempt {i+1}/{max_retries}): {e}")
			time.sleep(2)
		else:
			raise Exception("Redis failed to start")

		# Verify worker is running
		result = subprocess.run(
			['docker', 'ps', '--filter', 'name=secator-test-worker', '--format', '{{.Status}}'],
			capture_output=True,
			text=True
		)
		if 'Up' not in result.stdout:
			raise Exception("Worker container is not running")
		print("Worker container is running")

	@classmethod
	def tearDownClass(cls) -> None:
		"""Tear down Docker containers."""
		print("Stopping Docker containers for remote worker tests...")
		subprocess.run(
			['docker', 'compose', '-f', cls.docker_compose_file, 'down', '-v'],
			cwd=INTEGRATION_DIR
		)

		# Clean up docker-compose file
		if os.path.exists(cls.docker_compose_file):
			os.remove(cls.docker_compose_file)

		# Reset environment variables
		os.environ.pop('SECATOR_CELERY_BROKER_URL', None)
		os.environ.pop('SECATOR_CELERY_RESULT_BACKEND', None)

	def test_httpx_remote(self):
		"""Test httpx task with remote worker."""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest("httpx not in TEST_TASKS")

		# Execute task remotely
		result = httpx.delay(['http://testphp.vulnweb.com'])
		results = result.get(timeout=30)

		# Verify results
		urls = [r.url for r in results if r._type == 'url']
		self.assertGreater(len(urls), 0, "Expected at least one URL result")

	def test_httpx_chain_remote(self):
		"""Test httpx chain with remote worker."""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest("httpx not in TEST_TASKS")

		# Create chain workflow
		sigs = [forward_results.si([])] + [httpx.s(target) for target in URL_TARGETS]
		workflow = chain(*sigs)
		result = workflow.apply_async()
		results = result.get(timeout=60)

		# Verify results
		urls = [r.url for r in results if r._type == 'url']
		targets = [r.name for r in results if r._type == 'target']
		self.assertEqual(len(urls), len(URL_TARGETS))
		self.assertEqual(len(targets), len(URL_TARGETS))

	def test_httpx_chord_remote(self):
		"""Test httpx chord with remote worker."""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest("httpx not in TEST_TASKS")

		existing_results = [Url(**{
			"url": "https://example.com",
			"method": "GET",
			"status_code": 200,
			"words": 100,
			"lines": 50,
			"content_type": "text/html",
			"content_length": 1000,
			"host": "1.2.3.4",
			"time": 0.1,
			"_source": "httpx",
			"_type": "url"
		})]

		# Create chord workflow
		sigs = []
		for target in URL_TARGETS:
			sig = httpx().s(target)
			sigs.append(sig)

		workflow = chain(
			forward_results.s(existing_results),
			sigs[0],
			chord((
				sigs[1],
				sigs[0],
			), forward_results.s()),
			sigs[1],
			chord((
				sigs[0],
				sigs[1],
			), forward_results.s())
		)
		result = workflow.apply_async()
		results = result.get(timeout=90)

		# Verify results
		urls = [r.url for r in results if r._type == 'url']
		targets = [r.name for r in results if r._type == 'target']
		self.assertIn(existing_results[0], results)
		self.assertGreaterEqual(len(urls), len(URL_TARGETS))

	def test_worker_availability(self):
		"""Test that remote worker is available and responding."""
		from secator.celery import is_celery_worker_alive

		# Check if worker is alive
		worker_alive = is_celery_worker_alive()
		self.assertTrue(worker_alive, "Remote worker should be available")

	def test_redis_connectivity(self):
		"""Test Redis connectivity for Celery broker."""
		import redis

		# Connect to Redis
		r = redis.Redis(host='localhost', port=6379, db=0)
		
		# Test ping
		self.assertTrue(r.ping(), "Redis should be accessible")

		# Test set/get
		test_key = 'secator_test_key'
		test_value = 'secator_test_value'
		r.set(test_key, test_value)
		self.assertEqual(r.get(test_key).decode(), test_value)
		r.delete(test_key)

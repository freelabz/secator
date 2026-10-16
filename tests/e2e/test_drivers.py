"""End-to-end tests for secator drivers.

Driver          Backend                 Test strategy
-----------     --------------------    --------------------------------
api             External HTTP API       Mock ``requests.request``
mongodb         MongoDB                 Spawn Docker container (skipped
                                        if Docker is unavailable)
gcs             Google Cloud Storage    Mock ``google.cloud.storage``

Notes:
    - 'discord' is not a supported driver in secator; available drivers
      are: mongodb, gcs, api.
    - Each test class registers the driver hooks directly on the Python
      runner (bypassing the CLI) so that the hook logic can be validated
      in isolation.
"""

import subprocess
import time
import unittest
import warnings
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED
from secator.utils_test import TEST_TASKS

TEST_URL = 'https://wikipedia.org'
TEST_HOST = 'wikipedia.org'
RUN_OPTS = {'tls_grab': True}

# MongoDB Docker settings — use a non-standard port to avoid conflicts.
_MONGO_PORT = 27019
_MONGO_CONTAINER = 'secator-test-mongodb'
_MONGO_URL = f'mongodb://localhost:{_MONGO_PORT}'


def _docker_available():
	"""Return True if Docker daemon is reachable."""
	try:
		result = subprocess.run(
			['docker', 'info'],
			capture_output=True,
			timeout=5,
		)
		return result.returncode == 0
	except (FileNotFoundError, subprocess.TimeoutExpired):
		return False


# ---------------------------------------------------------------------------
# API driver
# ---------------------------------------------------------------------------

class TestAPIDriver(unittest.TestCase):
	"""API driver sends runner/finding data to a (mocked) external HTTP API."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx
		cls.httpx_cls = httpx
		cls.skip_all = httpx not in TEST_TASKS or not ADDONS_ENABLED.get('api', False)

	@staticmethod
	def _make_mock_response(payload=None):
		"""Return a mock ``requests.Response`` with ``ok=True``."""
		resp = MagicMock()
		resp.ok = True
		resp.status_code = 200
		resp.json.return_value = payload or {'id': 'test-runner-001'}
		return resp

	def test_api_driver_calls_endpoints(self):
		"""API driver POSTs/PUTs to runner and finding endpoints for each item."""
		if self.__class__.skip_all:
			self.skipTest('httpx not in TEST_TASKS or api addon not available')

		from secator.hooks.api import HOOKS as API_HOOKS

		call_log = []

		def mock_request(method, url, **kwargs):
			call_log.append((method, url))
			payload = {'id': 'test-runner-001'} if 'runners' in url else {'id': 'test-finding-001'}
			return self._make_mock_response(payload)

		with patch('secator.hooks.api.API_URL', 'https://mock-api.example.com'), \
				patch('secator.hooks.api.API_KEY', 'test-key'), \
				patch('secator.hooks.api.API_HEADER_NAME', 'Bearer'), \
				patch('secator.hooks.api.API_WORKSPACE_GET_ENDPOINT', ''), \
				patch('secator.hooks.api.FORCE_SSL', False), \
				patch('requests.request', side_effect=mock_request):
			runner = self.__class__.httpx_cls(
				TEST_URL,
				sync=True,
				hooks=API_HOOKS,
				**RUN_OPTS,
			)
			results = runner.run()

		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)
		self.assertGreater(len(call_log), 0, 'Expected at least one API request')
		methods_used = {m for m, _ in call_log}
		self.assertTrue(
			methods_used & {'POST', 'PUT'},
			f'Expected POST or PUT calls; got {methods_used}',
		)


# ---------------------------------------------------------------------------
# MongoDB driver
# ---------------------------------------------------------------------------

class TestMongoDBDriver(unittest.TestCase):
	"""MongoDB driver persists runner/finding data to MongoDB (requires Docker)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx
		cls.httpx_cls = httpx
		cls.skip_all = httpx not in TEST_TASKS or not ADDONS_ENABLED.get('mongodb', False)
		cls.docker_available = _docker_available()
		cls.container_started = False

		if not cls.skip_all and cls.docker_available:
			# Remove any leftover container from a previous run.
			subprocess.run(
				['docker', 'rm', '-f', _MONGO_CONTAINER],
				capture_output=True,
			)
			result = subprocess.run(
				[
					'docker', 'run', '-d',
					'--name', _MONGO_CONTAINER,
					'-p', f'{_MONGO_PORT}:27017',
					'mongo:7',
				],
				capture_output=True,
				text=True,
			)
			cls.container_started = result.returncode == 0
			if cls.container_started:
				time.sleep(5)  # Wait for MongoDB to finish starting up.

	@classmethod
	def tearDownClass(cls):
		if cls.container_started:
			subprocess.run(['docker', 'stop', _MONGO_CONTAINER], capture_output=True)
			subprocess.run(['docker', 'rm', _MONGO_CONTAINER], capture_output=True)

	def test_mongodb_driver_persists_findings(self):
		"""MongoDB driver inserts findings into the ``findings`` collection."""
		if self.__class__.skip_all:
			self.skipTest('httpx not in TEST_TASKS or mongodb addon not available')
		if not self.__class__.docker_available:
			self.skipTest('Docker is not available')
		if not self.__class__.container_started:
			self.skipTest('Failed to start MongoDB Docker container')

		import pymongo
		from secator.hooks.mongodb import HOOKS as MONGO_HOOKS

		# Patch module-level URL and reset the cached client so the patched URL is used.
		with patch('secator.hooks.mongodb.MONGODB_URL', _MONGO_URL), \
				patch('secator.hooks.mongodb._mongodb_client', None):
			runner = self.__class__.httpx_cls(
				TEST_URL,
				sync=True,
				hooks=MONGO_HOOKS,
				**RUN_OPTS,
			)
			results = runner.run()

		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify that findings were written to the MongoDB instance.
		client = pymongo.MongoClient(_MONGO_URL, serverSelectionTimeoutMS=5000)
		try:
			finding_count = client.main.findings.count_documents({})
		finally:
			client.close()
		self.assertGreater(finding_count, 0, 'Expected at least one document in MongoDB findings collection')


# ---------------------------------------------------------------------------
# GCS driver
# ---------------------------------------------------------------------------

class TestGCSDriver(unittest.TestCase):
	"""GCS driver processes items without errors (GCS client is mocked)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx
		cls.httpx_cls = httpx
		cls.skip_all = httpx not in TEST_TASKS or not ADDONS_ENABLED.get('gcs', False)

	def test_gcs_driver_runs_without_error(self):
		"""GCS driver runs without errors when processing items; file uploads are mocked."""
		if self.__class__.skip_all:
			self.skipTest('httpx not in TEST_TASKS or gcs addon not available')

		from secator.hooks.gcs import HOOKS as GCS_HOOKS

		mock_client = MagicMock()
		mock_bucket = MagicMock()
		mock_client.bucket.return_value = mock_bucket

		with patch('secator.hooks.gcs.GCS_BUCKET_NAME', 'test-bucket'), \
				patch('secator.hooks.gcs._gcs_client', None), \
				patch('google.cloud.storage.Client', return_value=mock_client):
			runner = self.__class__.httpx_cls(
				TEST_URL,
				sync=True,
				hooks=GCS_HOOKS,
				**RUN_OPTS,
			)
			results = runner.run()

		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)


if __name__ == '__main__':
	unittest.main()

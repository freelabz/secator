"""End-to-end tests for secator runners.

These tests verify that tasks, workflows, and scans can be invoked in sync/async mode
using both the dynamic loader (`from secator.tasks import httpx`) and the normal loader
(`Task(TemplateLoader(...), ...)`).
"""
import unittest
import warnings
from threading import Thread
from time import sleep

from secator.runners import Command
from secator.template import TemplateLoader
from secator.runners import Task, Workflow, Scan
from secator.output_types import Url, Certificate
from secator.utils_test import TEST_TASKS


# Test targets
TEST_URL = 'https://wikipedia.org'
TEST_HOST = 'wikipedia.org'

# Run options
RUN_OPTS = {
	'tls_grab': True,
}


def assert_has_url_result(test_case, results, expected_url=TEST_URL):
	"""Assert that results contain a Url object with the expected url.

	Args:
		test_case: The unittest.TestCase instance.
		results: List of result objects.
		expected_url: The expected URL string.
	"""
	urls = [r for r in results if isinstance(r, Url)]
	test_case.assertGreater(len(urls), 0, 'Expected at least one Url result')

	# Check that at least one URL matches (may have trailing slash or www prefix)
	url_values = [u.url for u in urls]
	matching_urls = [u for u in url_values if expected_url.rstrip('/') in u or u.rstrip('/') in expected_url]
	test_case.assertGreater(
		len(matching_urls), 0,
		f'Expected a Url with url containing {expected_url}, got: {url_values}'
	)


def assert_has_certificate_result(test_case, results, expected_host=TEST_HOST):
	"""Assert that results contain a Certificate object with the expected host.

	Args:
		test_case: The unittest.TestCase instance.
		results: List of result objects.
		expected_host: The expected host string.
	"""
	certs = [r for r in results if isinstance(r, Certificate)]
	test_case.assertGreater(len(certs), 0, 'Expected at least one Certificate result')

	# Check that at least one certificate matches the host
	cert_hosts = [c.host for c in certs]
	matching_certs = [h for h in cert_hosts if expected_host in h or h in expected_host]
	test_case.assertGreater(
		len(matching_certs), 0,
		f'Expected a Certificate with host containing {expected_host}, got: {cert_hosts}'
	)


class TestTaskSync(unittest.TestCase):
	"""Test Task runner in sync mode (no Celery worker needed)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def test_task_sync_dynamic_loader(self):
		"""Test task invocation in sync mode using the dynamic loader.

		Example:
			from secator.tasks import httpx
			results = httpx('wikipedia.org', sync=True, **run_opts).run()
		"""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest('httpx not in TEST_TASKS')

		runner = httpx(TEST_URL, sync=True, **RUN_OPTS)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify we have a Url result with url='https://wikipedia.org'
		assert_has_url_result(self, results, TEST_URL)

		# Verify we have a Certificate result with host='wikipedia.org'
		assert_has_certificate_result(self, results, TEST_HOST)

	def test_task_sync_normal_loader(self):
		"""Test task invocation in sync mode using the normal loader (TemplateLoader).

		Example:
			config = TemplateLoader(input={'name': 'httpx', 'type': 'task'})
			results = Task(config, 'wikipedia.org', run_opts={'sync': True, **run_opts}).run()
		"""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest('httpx not in TEST_TASKS')

		config = TemplateLoader(input={'name': 'httpx', 'type': 'task'})
		run_opts = {'sync': True, **RUN_OPTS}
		runner = Task(config, TEST_URL, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify we have a Url result with url='https://wikipedia.org'
		assert_has_url_result(self, results, TEST_URL)

		# Verify we have a Certificate result with host='wikipedia.org'
		assert_has_certificate_result(self, results, TEST_HOST)


class TestWorkflowSync(unittest.TestCase):
	"""Test Workflow runner in sync mode (no Celery worker needed)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def test_workflow_sync_dynamic_loader(self):
		"""Test workflow invocation in sync mode using the dynamic loader.

		Example:
			from secator.workflows import host_recon
			results = host_recon('wikipedia.org', sync=True).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.workflows import host_recon
		runner = host_recon(TEST_HOST, sync=True, passive=True)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_workflow_sync_normal_loader(self):
		"""Test workflow invocation in sync mode using the normal loader (TemplateLoader).

		Example:
			config = TemplateLoader(name='workflow/host_recon')
			results = Workflow(config, 'wikipedia.org', run_opts={'sync': True}).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		config = TemplateLoader(name='workflow/host_recon')
		run_opts = {'sync': True, 'passive': True}
		runner = Workflow(config, TEST_HOST, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)


class TestScanSync(unittest.TestCase):
	"""Test Scan runner in sync mode (no Celery worker needed)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def test_scan_sync_dynamic_loader(self):
		"""Test scan invocation in sync mode using the dynamic loader.

		Example:
			from secator.scans import host
			results = host('wikipedia.org', sync=True).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.scans import host
		runner = host(TEST_HOST, sync=True)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_scan_sync_normal_loader(self):
		"""Test scan invocation in sync mode using the normal loader (TemplateLoader).

		Example:
			config = TemplateLoader(name='scan/host')
			results = Scan(config, 'wikipedia.org', run_opts={'sync': True}).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		config = TemplateLoader(name='scan/host')
		run_opts = {'sync': True}
		runner = Scan(config, TEST_HOST, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)


class TestTaskAsync(unittest.TestCase):
	"""Test Task runner in async mode (requires Celery worker)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

		# Start Celery worker in a thread
		cls.cmd = Command.execute(
			'secator worker --use-command-runner',
			quiet=True,
			run=False
		)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(5)

	@classmethod
	def tearDownClass(cls):
		cls.cmd.stop_process()
		cls.thread.join()

	def test_task_async_dynamic_loader_delay(self):
		"""Test task invocation in async mode using the dynamic loader with .delay().

		Example:
			from secator.tasks import httpx
			result = httpx.delay('wikipedia.org', **run_opts).get()
		"""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest('httpx not in TEST_TASKS')

		async_result = httpx.delay(TEST_URL, **RUN_OPTS)
		results = async_result.get()

		# Verify we got results
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify we have a Url result with url='https://wikipedia.org'
		assert_has_url_result(self, results, TEST_URL)

		# Verify we have a Certificate result with host='wikipedia.org'
		assert_has_certificate_result(self, results, TEST_HOST)

	def test_task_async_normal_loader_sync_false(self):
		"""Test task invocation in async mode using the normal loader with sync=False.

		Example:
			config = TemplateLoader(input={'name': 'httpx', 'type': 'task'})
			results = Task(config, 'wikipedia.org', run_opts={'sync': False, **run_opts}).run()
		"""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest('httpx not in TEST_TASKS')

		config = TemplateLoader(input={'name': 'httpx', 'type': 'task'})
		run_opts = {'sync': False, **RUN_OPTS}
		runner = Task(config, TEST_URL, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify we have a Url result with url='https://wikipedia.org'
		assert_has_url_result(self, results, TEST_URL)

		# Verify we have a Certificate result with host='wikipedia.org'
		assert_has_certificate_result(self, results, TEST_HOST)

	def test_task_async_dynamic_loader_sync_false(self):
		"""Test task invocation in async mode using the dynamic loader with sync=False.

		Example:
			from secator.tasks import httpx
			results = httpx('wikipedia.org', sync=False, **run_opts).run()
		"""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			self.skipTest('httpx not in TEST_TASKS')

		runner = httpx(TEST_URL, sync=False, **RUN_OPTS)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Verify we have a Url result with url='https://wikipedia.org'
		assert_has_url_result(self, results, TEST_URL)

		# Verify we have a Certificate result with host='wikipedia.org'
		assert_has_certificate_result(self, results, TEST_HOST)


class TestWorkflowAsync(unittest.TestCase):
	"""Test Workflow runner in async mode (requires Celery worker)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

		# Start Celery worker in a thread
		cls.cmd = Command.execute(
			'secator worker --use-command-runner',
			quiet=True,
			run=False
		)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(5)

	@classmethod
	def tearDownClass(cls):
		cls.cmd.stop_process()
		cls.thread.join()

	def test_workflow_async_dynamic_loader_delay(self):
		"""Test workflow invocation in async mode using the dynamic loader with .delay().

		Example:
			from secator.workflows import host_recon
			result = host_recon.delay('wikipedia.org').get()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.workflows import host_recon
		async_result = host_recon.delay(TEST_HOST, passive=True)
		results = async_result.get()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_workflow_async_normal_loader_sync_false(self):
		"""Test workflow invocation in async mode using the normal loader with sync=False.

		Example:
			config = TemplateLoader(name='workflow/host_recon')
			results = Workflow(config, 'wikipedia.org', run_opts={'sync': False}).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		config = TemplateLoader(name='workflow/host_recon')
		run_opts = {'sync': False, 'passive': True}
		runner = Workflow(config, TEST_HOST, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_workflow_async_dynamic_loader_sync_false(self):
		"""Test workflow invocation in async mode using the dynamic loader with sync=False.

		Example:
			from secator.workflows import host_recon
			results = host_recon('wikipedia.org', sync=False).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.workflows import host_recon
		runner = host_recon(TEST_HOST, sync=False, passive=True)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)


class TestScanAsync(unittest.TestCase):
	"""Test Scan runner in async mode (requires Celery worker)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

		# Start Celery worker in a thread
		cls.cmd = Command.execute(
			'secator worker --use-command-runner',
			quiet=True,
			run=False
		)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(5)

	@classmethod
	def tearDownClass(cls):
		cls.cmd.stop_process()
		cls.thread.join()

	def test_scan_async_dynamic_loader_delay(self):
		"""Test scan invocation in async mode using the dynamic loader with .delay().

		Example:
			from secator.scans import host
			result = host.delay('wikipedia.org').get()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.scans import host
		async_result = host.delay(TEST_HOST)
		results = async_result.get()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_scan_async_normal_loader_sync_false(self):
		"""Test scan invocation in async mode using the normal loader with sync=False.

		Example:
			config = TemplateLoader(name='scan/host')
			results = Scan(config, 'wikipedia.org', run_opts={'sync': False}).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		config = TemplateLoader(name='scan/host')
		run_opts = {'sync': False}
		runner = Scan(config, TEST_HOST, run_opts=run_opts)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)

	def test_scan_async_dynamic_loader_sync_false(self):
		"""Test scan invocation in async mode using the dynamic loader with sync=False.

		Example:
			from secator.scans import host
			results = host('wikipedia.org', sync=False).run()
		"""
		from secator.tasks import httpx, nmap
		if httpx not in TEST_TASKS or nmap not in TEST_TASKS:
			self.skipTest('httpx or nmap not in TEST_TASKS')

		from secator.scans import host
		runner = host(TEST_HOST, sync=False)
		results = runner.run()

		# Verify we got results
		self.assertIsInstance(results, list)


if __name__ == '__main__':
	unittest.main()

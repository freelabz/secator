import unittest
from secator.celery import app, forward_results  # noqa: F401
from secator.utils_test import mock_command, FIXTURES_TASKS, TEST_TASKS, FIXTURES_DIR, load_fixture
from secator.output_types import Url
from celery import chain, chord

TARGETS = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']


class TestCelery(unittest.TestCase):

	def test_httpx_chain(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [forward_results.si([])] + [httpx.s(target) for target in TARGETS]
			workflow = chain(*sigs)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(urls), len(TARGETS))
			self.assertEqual(len(targets), len(TARGETS))

	def test_httpx_chain_with_results(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		existing_results = [Url(**{
			"url": "https://example.synology.me",
			"method": "GET",
			"status_code": 200,
			"words": 438,
			"lines": 136,
			"content_type":
			"text/html",
			"content_length": 11577,
			"host": "82.66.157.114",
			"time": 0.16246860100000002,
			"_source": "httpx",
			"_type": "url"
		})]
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [forward_results.s(existing_results)] + [httpx.s(target) for target in TARGETS]
			workflow = chain(*sigs)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(urls), len(TARGETS) + 1)
			self.assertEqual(len(targets), len(TARGETS))
			self.assertIn(existing_results[0], results)

	def test_httpx_workflow(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
		sigs = []
		for target in targets:
			sig = httpx().s(target)
			sigs.append(sig)
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(targets)):
			workflow = chain(
				forward_results.s([]),
				sigs[0],
				chord((
					sigs[1],
					sigs[2],
				), forward_results.s()),
				sigs[3],
				chord((
					sigs[4],
					sigs[5],
				), forward_results.s())
			)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(TARGETS))
			self.assertEqual(len(urls), len(TARGETS))

	def test_nmap_workflow(self):
		from secator.tasks import nmap
		if nmap not in TEST_TASKS:
			return

		nmap_fixture = load_fixture('nmap_output', fixtures_dir=FIXTURES_DIR, ext='.xml', only_path=True)
		with mock_command(nmap, fixture=[FIXTURES_TASKS[nmap]] * len(TARGETS)):
			workflow = chain(
				forward_results.s([]),
				chord((
					nmap.s(TARGETS, output_path=nmap_fixture)
				), forward_results.s()),
			)
			result = workflow.apply()
			results = result.get()
			vulns = [r.id for r in results if r._type == 'vulnerability']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(TARGETS))
			self.assertEqual(len(vulns), 61)  # number of vulns in the XML fixture

	def test_ffuf_chunked(self):
		from secator.tasks import ffuf
		if ffuf not in TEST_TASKS:
			return

		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]

		with mock_command(ffuf, fixture=[FIXTURES_TASKS[ffuf]] * len(HTTP_TARGETS)):
			workflow = chain(
				forward_results.s([]),
				chord((
					ffuf.s(HTTP_TARGETS)
				), forward_results.s()),
			)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(HTTP_TARGETS) * 2)
			self.assertEqual(len(urls), len(HTTP_TARGETS))

	def test_rate_limit_adjustment_for_chunked_tasks(self):
		"""Test that rate_limit is divided by chunk count when chunking tasks."""
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# Create a task with rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 100, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			workflow = break_task(task, task_opts, results=[])

			# Check that rate_limit was adjusted
			# With 6 targets and input_chunk_size=1 (default for most tasks),
			# we should have 6 chunks, so rate_limit should be 100 // 6 = 16
			# The workflow should be a chord with adjusted rate_limit in each signature
			self.assertIsNotNone(workflow)

			# Extract the signatures from the chord to check rate_limit
			# The workflow is a chord, so we can access its tasks
			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			if header_tasks:
				# Each task should have the adjusted rate_limit in its kwargs
				first_sig = header_tasks[0]
				# The rate_limit should be in the kwargs of the signature
				expected_rate_limit = 100 // 6  # = 16
				if 'opts' in first_sig.kwargs and 'rate_limit' in first_sig.kwargs['opts']:
					actual_rate_limit = first_sig.kwargs['opts']['rate_limit']
					self.assertEqual(actual_rate_limit, expected_rate_limit)

	def test_rate_limit_adjustment_minimum_value(self):
		"""Test that rate_limit never goes below 1 when chunking."""
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# Create a task with low rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 2, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			# With rate_limit=2 and 6 chunks, adjusted rate_limit should be max(1, 2//6) = 1
			workflow = break_task(task, task_opts, results=[])

			# The workflow should exist and have properly adjusted rate_limit
			self.assertIsNotNone(workflow)

			# Extract the signatures from the chord to check rate_limit
			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			if header_tasks:
				# Each task should have the adjusted rate_limit in its kwargs
				first_sig = header_tasks[0]
				# The rate_limit should be at least 1
				if 'opts' in first_sig.kwargs and 'rate_limit' in first_sig.kwargs['opts']:
					actual_rate_limit = first_sig.kwargs['opts']['rate_limit']
					self.assertGreaterEqual(actual_rate_limit, 1)
					self.assertEqual(actual_rate_limit, 1)  # Should be 1 since 2//6 = 0, but max(1, 0) = 1

	def test_break_task_with_disabled_chunking(self):
		"""Test that break_task doesn't chunk when input_chunk_size=-1."""
		from secator.tasks import httpx
		from secator.celery import break_task
		if httpx not in TEST_TASKS:
			return

		class TestTask(httpx):
			input_chunk_size = -1

		# Create a task with many inputs
		inputs = ['target1', 'target2', 'target3', 'target4', 'target5']
		task = TestTask(inputs)
		task_opts = {}

		# Mock to get the workflow signature
		with mock_command(TestTask, fixture=[FIXTURES_TASKS[httpx]]):
			workflow = break_task(task, task_opts, results=[])
			# With input_chunk_size=-1, should return the inputs as-is without chunking
			# This means one chunk with all inputs
			self.assertEqual(len(workflow.tasks), len(inputs))

	def test_chunk_rate_limit_config_disabled(self):
		"""Test that rate_limit is NOT adjusted when CONFIG.runners.chunk_rate_limit is False."""
		from secator.celery import break_task
		from secator.config import CONFIG
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 100, 'sync': False}

		original_value = CONFIG.runners.chunk_rate_limit
		try:
			CONFIG.runners.chunk_rate_limit = False
			with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
				task = httpx(HTTP_TARGETS, **task_opts)
				task.has_children = True
				workflow = break_task(task, task_opts, results=[])
				self.assertIsNotNone(workflow)
				# Rate limit should remain unchanged (100) since config disabled division
				header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
				if header_tasks:
					first_sig = header_tasks[0]
					if 'opts' in first_sig.kwargs and 'rate_limit' in first_sig.kwargs['opts']:
						self.assertEqual(first_sig.kwargs['opts']['rate_limit'], 100)
		finally:
			CONFIG.runners.chunk_rate_limit = original_value

	def test_rate_limit_host_chunking(self):
		"""Test that rate_limit_host groups chunks by host and divides rate limit per host."""
		from secator.celery import break_task, get_target_host
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# 4 targets: 3 for bing.com, 1 for google.com
		HTTP_TARGETS = [
			'https://bing.com/a', 'https://bing.com/b', 'https://bing.com/c',
			'https://google.com/x',
		]
		task_opts = {'rate_limit': 90, 'rate_limit_host': True, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True
			workflow = break_task(task, task_opts, results=[])
			self.assertIsNotNone(workflow)

			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			self.assertEqual(len(header_tasks), 4)  # 3 bing chunks + 1 google chunk

			# Collect rate limits per host
			host_rate_limits = {}
			for sig in header_tasks:
				if 'opts' in sig.kwargs:
					rl = sig.kwargs['opts'].get('rate_limit', 90)
					# Get host from targets in the signature args
					targets = sig.args[1] if len(sig.args) > 1 else sig.args[0]
					if isinstance(targets, list):
						host = get_target_host(targets[0])
					else:
						host = get_target_host(targets)
					host_rate_limits.setdefault(host, set()).add(rl)

			# bing.com has 3 chunks -> 90 // 3 = 30
			self.assertEqual(host_rate_limits.get('bing.com'), {30})
			# google.com has 1 chunk -> 90 // 1 = 90
			self.assertEqual(host_rate_limits.get('google.com'), {90})

	def test_get_target_host(self):
		"""Test get_target_host extracts hostname correctly for all input types."""
		from secator.celery import get_target_host
		# URLs
		self.assertEqual(get_target_host('https://example.com/path'), 'example.com')
		self.assertEqual(get_target_host('http://sub.example.com:8080/path'), 'sub.example.com')
		# Bare hostnames
		self.assertEqual(get_target_host('example.com'), 'example.com')
		self.assertEqual(get_target_host('sub.example.com'), 'sub.example.com')
		# IPs
		self.assertEqual(get_target_host('192.168.1.1'), '192.168.1.1')
		# Host:port
		self.assertEqual(get_target_host('192.168.1.1:8080'), '192.168.1.1')
		self.assertEqual(get_target_host('example.com:443'), 'example.com')
		# CIDR ranges
		self.assertEqual(get_target_host('10.0.0.0/24'), '10.0.0.0')
		# Usernames (no meaningful host, returned as-is)
		self.assertEqual(get_target_host('johndoe'), 'johndoe')
		# Paths (returned as-is)
		self.assertEqual(get_target_host('/path/to/file'), '/path/to/file')


class TestDelayMethods(unittest.TestCase):
	"""Test the delay methods for different runner types."""

	def test_command_delay_signature(self):
		"""Test that Command.delay() creates a proper Celery signature."""
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# Test that delay returns an AsyncResult-like object
		sig = httpx.delay('example.com')
		self.assertIsNotNone(sig)
		self.assertTrue(hasattr(sig, 'id'))

	def test_dynamic_workflow_delay_creates_signature(self):
		"""Test that DynamicWorkflow.delay() creates a proper Celery signature."""
		from secator.loader import get_configs_by_type

		# Get a workflow config
		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		# Import the dynamic workflow
		from secator.workflows import DYNAMIC_WORKFLOWS
		if not DYNAMIC_WORKFLOWS:
			self.skipTest('No dynamic workflows available')

		workflow_name = list(DYNAMIC_WORKFLOWS.keys())[0]
		workflow = DYNAMIC_WORKFLOWS[workflow_name]

		# Test that delay method exists and is callable
		self.assertTrue(callable(getattr(workflow, 'delay', None)))

		# Test that s() and si() methods exist
		self.assertTrue(callable(getattr(workflow, 's', None)))
		self.assertTrue(callable(getattr(workflow, 'si', None)))

	def test_dynamic_scan_delay_creates_signature(self):
		"""Test that DynamicScan.delay() creates a proper Celery signature."""
		from secator.loader import get_configs_by_type

		# Get a scan config
		scans = get_configs_by_type('scan')
		if not scans:
			self.skipTest('No scans configured')

		# Import the dynamic scan
		from secator.scans import DYNAMIC_SCANS
		if not DYNAMIC_SCANS:
			self.skipTest('No dynamic scans available')

		scan_name = list(DYNAMIC_SCANS.keys())[0]
		scan = DYNAMIC_SCANS[scan_name]

		# Test that delay method exists and is callable
		self.assertTrue(callable(getattr(scan, 'delay', None)))

		# Test that s() and si() methods exist
		self.assertTrue(callable(getattr(scan, 's', None)))
		self.assertTrue(callable(getattr(scan, 'si', None)))

	def test_runner_classmethod_delay(self):
		"""Test Runner.delay() classmethod with explicit config (TemplateLoader)."""
		from secator.runners import Runner
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# Test that the classmethod accepts config (TemplateLoader) and targets
		sig = Runner.delay(config, ['example.com'])
		self.assertIsNotNone(sig)
		self.assertTrue(hasattr(sig, 'id'))

	def test_run_workflow_celery_task(self):
		"""Test run_workflow Celery task with config as TemplateLoader."""
		from secator.celery import start_runner
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# Create a signature with config as TemplateLoader
		sig = start_runner.s(
			config=config,
			targets=['example.com'],
			results=[],
			run_opts={'dry_run': True},
			hooks={},
			context={}
		)
		self.assertIsNotNone(sig)

	def test_run_scan_celery_task(self):
		"""Test run_scan Celery task with config as TemplateLoader."""
		from secator.celery import start_runner
		from secator.loader import get_configs_by_type

		scans = get_configs_by_type('scan')
		if not scans:
			self.skipTest('No scans configured')

		config = scans[0]

		# Create a signature with config as TemplateLoader
		sig = start_runner.s(
			config=config,
			targets=['example.com'],
			results=[],
			run_opts={'dry_run': True},
			hooks={},
			context={}
		)
		self.assertIsNotNone(sig)

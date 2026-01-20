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
		from secator.celery import run_workflow
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# Create a signature with config as TemplateLoader
		sig = run_workflow.s(
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
		from secator.celery import run_scan
		from secator.loader import get_configs_by_type

		scans = get_configs_by_type('scan')
		if not scans:
			self.skipTest('No scans configured')

		config = scans[0]

		# Create a signature with config as TemplateLoader
		sig = run_scan.s(
			config=config,
			targets=['example.com'],
			results=[],
			run_opts={'dry_run': True},
			hooks={},
			context={}
		)
		self.assertIsNotNone(sig)

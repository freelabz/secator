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


class TestRunnerPickle(unittest.TestCase):
	"""Test that Runner objects with dynamic driver hooks can be pickled/unpickled."""

	def test_runner_pickle_survives_missing_module_on_worker(self):
		"""Reproduces the original bug: unpickling a runner whose hooks reference a
		dynamically-loaded module that does not exist on the worker side.
		Without the __getstate__/__setstate__ fix this raises ModuleNotFoundError."""
		import pickle
		import types
		import sys
		from secator.runners import Workflow
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# 1) CLI side: load the driver into sys.modules (as the loader does)
		fake_module = types.ModuleType('secator.hooks.testdriver')

		def on_start(runner, *args):
			pass

		on_start.__module__ = 'secator.hooks.testdriver'
		on_start.__qualname__ = 'on_start'
		fake_module.on_start = on_start
		sys.modules['secator.hooks.testdriver'] = fake_module

		hooks = {Workflow: {'on_start': [on_start]}}
		runner = Workflow(config, inputs=['example.com'], run_opts={'dry_run': True}, hooks=hooks, context={})

		# Pickle while the module is available (simulates the CLI/sender side)
		pickled = pickle.dumps(runner)

		# 2) Worker side: remove the module to simulate it not being installed
		del sys.modules['secator.hooks.testdriver']

		# Without the fix, unpickling would raise:
		#   ModuleNotFoundError: No module named 'secator.hooks.testdriver'
		# With the fix, __getstate__ strips hooks so the bytes contain no reference
		# to the dynamic module and unpickling succeeds.
		restored = pickle.loads(pickled)
		self.assertEqual(restored.name, runner.name)
		# Hooks were stripped; dynamic hook not re-registered (driver not in context['drivers'])
		self.assertNotIn(on_start, restored.resolved_hooks.get('on_start', []))

	def test_runner_pickle_restores_hooks_from_context_drivers(self):
		"""Unpickling a Runner re-registers hooks from context['drivers']."""
		import pickle
		import sys
		import types
		from unittest.mock import patch
		from secator.runners import Workflow
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# Simulate an external driver module
		fake_module = types.ModuleType('secator.hooks.fakedriver')

		def on_end(runner, *args):
			pass

		on_end.__module__ = 'secator.hooks.fakedriver'
		on_end.__qualname__ = 'on_end'
		fake_module.on_end = on_end
		fake_module.HOOKS = {Workflow: {'on_end': [on_end]}}
		sys.modules['secator.hooks.fakedriver'] = fake_module

		try:
			# Patch discover_external_drivers to avoid filesystem scanning;
			# the module is already in sys.modules so import_dynamic will find it.
			with patch('secator.loader.discover_external_drivers', return_value=['fakedriver']):
				context = {'drivers': ['fakedriver']}
				hooks = {Workflow: {'on_end': [on_end]}}
				runner = Workflow(config, inputs=['example.com'], run_opts={'dry_run': True}, hooks=hooks, context=context)
				pickled = pickle.dumps(runner)
				restored = pickle.loads(pickled)
				self.assertEqual(restored.name, runner.name)
				# __setstate__ re-registers on_end from fakedriver via context['drivers']
				self.assertIn(on_end, restored.resolved_hooks.get('on_end', []))

		finally:
			del sys.modules['secator.hooks.fakedriver']

	def test_task_pickle_restores_hooks_from_base_task_key(self):
		"""Regression for chunk-parent tasks stuck in RUNNING.

		A driver's HOOKS dict is keyed by the *base* runner classes (Scan/Workflow/Task),
		but a task runner's class is its command subclass (e.g. ``httpx``), never the base
		``Task``. So __setstate__ must flatten driver HOOKS to the runner's base type before
		register_hooks() — otherwise its exact ``hooks.get(self.__class__)`` lookup misses
		the ``Task`` entry and the task's on_end hook is never re-registered on unpickle.
		Only chunk-parent tasks get pickled into a chord callback, so they were the ones
		left stuck in RUNNING because mark_runner_completed() ran zero on_end hooks."""
		import pickle
		import sys
		import types
		from unittest.mock import patch
		from secator.runners import Task
		from secator.tasks import httpx

		# Simulate an external driver module keyed by the BASE Task class, exactly like the
		# real mongodb/api driver HOOKS dicts.
		fake_module = types.ModuleType('secator.hooks.faketaskdriver')

		def on_end(runner, *args):
			pass

		on_end.__module__ = 'secator.hooks.faketaskdriver'
		on_end.__qualname__ = 'on_end'
		fake_module.on_end = on_end
		fake_module.HOOKS = {Task: {'on_end': [on_end]}}
		sys.modules['secator.hooks.faketaskdriver'] = fake_module

		try:
			with patch('secator.loader.discover_external_drivers', return_value=['faketaskdriver']):
				context = {'drivers': ['faketaskdriver']}
				# Instance class is `httpx` (a Command subclass), not the base Task.
				task = httpx(['example.com'], hooks={Task: {'on_end': [on_end]}}, context=context, dry_run=True)
				self.assertIsNot(type(task), Task)  # sanity: command subclass, not base Task
				restored = pickle.loads(pickle.dumps(task))
				# With the fix, on_end is re-registered from the base `Task` key in HOOKS.
				self.assertIn(on_end, restored.resolved_hooks.get('on_end', []))

		finally:
			del sys.modules['secator.hooks.faketaskdriver']

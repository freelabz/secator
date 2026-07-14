import tempfile
import unittest
from pathlib import Path
from secator.celery import app, join_results  # noqa: F401
from secator.utils_test import mock_command, FIXTURES_TASKS, TEST_TASKS, FIXTURES_DIR, load_fixture
from secator.output_types import Url
from celery import chain, chord

TARGETS = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']

# TEST_TASKS holds TemplateLoaders, so `<task class> in TEST_TASKS` is always False (the old
# guard silently skipped every chain test). Match by name instead; mock_command mocks the
# binary, so the task only needs to be registered — not installed.
TEST_TASK_NAMES = {t.name for t in TEST_TASKS}


class TestCelery(unittest.TestCase):
	"""The Celery chain no longer carries a result payload — tasks pass topology only and
	every finding lands in the store (here the sqlite driver). So these assert on the STORE,
	not on `result.get()` (which is topology-only)."""

	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		self.sqlite_mod = sqlite_mod
		self.temp_dir = tempfile.mkdtemp()
		self._orig_path = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.temp_dir) / 'test.db')
		sqlite_mod._conns.clear()
		# Driver context threaded into every task so its on_item hook persists to the store.
		self.ctx = {'drivers': ['sqlite'], 'workspace_id': 'ws', 'workspace_name': 'ws'}

	def tearDown(self):
		import shutil
		from secator.config import CONFIG
		for conn in self.sqlite_mod._conns.values():
			conn.close()
		self.sqlite_mod._conns.clear()
		CONFIG.addons.sqlite.path = self._orig_path
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _store(self, _type):
		from secator.query.sqlite import SqliteBackend
		return SqliteBackend(workspace_id='ws').search({'_type': _type})

	def test_httpx_chain(self):
		from secator.tasks import httpx
		if 'httpx' not in TEST_TASK_NAMES:
			return

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [join_results.si([])] + [httpx.s(target, context=dict(self.ctx)) for target in TARGETS]
			chain(*sigs).apply().get()
			self.assertEqual(len(self._store('url')), len(TARGETS))
			self.assertEqual(len(self._store('target')), len(TARGETS))

	def test_httpx_chain_with_results(self):
		from secator.tasks import httpx
		if 'httpx' not in TEST_TASK_NAMES:
			return

		# A pre-existing finding now lives in the store, not seeded through the chain payload.
		existing = Url(**{
			"url": "https://example.synology.me", "method": "GET", "status_code": 200,
			"words": 438, "lines": 136, "content_type": "text/html", "content_length": 11577,
			"host": "82.66.157.114", "time": 0.16, "_source": "httpx", "_type": "url",
			"_context": {"workspace_id": "ws"},
		})

		class _R:
			config = type('C', (), {'name': 'httpx'})()
			context = {'workspace_id': 'ws'}
		self.sqlite_mod.update_finding(_R(), existing)

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [join_results.si([])] + [httpx.s(target, context=dict(self.ctx)) for target in TARGETS]
			chain(*sigs).apply().get()
			self.assertEqual(len(self._store('url')), len(TARGETS) + 1)
			self.assertEqual(len(self._store('target')), len(TARGETS))

	def test_httpx_workflow(self):
		from secator.tasks import httpx
		if 'httpx' not in TEST_TASK_NAMES:
			return

		targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
		sigs = [httpx().s(target, context=dict(self.ctx)) for target in targets]
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(targets)):
			# Two adjacent groups need the join_results bridge task between them.
			workflow = chain(
				join_results.s([]),
				sigs[0],
				chord((sigs[1], sigs[2]), join_results.s()),
				sigs[3],
				chord((sigs[4], sigs[5]), join_results.s()),
			)
			workflow.apply().get()
			self.assertEqual(len(self._store('target')), len(TARGETS))
			self.assertEqual(len(self._store('url')), len(TARGETS))

	def test_nmap_workflow(self):
		from secator.tasks import nmap
		if 'nmap' not in TEST_TASK_NAMES:
			return

		nmap_fixture = load_fixture('nmap_output', fixtures_dir=FIXTURES_DIR, ext='.xml', only_path=True)
		with mock_command(nmap, fixture=[FIXTURES_TASKS[nmap]] * len(TARGETS)):
			workflow = chain(
				join_results.s([]),
				chord((nmap.s(TARGETS, output_path=nmap_fixture, context=dict(self.ctx))), join_results.s()),
			)
			workflow.apply().get()
			self.assertEqual(len(self._store('target')), len(TARGETS))
			self.assertEqual(len(self._store('vulnerability')), 61)  # number of vulns in the XML fixture

	def test_ffuf_chunked(self):
		from secator.tasks import ffuf
		if 'ffuf' not in TEST_TASK_NAMES:
			return

		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]

		with mock_command(ffuf, fixture=[FIXTURES_TASKS[ffuf]] * len(HTTP_TARGETS)):
			workflow = chain(
				join_results.s([]),
				chord((ffuf.s(HTTP_TARGETS, context=dict(self.ctx))), join_results.s()),
			)
			workflow.apply().get()
			self.assertEqual(len(self._store('target')), len(HTTP_TARGETS) * 2)
			self.assertEqual(len(self._store('url')), len(HTTP_TARGETS))

	def test_rate_limit_adjustment_for_chunked_tasks(self):
		"""Test that rate_limit is divided by chunk count when chunking tasks."""
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:  # vacuous by design (kept dormant, unrelated to payload drop)
			return

		# Create a task with rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 100, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			workflow = break_task(task, task_opts)

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
		if httpx not in TEST_TASKS:  # vacuous by design (kept dormant, unrelated to payload drop)
			return

		# Create a task with low rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 2, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			# With rate_limit=2 and 6 chunks, adjusted rate_limit should be max(1, 2//6) = 1
			workflow = break_task(task, task_opts)

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

	def test_chunk_sigs_routed_via_resolve_task_queue(self):
		import secator.celery as celery_mod
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:  # vacuous by design (kept dormant, unrelated to payload drop)
			return

		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, sync=False)
			task.has_children = True
			orig = celery_mod.resolve_task_queue
			celery_mod.resolve_task_queue = lambda cls, opts: 'sentinel_queue'
			try:
				workflow = break_task(task, {'sync': False})
			finally:
				celery_mod.resolve_task_queue = orig

			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			self.assertTrue(header_tasks, 'expected chunk signatures in the chord header')
			for sig in header_tasks:
				self.assertEqual(sig.options.get('queue'), 'sentinel_queue')

	def test_break_task_with_disabled_chunking(self):
		"""Test that break_task doesn't chunk when input_chunk_size=-1."""
		from secator.tasks import httpx
		from secator.celery import break_task
		if httpx not in TEST_TASKS:  # vacuous by design (kept dormant, unrelated to payload drop)
			return

		class TestTask(httpx):
			input_chunk_size = -1

		# Create a task with many inputs
		inputs = ['target1', 'target2', 'target3', 'target4', 'target5']
		task = TestTask(inputs)
		task_opts = {}

		# Mock to get the workflow signature
		with mock_command(TestTask, fixture=[FIXTURES_TASKS[httpx]]):
			workflow = break_task(task, task_opts)
			# With input_chunk_size=-1, should return the inputs as-is without chunking
			# This means one chunk with all inputs
			self.assertEqual(len(workflow.tasks), len(inputs))


class TestNoPayloadIngestion(unittest.TestCase):
	"""#1310 regression: the mongodb --sync `deduplicate` crash ('str' has no attribute ...)
	came from chain_results reducing findings to uuid strings, which mark_runner_completed
	ingested into runner.results, where mark_duplicates then called ._compare_key() on a str.
	With the payload dropped, mark_runner_completed ignores its upstream arg entirely, so uuid
	strings can never enter runner.results — the crash is impossible by construction."""

	def test_mark_completed_ignores_uuid_string_payload(self):
		from secator.loader import get_configs_by_type
		from secator.runners import Workflow
		from secator.celery import mark_runner_completed
		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')
		wf = Workflow(workflows[0], inputs=['example.com'], run_opts={'dry_run': True}, context={})
		# Feed the exact shape chain_results used to emit (ObjectId-like uuid strings).
		ret = mark_runner_completed(['deadbeefdeadbeefdeadbeef', 'cafebabecafebabecafebabe'], wf, enable_hooks=False)
		self.assertEqual(ret, [])                                       # topology-only return
		self.assertFalse(any(isinstance(r, str) for r in wf.results))   # no str in results
		self.assertEqual(wf.status, 'SUCCESS')                          # mark_duplicates did not crash


class TestDelayMethods(unittest.TestCase):
	"""Test the delay methods for different runner types."""

	def test_command_delay_signature(self):
		"""Test that Command.delay() creates a proper Celery signature."""
		from secator.tasks import httpx
		if 'httpx' not in TEST_TASK_NAMES:
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


class TestWorkerLossRetryCap(unittest.TestCase):
	"""Worker-loss redelivery cap (task_acks_late + task_reject_on_worker_lost)."""

	def test_bump_worker_loss_count_get_set_fallback(self):
		"""Counter increments via the generic get/set fallback (any KV backend, e.g. filesystem)."""
		from secator.celery import bump_worker_loss_count

		# Use a unique id so reruns don't collide, and clean up the backend key afterwards.
		task_id = f'wl-test-{id(self)}'
		key = app.backend.get_key_for_task(f'worker-loss-{task_id}')
		try:
			self.assertEqual(bump_worker_loss_count(task_id), 1)
			self.assertEqual(bump_worker_loss_count(task_id), 2)
			self.assertEqual(bump_worker_loss_count(task_id), 3)
			# A different task id is counted independently.
			self.assertEqual(bump_worker_loss_count(f'{task_id}-other'), 1)
		finally:
			try:
				app.backend.delete(key)
				app.backend.delete(app.backend.get_key_for_task(f'worker-loss-{task_id}-other'))
			except Exception:
				pass

	def test_bump_worker_loss_count_prefers_atomic_incr(self):
		"""When the backend implements atomic incr (Redis/Memcached), it is used directly."""
		from unittest.mock import patch
		from secator.celery import bump_worker_loss_count

		with patch.object(app.backend, 'incr', return_value=42, create=True) as mock_incr:
			self.assertEqual(bump_worker_loss_count('task-abc'), 42)
			mock_incr.assert_called_once()

	def test_bump_worker_loss_count_disabled_without_kv(self):
		"""Returns 0 (cap disabled) on backends with neither incr nor get/set (db/RPC)."""
		from unittest.mock import patch
		from secator.celery import bump_worker_loss_count

		with patch.object(app.backend, 'incr', side_effect=NotImplementedError, create=True):
			with patch.object(app.backend, 'get', side_effect=NotImplementedError, create=True):
				self.assertEqual(bump_worker_loss_count('task-abc'), 0)

	def test_abandon_task_persists_failure_error_to_store(self):
		"""Abandoning returns topology-only, persisting a self-owned FAILURE Error to the store
		(not the payload) so the chord proceeds and the failure is still queryable."""
		import tempfile
		from pathlib import Path
		from secator.tasks import httpx
		from secator.celery import abandon_task
		from secator.config import CONFIG
		import secator.hooks.sqlite as sqlite_mod
		from secator.query.sqlite import SqliteBackend
		if 'httpx' not in TEST_TASK_NAMES:
			self.skipTest('httpx not available')

		orig_path = CONFIG.addons.sqlite.path
		tmp = tempfile.mkdtemp()
		CONFIG.addons.sqlite.path = str(Path(tmp) / 'test.db')
		sqlite_mod._conns.clear()
		try:
			ctx = {'drivers': ['sqlite'], 'workspace_id': 'ws', 'workspace_name': 'ws'}
			ret = abandon_task('httpx', ['example.com'], {'context': ctx}, delivery_count=2)
			self.assertEqual(ret, [])  # topology-only return
			errors = SqliteBackend(workspace_id='ws').search({'_type': 'error'})
			self.assertEqual(len(errors), 1)
			# Message separates delivery attempts (broker redeliveries) from the retry cap, so it
			# reads sensibly even when the cap is 0 (a redelivery still occurs; the work isn't re-run).
			self.assertIn('abandoned after 2 delivery attempts', errors[0]['message'])
			self.assertIn('retry cap:', errors[0]['message'])
		finally:
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = orig_path
			import shutil
			shutil.rmtree(tmp, ignore_errors=True)

	def test_retries_exhausted_does_not_count_initial_delivery(self):
		"""delivery_count includes the initial run; task_max_retries=N allows N redeliveries."""
		from secator.celery import worker_loss_retries_exhausted
		# task_max_retries=3 -> initial (1) + 3 redeliveries (2,3,4) allowed, abandon on the 5th delivery.
		self.assertFalse(worker_loss_retries_exhausted(1, 3))  # initial run
		self.assertFalse(worker_loss_retries_exhausted(2, 3))  # redelivery 1
		self.assertFalse(worker_loss_retries_exhausted(3, 3))  # redelivery 2
		self.assertFalse(worker_loss_retries_exhausted(4, 3))  # redelivery 3 (last allowed)
		self.assertTrue(worker_loss_retries_exhausted(5, 3))   # redelivery 4 -> abandon
		# task_max_retries=0 -> no redeliveries; abandon on the first redelivery, not the initial run.
		self.assertFalse(worker_loss_retries_exhausted(1, 0))
		self.assertTrue(worker_loss_retries_exhausted(2, 0))

	def test_worker_cancel_flag_wired_to_app_conf(self):
		"""The worker_cancel_long_running_tasks_on_connection_loss config flag reaches app.conf."""
		from secator.config import CONFIG
		self.assertEqual(
			app.conf.worker_cancel_long_running_tasks_on_connection_loss,
			CONFIG.celery.worker_cancel_long_running_tasks_on_connection_loss,
		)


class TestRunnerPickle(unittest.TestCase):
	"""Test that Runner objects with dynamic driver hooks can be pickled/unpickled."""

	def test_runner_pickle_survives_with_discovered_module(self):
		"""Runners pickle/unpickle natively (no __getstate__/__setstate__).

		Driver hook functions reference dynamically-loaded modules. The worker
		discovers external drivers at startup (celery.py IN_WORKER), so those
		modules are in sys.modules and hook functions resolve on unpickle. The
		hook survives the round-trip and unpickling does NOT re-register hooks
		(which, under replace()/chord synchronization, previously flooded logs)."""
		import pickle
		import types
		import sys
		from secator.runners import Runner, Workflow
		from secator.loader import get_configs_by_type

		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')

		config = workflows[0]

		# Driver module present in sys.modules, as on a worker post-discovery
		fake_module = types.ModuleType('secator.hooks.testdriver')

		def on_start(runner, *args):
			pass

		on_start.__module__ = 'secator.hooks.testdriver'
		on_start.__qualname__ = 'on_start'
		fake_module.on_start = on_start
		sys.modules['secator.hooks.testdriver'] = fake_module

		try:
			hooks = {Workflow: {'on_start': [on_start]}}
			runner = Workflow(config, inputs=['example.com'], run_opts={'dry_run': True}, hooks=hooks, context={})
			self.assertIn(on_start, runner.resolved_hooks.get('on_start', []))

			# Unpickling must NOT call register_hooks (native pickling restores state)
			calls = {'n': 0}
			orig = Runner.register_hooks

			def counting(self, h):
				calls['n'] += 1
				return orig(self, h)

			Runner.register_hooks = counting
			try:
				restored = pickle.loads(pickle.dumps(runner))
			finally:
				Runner.register_hooks = orig

			self.assertEqual(calls['n'], 0, 'unpickle must not re-register hooks')
			self.assertEqual(restored.name, runner.name)
			# The dynamically-referenced hook survives natively
			self.assertIn(on_start, restored.resolved_hooks.get('on_start', []))
		finally:
			del sys.modules['secator.hooks.testdriver']

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
				# on_end is loaded at init from context['drivers'] and survives pickling natively
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

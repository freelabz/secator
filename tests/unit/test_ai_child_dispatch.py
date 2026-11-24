"""Where an AI run's child runners execute when the AI task runs inside a worker."""
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from celery import signals

from secator import celery_signals
from secator.ai import utils
from secator.ai.tools import _runner
from secator.ai.utils import _is_heavy_runner
from secator.celery import app


@app.task
def _noop():
	return []


class TestIsHeavyRunner(unittest.TestCase):

	@contextmanager
	def _cfg(self, profiles=('large', 'extra_large'), max_targets=10):
		ai = utils.CONFIG.addons.ai
		prev = ai.dispatch_profiles, ai.inline_max_targets
		ai.dispatch_profiles, ai.inline_max_targets = list(profiles), max_targets
		try:
			yield
		finally:
			ai.dispatch_profiles, ai.inline_max_targets = prev

	def test_workflow_always_dispatched(self):
		with self._cfg():
			self.assertTrue(_is_heavy_runner('workflow', 'host_recon', {}, ['a']))

	def test_small_task_runs_inline(self):
		with self._cfg():
			self.assertFalse(_is_heavy_runner('task', 'httpx', {}, ['a']))
			# several targets, but one run through the input-file flag: no chunking
			self.assertFalse(_is_heavy_runner('task', 'httpx', {}, ['a', 'b']))

	def test_heavy_profile_dispatched(self):
		with self._cfg():
			self.assertTrue(_is_heavy_runner('task', 'nuclei', {}, ['a']))
			self.assertTrue(_is_heavy_runner('task', 'httpx', {'screenshot': True}, ['a']))

	def test_profile_list_is_configurable(self):
		with self._cfg(profiles=['small']):
			self.assertTrue(_is_heavy_runner('task', 'nmap', {}, ['a']))

	def test_task_that_would_chunk_dispatched(self):
		with self._cfg():
			# nmap: input_chunk_size 1 -> one chunk per host
			self.assertFalse(_is_heavy_runner('task', 'nmap', {}, ['a']))
			self.assertTrue(_is_heavy_runner('task', 'nmap', {}, ['a', 'b']))
			# whois: no input-file flag -> one chunk per target
			self.assertTrue(_is_heavy_runner('task', 'whois', {}, ['a', 'b']))

	def test_chunk_size_override_is_honored(self):
		real = utils.CONFIG
		cfg = SimpleNamespace(addons=real.addons, tasks=SimpleNamespace(overrides={'httpx': {'input_chunk_size': 2}}))
		with self._cfg(), mock.patch.object(utils, 'CONFIG', cfg), mock.patch('secator.runners._helpers.CONFIG', cfg):
			self.assertFalse(_is_heavy_runner('task', 'httpx', {}, ['a', 'b']))
			self.assertTrue(_is_heavy_runner('task', 'httpx', {}, ['a', 'b', 'c']))

	def test_task_with_targets_extractor_dispatched(self):
		with self._cfg():
			self.assertTrue(_is_heavy_runner('task', 'httpx', {'targets_': [{'type': 'url', 'field': 'url'}]}, ['a']))

	def test_runtime_chunk_rule_dispatched(self):
		with self._cfg():
			# fping takes a file of hosts, but a CIDR range runs alone (-g): one chunk per target
			self.assertFalse(_is_heavy_runner('task', 'fping', {}, ['10.0.0.1', '10.0.0.2']))
			self.assertTrue(_is_heavy_runner('task', 'fping', {}, ['10.0.0.0/30', '10.0.0.2']))

	def test_many_targets_dispatched(self):
		with self._cfg(max_targets=3):
			self.assertFalse(_is_heavy_runner('task', 'httpx', {}, ['a', 'b', 'c']))
			self.assertTrue(_is_heavy_runner('task', 'httpx', {}, ['a', 'b', 'c', 'd']))

	def test_subagent_runs_inline(self):
		with self._cfg(max_targets=1):
			self.assertFalse(_is_heavy_runner('task', 'ai', {}, ['a', 'b', 'c']))

	def test_unknown_task_inline(self):
		with self._cfg():
			self.assertFalse(_is_heavy_runner('task', 'not_a_task', {}, ['a']))


class TestChunkingRuleShared(unittest.TestCase):
	"""The ai dispatch rule and the runners' needs_chunking() use one chunking rule."""

	# The rules needs_chunking() inlined before they moved to chunking_needed(), copied verbatim
	# (secator/runners/command.py and secator/runners/python.py), as the reference.
	@staticmethod
	def _legacy_command(inputs, sync, input_chunk_size, file_flag, chunk):
		many_targets = len(inputs) > 1
		targets_over_chunk_size = input_chunk_size and input_chunk_size != -1 and len(inputs) > input_chunk_size  # noqa: E501
		has_file_flag = file_flag is not None
		is_chunk = chunk
		chunk_it = (sync and many_targets and not has_file_flag and not is_chunk) or (not sync and many_targets and targets_over_chunk_size and not is_chunk)  # noqa: E501
		return chunk_it

	@staticmethod
	def _legacy_python(inputs, sync, input_chunk_size, chunk):
		many_targets = len(inputs) > 1
		targets_over_chunk_size = input_chunk_size and input_chunk_size != -1 and len(inputs) > input_chunk_size  # noqa: E501
		is_chunk = chunk
		chunk_it = (sync and many_targets and not is_chunk) or (not sync and many_targets and targets_over_chunk_size and not is_chunk)  # noqa: E501
		return chunk_it

	def test_chunking_needed_matches_previous_rule(self):
		"""Truth table: chunking_needed() agrees with both previous inline rules on every
		combination (callers only use the result's truthiness)."""
		from itertools import product
		from secator.runners._helpers import chunking_needed
		combos = 0
		for count, sync, size, flag, chunk in product(
				range(0, 25), (True, False, 1, 0, None), (None, 0, -1, 1, 2, 5, 20, 100),
				(None, '', '-l'), (None, False, 0, 1, True)):
			inputs = [f'h{i}' for i in range(count)]
			combos += 1
			with self.subTest(count=count, sync=sync, size=size, flag=flag, chunk=chunk):
				self.assertEqual(
					bool(chunking_needed(count, sync, size, flag, chunk)),
					bool(self._legacy_command(inputs, sync, size, flag, chunk)))
				self.assertEqual(
					bool(chunking_needed(count, sync, size, is_chunk=chunk)),
					bool(self._legacy_python(inputs, sync, size, chunk)))
		self.assertEqual(combos, 25 * 5 * 8 * 3 * 5)

	def test_would_chunk_honors_overrides(self):
		from secator.runners import Task
		cls = Task.get_task_class('httpx')
		cfg = SimpleNamespace(tasks=SimpleNamespace(overrides={'httpx': {'file_flag': None, 'input_chunk_size': 2}}))
		self.assertFalse(cls.would_chunk(['a', 'b'], sync=True))
		with mock.patch('secator.runners._helpers.CONFIG', cfg):
			self.assertTrue(cls.would_chunk(['a', 'b'], sync=True))
			self.assertTrue(cls.would_chunk(['a', 'b', 'c'], sync=False))
			self.assertFalse(cls.would_chunk(['a', 'b'], sync=False))

	def test_would_chunk_follows_runtime_rule(self):
		# fping: a CIDR range is passed with -g, one range per run
		from secator.runners import Task
		cls = Task.get_task_class('fping')
		self.assertFalse(cls.would_chunk(['10.0.0.1', '10.0.0.2'], sync=True))
		self.assertTrue(cls.would_chunk(['10.0.0.0/30', '10.0.0.2'], sync=True))
		self.assertTrue(cls.would_chunk(['10.0.0.0/30', '10.0.0.2'], sync=False))
		self.assertFalse(cls.would_chunk(['10.0.0.0/30', '10.0.0.0/30'], sync=False))


class TestWouldChunkParity(unittest.TestCase):
	"""``would_chunk`` (the task class, before the child exists) agrees with ``needs_chunking`` on
	the runner built from the same inputs, opts and ``tasks.overrides``, for every task.

	Exact whenever every input is of a type the task takes. Otherwise the built runner drops the
	unsupported inputs after its hooks ran, and ``would_chunk`` (which counts them) may only say
	yes where the runner says no: it never misses a runner that chunks.
	"""

	CASES = {
		'one host': ['example.com'],
		'hosts': ['a.example.com', 'b.example.com', 'c.example.com'],
		'duplicates': ['a.example.com', 'a.example.com'],
		'urls': ['http://a.example.com', 'https://b.example.com/x'],
		'ips': ['10.0.0.1', '10.0.0.2'],
		'one cidr': ['10.0.0.0/30'],
		'cidrs': ['10.0.0.0/30', '10.0.1.0/30'],
		'cidr and ip': ['10.0.0.0/30', '10.0.0.5'],
		'mixed': ['10.0.0.0/30', '10.0.0.5', 'example.com', 'http://example.com/a'],
		'host then url': ['a.example.com', 'http://b.example.com'],
		'over chunk size': [f'h{i}.example.com' for i in range(25)],
		'over chunk size, urls': [f'http://h{i}.example.com' for i in range(25)],
		'emails': ['a@example.com', 'b@example.com'],
	}
	OVERRIDES = (
		{},
		{'input_chunk_size': 2},
		{'file_flag': None},
		{'file_flag': '-x', 'input_chunk_size': -1},
	)
	# Options a task's runtime chunking depends on (see runtime_chunk_attrs / before_init).
	TASK_OPTS = {
		'dnsx': ({'wordlist': 'words.txt'}, {'wordlist': 'words.txt', 'wildcard_domain': 'example.com'}),
	}

	@classmethod
	def setUpClass(cls):
		import tempfile
		cls._tmp = tempfile.TemporaryDirectory()
		paths = []
		for name in ('a.txt', 'b.txt'):
			path = f'{cls._tmp.name}/{name}'
			open(path, 'w').close()
			paths.append(path)
		cls.CASES = dict(cls.CASES, paths=paths, folder=[cls._tmp.name])

	@classmethod
	def tearDownClass(cls):
		cls._tmp.cleanup()

	def test_every_task(self):
		from secator.loader import discover_tasks
		from secator.runners import Runner
		from secator.utils import autodetect_type
		tasks = discover_tasks()
		self.assertGreater(len(tasks), 30)
		checked = exact = 0
		with (
			# Driver hooks persist runner state; they never touch inputs or chunk attributes.
			mock.patch.object(Runner, '_apply_context_drivers', lambda self: None),
			# No network / downloads while building: dnsx probes wildcard DNS, wordlists download.
			mock.patch('secator.tasks.dnsx.check_dns_response', return_value=False),
			mock.patch('secator.utils.download_file', side_effect=lambda val, **_: val),
		):
			for task_cls in tasks:
				name = task_cls.__name__
				for overrides in self.OVERRIDES:
					cfg = SimpleNamespace(tasks=SimpleNamespace(overrides={name: overrides}))
					with mock.patch('secator.runners._helpers.CONFIG', cfg):
						for opts in ({},) + self.TASK_OPTS.get(name, ()):
							for case, inputs in self.CASES.items():
								runner = task_cls(
									list(inputs), sync=True, print_line=False, print_item=False, quiet=True, **opts)
								supported = all(
									not task_cls.input_types or autodetect_type(i) in task_cls.input_types for i in inputs)
								for sync in (True, False):
									with self.subTest(task=name, case=case, opts=opts, overrides=overrides, sync=sync):
										predicted = task_cls.would_chunk(list(inputs), sync, opts)
										built = bool(runner.needs_chunking(sync))
										checked += 1
										if supported:
											exact += 1
											self.assertEqual(predicted, built)
										else:
											self.assertTrue(predicted or not built, 'would_chunk missed a runner that chunks')
		self.assertGreater(exact, checked // 4)

	def test_runtime_chunk_changes_are_declared(self):
		"""A task that changes input_chunk_size / file_flag at runtime declares the rule in
		runtime_chunk_attrs, so would_chunk sees it."""
		import inspect
		import re
		from secator.loader import discover_tasks
		from secator.runners import Command
		# dnsx: a wordlist switches the input flag to -d; it keeps a file flag and its chunk size,
		# so chunking is unchanged (covered by test_every_task with a wordlist).
		unchanged = {'dnsx'}
		for task_cls in discover_tasks():
			if not issubclass(task_cls, Command) or task_cls.__name__ in unchanged:
				continue
			source = inspect.getsource(task_cls)
			if re.search(r'self\.(file_flag|input_chunk_size)\s*=', source):
				with self.subTest(task=task_cls.__name__):
					self.assertIsNot(
						task_cls.runtime_chunk_attrs.__func__, Command.runtime_chunk_attrs.__func__)


class TestRunRunnerDispatch(unittest.TestCase):

	def _run(self, targets, in_worker=True, fail=False):
		"""Drive _run_runner on a fake child; returns (generator, child runner, run_opts)."""
		child = mock.MagicMock(done=False, reports_folder=None)

		def items():
			yield 'x'
			if fail:
				raise RuntimeError('boom')
			yield 'y'
		child.__iter__.side_effect = lambda: items()
		ctx = SimpleNamespace(
			targets=targets, encryptor=None, dry_run=False, silent=True, subagent=False, sync=True,
			verbose=False, isolated=False, dangerous=False, in_scope=None, out_of_scope=None,
			permission_engine=None)
		action = {'name': 'nmap', 'targets': targets}
		patches = [
			mock.patch.object(_runner, '_get_result_context', return_value={}),
			mock.patch.object(_runner, '_child_preamble', return_value=({}, None)),
			mock.patch.object(_runner, 'Task', mock.MagicMock(return_value=child)),
			mock.patch('secator.celery.IN_WORKER', in_worker),
		]
		for p in patches:
			p.start()
			self.addCleanup(p.stop)
		gen = _runner._run_runner(action, ctx, 'task')
		next(gen)  # the runner card
		return gen, child, _runner.Task.call_args.kwargs['run_opts']

	def test_wide_task_dispatched_in_worker(self):
		gen, child, run_opts = self._run(['a', 'b'])
		self.assertFalse(run_opts['sync'])
		self.assertEqual(list(gen), ['x', 'y'])
		child.stop_celery_tasks.assert_not_called()

	def test_single_target_runs_in_process(self):
		_, _, run_opts = self._run(['a'])
		self.assertTrue(run_opts['sync'])

	def test_not_dispatched_outside_worker(self):
		_, _, run_opts = self._run(['a', 'b'], in_worker=False)
		self.assertTrue(run_opts['sync'])

	def test_dispatched_child_revoked_when_parent_stops_following(self):
		gen, child, _ = self._run(['a', 'b'])
		next(gen)
		gen.close()
		child.stop_celery_tasks.assert_called_once()

	def test_dispatched_child_revoked_on_error(self):
		gen, child, _ = self._run(['a', 'b'], fail=True)
		with self.assertRaises(RuntimeError):
			list(gen)
		child.stop_celery_tasks.assert_called_once()


class TestPostrunEagerChild(unittest.TestCase):
	"""An in-process (eager) child task fires task_postrun in the worker's own process, whatever
	the pool type: it must not end the outer task's bookkeeping."""

	def _apply(self, eager):
		seen = []

		def record(task=None, **_):
			seen.append(task.request.is_eager)
		signals.task_postrun.connect(record, weak=False)
		signals.task_postrun.connect(celery_signals.task_postrun_handler, weak=False)
		self.addCleanup(signals.task_postrun.disconnect, record)
		self.addCleanup(signals.task_postrun.disconnect, celery_signals.task_postrun_handler)
		with (
			mock.patch.object(celery_signals, 'kill_worker') as kill,
			mock.patch.object(celery_signals, 'clear_task_running') as clear,
			mock.patch.object(celery_signals, 'IDLE_TIMEOUT', -1),
			mock.patch.object(celery_signals.CONFIG.celery, 'worker_kill_after_task', True),
		):
			if eager:
				_noop.apply()
			else:
				task = SimpleNamespace(name='secator.celery.run_command', request=SimpleNamespace(is_eager=False))
				celery_signals.task_postrun_handler(sender=task, task=task)
		return seen, kill, clear

	def test_eager_child_fires_postrun_but_keeps_worker(self):
		seen, kill, clear = self._apply(eager=True)
		self.assertEqual(seen, [True])
		kill.assert_not_called()
		clear.assert_not_called()

	def test_worker_task_kills_worker_after_task(self):
		# the worker's main process is the parent only when the task ran in a prefork pool child
		for pool_child in (True, False):
			with mock.patch.object(celery_signals, 'in_pool_child', return_value=pool_child):
				_, kill, clear = self._apply(eager=False)
			clear.assert_called_once()
			kill.assert_called_once_with(parent=pool_child)

	def test_main_process_is_not_a_pool_child(self):
		self.assertFalse(celery_signals.in_pool_child())


if __name__ == '__main__':
	unittest.main()

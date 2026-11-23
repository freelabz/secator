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

	@staticmethod
	def _legacy(count, sync, chunk_size, file_flag, is_chunk):
		# The rule needs_chunking() inlined before it was moved to chunking_needed().
		many = count > 1
		over = chunk_size and chunk_size != -1 and count > chunk_size
		return bool((sync and many and file_flag is None and not is_chunk) or (not sync and many and over and not is_chunk))

	def test_chunking_needed_matches_previous_rule(self):
		from itertools import product
		from secator.runners._helpers import chunking_needed
		for count, sync, size, flag, is_chunk in product(
				(0, 1, 2, 5, 101), (True, False), (None, 0, -1, 1, 2, 100), (None, '-l'), (None, 1)):
			with self.subTest(count=count, sync=sync, size=size, flag=flag, is_chunk=is_chunk):
				self.assertEqual(
					chunking_needed(count, sync, size, flag, is_chunk),
					self._legacy(count, sync, size, flag, is_chunk))

	def test_would_chunk_matches_needs_chunking_on_built_task(self):
		from secator.runners import Task
		for name in ('nmap', 'httpx', 'whois', 'dnsx', 'search_vulns'):
			cls = Task.get_task_class(name)
			for targets in (['a.com'], ['a.com', 'b.com'], [f'h{i}.com' for i in range(120)]):
				task = cls(targets, sync=True, print_line=False, print_item=False, enable_hooks=False)
				for sync in (True, False):
					with self.subTest(task=name, n=len(targets), sync=sync):
						self.assertEqual(cls.would_chunk(len(targets), sync), task.needs_chunking(sync))

	def test_would_chunk_honors_overrides(self):
		from secator.runners import Task
		cls = Task.get_task_class('httpx')
		cfg = SimpleNamespace(tasks=SimpleNamespace(overrides={'httpx': {'file_flag': None, 'input_chunk_size': 2}}))
		self.assertFalse(cls.would_chunk(2, sync=True))
		with mock.patch('secator.runners._helpers.CONFIG', cfg):
			self.assertTrue(cls.would_chunk(2, sync=True))
			self.assertTrue(cls.would_chunk(3, sync=False))
			self.assertFalse(cls.would_chunk(2, sync=False))


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

# tests/unit/test_ai_setup_local.py

"""Tests ensuring `secator x ai setup` always runs locally, never on a worker."""

import unittest
from contextlib import ExitStack
from unittest import mock

from click.testing import CliRunner


class TestRequiresLocalExecution(unittest.TestCase):
	"""Unit tests for the requires_local_execution hook."""

	def test_base_runner_returns_false(self):
		from secator.runners._base import Runner
		self.assertFalse(Runner.requires_local_execution('setup', {}))
		self.assertFalse(Runner.requires_local_execution(['setup'], {}))

	def test_ai_setup_string(self):
		from secator.tasks.ai import ai
		self.assertTrue(ai.requires_local_execution('setup', {}))

	def test_ai_setup_list(self):
		from secator.tasks.ai import ai
		self.assertTrue(ai.requires_local_execution(['setup'], {}))

	def test_ai_non_setup(self):
		from secator.tasks.ai import ai
		self.assertFalse(ai.requires_local_execution('example.com', {}))
		self.assertFalse(ai.requires_local_execution([], {}))


class TestAiSetupForcesSync(unittest.TestCase):
	"""End-to-end: `x ai setup` runs sync even when a worker is alive."""

	def _run_with_worker_alive(self, inputs):
		"""Invoke `secator x <inputs>` with a worker mocked alive, capturing the runner's sync opt.

		CLI subcommands are generated at import time, so `runner_cls` is already bound to the
		real Task class. We patch methods on that class object (not the module name) so the
		already-bound reference picks up the stub.
		"""
		import secator.cli_helper as cli_helper
		from secator.cli import cli

		captured = {}

		def fake_init(self, config, inputs, run_opts=None, hooks=None, context=None):
			captured['sync'] = (run_opts or {}).get('sync')
			captured['inputs'] = inputs

		with ExitStack() as stack:
			stack.enter_context(mock.patch('secator.celery.is_celery_worker_alive', return_value=True))
			stack.enter_context(mock.patch.object(cli_helper.Task, '__init__', fake_init))
			stack.enter_context(mock.patch.object(cli_helper.Task, '__iter__', lambda self: iter([])))
			result = CliRunner().invoke(cli, ['x'] + inputs)
		return result, captured

	def test_ai_setup_runs_sync_despite_worker(self):
		result, captured = self._run_with_worker_alive(['ai', 'setup'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertTrue(captured.get('sync'), 'ai setup must run sync (locally), not on a worker')

	def test_ai_with_target_dispatches_to_worker(self):
		"""Sanity check: a normal ai invocation is still dispatched to the worker (sync=False)."""
		result, captured = self._run_with_worker_alive(['ai', 'example.com'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertIn('sync', captured)
		self.assertFalse(captured.get('sync'), 'normal ai run should dispatch to worker when alive')


if __name__ == '__main__':
	unittest.main()

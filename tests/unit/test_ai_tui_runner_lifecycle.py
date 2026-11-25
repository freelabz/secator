"""The ai TUI must show why a run stopped, and must finalize the run when the user quits.

`run_ai_tui` drives the runner on a daemon thread and taps its items through an on_item
hook. Two gaps were covered here:

- a driver hook that fails when the runner starts (e.g. the api driver cannot create the
runner) records its Error without running hooks, so the TUI feed never saw it: the runner
stopped before the AI loop and the TUI showed nothing, as if the AI never answered;
- quitting the TUI (Ctrl+C) ended the process without the runner leaving its loop, so no
``on_end`` hook ran and every driver kept the run RUNNING.

The CLI parity test also pins that a driver from ``drivers.defaults`` and the same driver
passed with ``--driver`` give the TUI the same drivers, hooks and context.
"""
import threading
import unittest
from unittest import mock

from secator.decorators import task
from secator.output_types import Error, Info
from secator.runners import PythonRunner


def _make_runner_cls(started, release):
	"""A PythonRunner with the (config, inputs, run_opts, hooks, context) signature run_ai_tui uses."""

	@task()
	class FakeAi(PythonRunner):
		input_types = None
		output_types = [Info]

		def __init__(self, config, inputs, run_opts=None, hooks=None, context=None):
			opts = dict(run_opts or {})
			opts.pop('sync', None)
			super().__init__(inputs, hooks=hooks, context=context or {}, sync=True, **opts)

		def yielder(self):
			yield Info(message='thinking')
			started.set()
			# like the AI waiting on the user / the LLM: block until the test releases it
			release.wait(5)

	return FakeAi


class _AppDriver:
	"""Stand-in for AITUI.run: drive the builder like TUIApp._consume, then 'quit'."""

	def __init__(self, wait_for=None):
		self.wait_for = wait_for
		self.rendered = []

	def run(self, app):
		self.app = app
		app.tui_render = self.rendered.append
		thread = self.thread = threading.Thread(target=lambda: [None for _ in app._runner_builder()], daemon=True)
		thread.start()
		if self.wait_for is not None:
			# the user quits (Ctrl+C) while the runner is still working
			assert self.wait_for.wait(5), 'runner never started'
			return
		thread.join(5)


def _run_tui(runner_cls, hooks, driver):
	from secator.tui import ai as tui_ai
	with mock.patch.object(tui_ai.AITUI, 'run', lambda app: driver.run(app)):
		tui_ai.run_ai_tui(runner_cls, None, ['example.com'], {'print_item': False}, hooks, {})


class TestAiTuiRunnerLifecycle(unittest.TestCase):

	def test_quit_finalizes_running_runner_as_revoked(self):
		started, release = threading.Event(), threading.Event()
		runner_cls = _make_runner_cls(started, release)
		ended = []
		hooks = {runner_cls: {'on_end': [lambda self: ended.append(self.status)]}}
		driver = _AppDriver(wait_for=started)
		try:
			_run_tui(runner_cls, hooks, driver)
		finally:
			release.set()
			# let the abandoned runner thread end so it cannot touch the next test's TUI
			driver.thread.join(5)
		self.assertEqual(ended, ['REVOKED'], 'quitting the TUI must run on_end with a final revoked status')

	def test_quit_finalizes_the_inner_runner_of_a_hookless_wrapper(self):
		# The CLI drives a Task wrapper that runs with hooks off and builds the real ai
		# runner; only that inner runner persists through the drivers, so it is the one
		# that must end revoked.
		started, release = threading.Event(), threading.Event()
		inner_cls = _make_runner_cls(started, release)

		@task()
		class Wrapper(PythonRunner):
			input_types = None
			output_types = [Info]

			def __init__(self, config, inputs, run_opts=None, hooks=None, context=None):
				opts = dict(run_opts or {})
				opts.pop('sync', None)
				super().__init__(inputs, hooks=hooks, context=context or {}, sync=True, **opts)
				self.enable_hooks = False

			def yielder(self):
				inner = inner_cls(None, self.inputs, run_opts={'print_item': False}, hooks=self._hooks.get(Wrapper, {}))
				yield from inner

		ended = []
		hooks = {Wrapper: {'on_end': [lambda self: ended.append((self.__class__.__name__, self.status))]}}
		driver = _AppDriver(wait_for=started)
		try:
			_run_tui(Wrapper, hooks, driver)
		finally:
			release.set()
			# let the abandoned runner thread end so it cannot touch the next test's TUI
			driver.thread.join(5)
		self.assertEqual(ended, [('FakeAi', 'REVOKED')])

	def test_quit_during_a_blocking_start_hook_finalizes_the_inner_runner(self):
		# A driver on_start hook (e.g. a network status update) is still running when the
		# user quits: the inner runner must already be tracked, so it still ends revoked.
		started, release = threading.Event(), threading.Event()
		inner_cls = _make_runner_cls(threading.Event(), release)

		@task()
		class Wrapper(PythonRunner):
			input_types = None
			output_types = [Info]

			def __init__(self, config, inputs, run_opts=None, hooks=None, context=None):
				opts = dict(run_opts or {})
				opts.pop('sync', None)
				super().__init__(inputs, hooks=hooks, context=context or {}, sync=True, **opts)
				self.enable_hooks = False

			def yielder(self):
				inner = inner_cls(None, self.inputs, run_opts={'print_item': False}, hooks=self._hooks.get(Wrapper, {}))
				yield from inner

		def slow_update(self):
			started.set()
			release.wait(5)

		ended = []
		hooks = {Wrapper: {
			'on_start': [slow_update],
			'on_end': [lambda self: ended.append((self.__class__.__name__, self.status))]}}
		driver = _AppDriver(wait_for=started)
		try:
			_run_tui(Wrapper, hooks, driver)
		finally:
			release.set()
			driver.thread.join(5)
		self.assertEqual(ended, [('FakeAi', 'REVOKED')])

	def test_quit_does_not_refinalize_a_finished_runner(self):
		started, release = threading.Event(), threading.Event()
		release.set()
		runner_cls = _make_runner_cls(started, release)
		ended = []
		hooks = {runner_cls: {'on_end': [lambda self: ended.append(self.status)]}}
		_run_tui(runner_cls, hooks, _AppDriver())
		self.assertEqual(len(ended), 1)
		self.assertNotEqual(ended[0], 'REVOKED')

	def test_start_hook_failure_is_shown_in_the_tui(self):
		started, release = threading.Event(), threading.Event()
		release.set()
		runner_cls = _make_runner_cls(started, release)

		def failing_create(self):
			raise RuntimeError('API POST runners failed (HTTP 502, non-JSON body)')

		hooks = {runner_cls: {'on_init': [failing_create]}}
		driver = _AppDriver()
		_run_tui(runner_cls, hooks, driver)
		self.assertFalse(started.is_set(), 'a failed start hook stops the runner before its loop')
		errors = [r for r in driver.rendered if isinstance(r, Error)]
		self.assertTrue(errors, 'the start hook error must reach the TUI, not be dropped silently')
		self.assertIn('execution failed', errors[0].message)
		# routed as the parent's own error (shown in the conversation), not buffered under a
		# runner card that never renders because the run failed before its first item
		self.assertEqual(errors[0]._source, driver.app._parent_source)
		# rendered once, even though the runner keeps the error in its results
		self.assertEqual(len({e._uuid for e in errors}), len(errors))

	def test_fed_errors_are_not_rendered_twice(self):
		from secator.tui.ai import _surface_unrendered_errors
		err = Error(message='boom')
		err._uuid = 'u1'
		app = mock.Mock()
		app._fed_uuids = {'u1'}
		runner = mock.Mock(self_errors=[err])
		_surface_unrendered_errors(app, runner)
		app.tui_render.assert_not_called()


class TestAiTuiStartsRunnerOnce(unittest.TestCase):

	def test_mounting_the_app_builds_the_runner_once(self):
		"""Textual calls on_mount of every class in the MRO: the app must not start the runner
		again from AITUI.on_mount, or two runners run (two reports, two end messages)."""
		import asyncio
		from secator.tui.ai import AITUI
		builds = []

		def build():
			builds.append(1)
			return iter(())

		async def body():
			app = AITUI(build, session='ai', mode='chat')
			async with app.run_test(size=(120, 40)) as pilot:
				await pilot.pause(0.2)

		asyncio.run(body())
		self.assertEqual(builds, [1])


class TestAiCliDriverParity(unittest.TestCase):
	"""A driver from drivers.defaults must set up the TUI exactly like --driver."""

	def _invoke(self, args):
		from click.testing import CliRunner
		import click.testing
		import secator.hooks.api as hooks_api
		import secator.tui.ai as tui_ai
		from secator.cli import cli
		from secator.config import CONFIG
		captured = {}

		def fake_run_ai_tui(runner_cls, config, inputs, opts, hooks, context):
			captured['hooks'] = hooks
			captured['context'] = dict(context)

		with mock.patch.object(tui_ai, 'run_ai_tui', fake_run_ai_tui), \
			mock.patch.object(hooks_api, 'resolve_workspace', return_value=('a' * 24, 'ws')), \
			mock.patch.object(CONFIG.drivers, 'defaults', ['api']), \
			mock.patch.object(click.testing._NamedTextIOWrapper, 'isatty', return_value=True, create=True):
			result = CliRunner().invoke(cli, ['x', 'ai', 'example.com', '-p', 'hi', '-ws', 'ws', *args], catch_exceptions=False)
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('context', captured, 'the TUI was not launched')
		return captured

	def test_default_driver_matches_explicit_driver(self):
		default = self._invoke([])
		explicit = self._invoke(['--driver', 'api'])
		self.assertEqual(default['context']['drivers'], ['api'])
		self.assertEqual(default['context'], explicit['context'])
		self.assertEqual(default['hooks'], explicit['hooks'])


if __name__ == '__main__':
	unittest.main()

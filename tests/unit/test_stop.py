"""Stopping runners: a stopped task ends REVOKED (not FAILURE), and a task revoked while still
queued never runs, whichever worker picks it up."""
import unittest
from unittest import mock

from celery import states
from celery.exceptions import Ignore

from secator import celery as secator_celery
from secator.celery import app, revoke_task, run_command
from secator.output_types import Error
from secator.runners import Command, Task


class Interrupted(Command):
	"""A command whose process dies from SIGINT, as when a running task is stopped."""
	cmd = 'kill -INT $$'
	shell = True
	input_flag = None
	input_types = []
	output_types = []

	def _build_cmd(self):
		self.cmd_options = {}
		self.shell = True

	def is_installed(self):
		return True


class TestStoppedCommand(unittest.TestCase):

	def test_killed_command_is_revoked_not_failed(self):
		cmd = Interrupted('x', enable_reports=False, quiet=True)
		cmd.run()
		self.assertTrue(cmd.killed)
		self.assertTrue(cmd.done)
		self.assertEqual(cmd.status, 'REVOKED')

	def test_failed_command_is_still_a_failure(self):
		class Failing(Interrupted):
			cmd = 'exit 3'

		cmd = Failing('x', enable_reports=False, quiet=True)
		cmd.run()
		self.assertFalse(cmd.killed)
		self.assertEqual(cmd.status, 'FAILURE')

	def test_stop_exceptions_carry_no_traceback(self):
		for exc in (SystemExit(-241), KeyboardInterrupt()):
			try:
				raise exc
			except BaseException as e:
				error = Error.from_exception(e)
			self.assertEqual(error.traceback, '')
		self.assertEqual(Error.from_exception(SystemExit(-241)).message, 'SystemExit: -241')
		try:
			raise ValueError('boom')
		except ValueError as e:
			self.assertIn('ValueError', Error.from_exception(e).traceback)


class TestRevokeTask(unittest.TestCase):

	def _revoke(self, ready):
		with (
			mock.patch.object(app.control, 'revoke') as revoke,
			mock.patch.object(app, 'AsyncResult', return_value=mock.Mock(ready=lambda: ready)),
			mock.patch.object(app.backend, 'mark_as_revoked') as mark,
		):
			revoke_task('some-id')
		revoke.assert_called_once_with('some-id', terminate=True)
		return mark

	def test_unfinished_task_is_recorded_as_revoked(self):
		self._revoke(ready=False).assert_called_once_with('some-id', reason='revoked')

	def test_finished_task_keeps_its_state(self):
		self._revoke(ready=True).assert_not_called()


class TestRevokedBeforeStart(unittest.TestCase):

	def _run(self, state, is_eager=False):
		"""Run run_command up to the task lookup, with the given stored state for its own id."""
		run_command.push_request(id='some-id', is_eager=is_eager)
		self.addCleanup(run_command.pop_request)
		reached = RuntimeError('task was built')
		with (
			mock.patch.object(run_command, 'AsyncResult', return_value=mock.Mock(state=state)) as result,
			mock.patch.object(secator_celery, 'IN_WORKER', False),
			mock.patch.object(Task, 'get_task_class', side_effect=reached),
		):
			try:
				run_command.run([], 'httpx', ['x'], {})
			except RuntimeError as e:
				self.assertIs(e, reached)
				return True, result
			return False, result

	def test_revoked_task_is_skipped(self):
		with self.assertRaises(Ignore):
			self._run(states.REVOKED)

	def test_pending_task_runs(self):
		built, _ = self._run(states.PENDING)
		self.assertTrue(built)

	def test_in_process_task_does_not_check(self):
		built, result = self._run(states.REVOKED, is_eager=True)
		self.assertTrue(built)
		result.assert_not_called()

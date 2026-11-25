"""Stopping runners: a stopped task ends REVOKED (not FAILURE), and a task revoked while still
queued never runs, whichever worker picks it up. See also test_revoked_runners_worker.py."""
import signal
import threading
import time
import unittest
from unittest import mock

from celery import states
from celery.exceptions import ChordError, Ignore

from secator import celery as secator_celery
from secator.ai.actions import ActionContext, _batch_executor
from secator.celery import app, break_task, revoke_task, run_command
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

	def _revoke(self, *metas):
		with (
			mock.patch.object(app.control, 'revoke') as revoke,
			mock.patch.object(app.backend, 'get_task_meta', side_effect=metas),
			mock.patch.object(app.backend, 'mark_as_revoked') as mark,
		):
			revoke_task('some-id')
		return revoke, mark

	def test_unfinished_task_is_recorded_as_revoked(self):
		revoke, mark = self._revoke({'status': states.PENDING, 'result': None})
		revoke.assert_called_once_with('some-id', terminate=True)
		mark.assert_called_once_with('some-id', reason='revoked')

	def test_finished_task_keeps_its_state(self):
		_, mark = self._revoke({'status': states.SUCCESS, 'result': []})
		mark.assert_not_called()

	def test_chunked_task_revokes_its_chunks(self):
		revoke, _ = self._revoke(
			{'status': 'RUNNING', 'result': {'celery_ids': ['chunk-1', 'chunk-2']}},
			{'status': 'RUNNING', 'result': {'celery_ids': []}},
			{'status': states.PENDING, 'result': None},
		)
		self.assertEqual([c.args[0] for c in revoke.call_args_list], ['some-id', 'chunk-1', 'chunk-2'])


class TestRevokedBeforeStart(unittest.TestCase):

	def _run(self, state, is_eager=False, chord=None):
		"""Run run_command up to the task lookup, with the given stored state for its own id."""
		run_command.push_request(id='some-id', is_eager=is_eager, chord=chord)
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

	def test_revoked_chunk_still_counts_in_its_chord(self):
		# Else the chord never completes, and the chunked task is never finalized.
		with mock.patch.object(run_command.backend, 'mark_as_revoked') as mark, self.assertRaises(Ignore):
			self._run(states.REVOKED, chord={'task': 'callback'})
		self.assertEqual(mark.call_args.kwargs['request'].chord, {'task': 'callback'})

	def test_pending_task_runs(self):
		built, _ = self._run(states.PENDING)
		self.assertTrue(built)

	def test_in_process_task_does_not_check(self):
		built, result = self._run(states.REVOKED, is_eager=True)
		self.assertTrue(built)
		result.assert_not_called()


class Sleep(Command):
	"""A command that runs until it is stopped."""
	cmd = 'sleep'
	input_flag = None
	input_types = []
	output_types = []
	input_chunk_size = 1

	def is_installed(self):
		return True


def _wait_for_process(cmd, timeout=10):
	deadline = time.time() + timeout
	while not cmd.process:
		if time.time() > deadline:
			raise TimeoutError('the command did not start')
		time.sleep(0.05)


class TestRunnerStop(unittest.TestCase):

	def test_stop_ends_a_command_revoked(self):
		# Started from a process ignoring SIGINT, like a Celery prefork pool process: the command
		# must not inherit it, else stop() cannot interrupt it.
		previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
		self.addCleanup(signal.signal, signal.SIGINT, previous)
		cmd = Sleep('30', enable_reports=False, quiet=True)
		thread = threading.Thread(target=cmd.run)
		thread.start()
		_wait_for_process(cmd)
		cmd.stop()
		thread.join(10)
		self.assertFalse(thread.is_alive())
		self.assertEqual(cmd.status, 'REVOKED')

	def test_command_stopped_before_it_starts_is_interrupted(self):
		cmd = Sleep('30', enable_reports=False, quiet=True)
		cmd.stop()
		cmd.run()
		self.assertTrue(cmd.killed)
		self.assertEqual(cmd.status, 'REVOKED')

	def test_stop_revokes_the_celery_tasks_of_an_async_runner(self):
		cmd = Sleep('30', enable_reports=False, quiet=True)
		cmd.sync = False
		with mock.patch.object(cmd, 'stop_celery_tasks') as stop_celery_tasks:
			cmd.stop()
		stop_celery_tasks.assert_called_once_with()
		self.assertTrue(cmd.revoked)


class TestBatchStop(unittest.TestCase):

	def test_stop_cancels_queued_actions_and_stops_running_runners(self):
		ctx = ActionContext(targets=[], model='')
		earlier = Sleep('30', enable_reports=False, quiet=True)  # spawned by an earlier batch, left alone
		ctx.record_runner(earlier, 'earlier-id')
		running = Sleep('30', enable_reports=False, quiet=True)
		with self.assertRaises(KeyboardInterrupt):
			with _batch_executor(ctx, max_workers=1) as executor:
				ctx.record_runner(running, 'id', 'other-id')
				executor.submit(running.run)
				queued = executor.submit(self.fail, 'queued action ran')
				_wait_for_process(running)
				raise KeyboardInterrupt
		self.assertTrue(queued.cancelled())
		self.assertEqual(running.status, 'REVOKED')
		self.assertFalse(earlier.revoked)


class TestChunkedTaskChordError(unittest.TestCase):
	"""A revoked or failed chunk fails the chord, which skips its callback: the callback's error
	callback finalizes the chunked task instead."""

	def _fail_chord(self, exc):
		task = Sleep(['10', '11'], enable_reports=False, quiet=True, context={'celery_id': 'task-id'})
		task.has_children = True
		callback = break_task(task, {}).body
		with (
			mock.patch.object(secator_celery.mark_runner_completed, 'si') as si,
			mock.patch.object(app.backend, 'fail_from_current_stack'),
		):
			app.backend.chord_error_from_stack(callback, exc)
		return si

	def test_revoked_chunk_ends_the_task_revoked(self):
		si = self._fail_chord(ChordError("Dependency chunk-id raised TaskRevokedError('terminated')"))
		runner = si.call_args.kwargs['runner']
		self.assertTrue(runner.revoked)
		si.return_value.apply_async.assert_called_once_with(queue='results')

	def test_failed_chunk_ends_the_task(self):
		si = self._fail_chord(ChordError("Dependency chunk-id raised ValueError('boom')"))
		self.assertFalse(si.call_args.kwargs['runner'].revoked)
		si.return_value.apply_async.assert_called_once_with(queue='results')

	def test_failed_callback_is_left_alone(self):
		self._fail_chord(ValueError('boom')).assert_not_called()

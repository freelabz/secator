"""Worker-termination handling (SIGTERM vs revoke).

A worker torn down by SIGTERM raises ``SystemExit`` inside the running task (billiard's
shutdown, ``SystemExit(-(256-signum))``). This happens for BOTH a node/Job eviction and a
``revoke(terminate=True)``. The runner must *propagate* it on the worker rather than swallow it
into a returned result, because that's what lets Celery apply the correct policy — the split
between the two SIGTERM sources is Celery's job, not ours:

eviction (worker lost, not revoked) is requeued via ``task_reject_on_worker_lost``;
``revoke(terminate=True)`` (revoked) is acknowledged and never retried.

Both confirmed with a real prefork worker; the revoked-set gating lives in Celery. These tests
cover the secator half: propagate ``SystemExit`` on the worker, surface an ``Error`` off it, and
never mark a torn-down task completed.
"""
import unittest
from unittest import mock

from secator.output_types import Error
from secator.runners._base import Runner


def _bare_runner():
	r = Runner.__new__(Runner)          # bypass heavy __init__
	r._worker_terminated = False
	return r


class TestWorkerTermination(unittest.TestCase):

	def test_worker_systemexit_propagates_and_flags(self):
		r = _bare_runner()
		with mock.patch('secator.runners._base.IN_WORKER', True):
			with self.assertRaises(SystemExit):
				r._handle_worker_termination(SystemExit(-241))
		self.assertTrue(r._worker_terminated)

	def test_client_systemexit_becomes_error(self):
		# Off the worker (CLI), keep the old behavior: don't crash, surface an Error.
		r = _bare_runner()
		with mock.patch('secator.runners._base.IN_WORKER', False):
			out = r._handle_worker_termination(SystemExit(-241))
		self.assertIsInstance(out, Error)
		self.assertFalse(r._worker_terminated)

	def test_worker_regular_exception_becomes_error(self):
		# A genuine task error is NOT a worker teardown -> Error, no propagate, no flag.
		r = _bare_runner()
		with mock.patch('secator.runners._base.IN_WORKER', True):
			out = r._handle_worker_termination(ValueError('boom'))
		self.assertIsInstance(out, Error)
		self.assertFalse(r._worker_terminated)

	def test_keyboardinterrupt_on_worker_is_not_propagated(self):
		# Only SystemExit is the worker-teardown signal. A Ctrl+C stays an Error (unchanged).
		r = _bare_runner()
		with mock.patch('secator.runners._base.IN_WORKER', True):
			out = r._handle_worker_termination(KeyboardInterrupt())
		self.assertIsInstance(out, Error)
		self.assertFalse(r._worker_terminated)

	def test_finalize_skips_mark_completed_when_terminated(self):
		# A torn-down task must not record a terminal status or reports for the aborted attempt.
		r = _bare_runner()
		r._worker_terminated = True
		r.sync = True
		r.join_threads = mock.Mock()
		r.mark_completed = mock.Mock()
		r.export_reports = mock.Mock()
		r._finalize()
		r.mark_completed.assert_not_called()
		r.export_reports.assert_not_called()

	def test_finalize_marks_completed_normally(self):
		# Sanity: without termination, sync runs still mark completed.
		r = _bare_runner()
		r.sync = True
		r.enable_reports = False
		r.join_threads = mock.Mock()
		r.mark_completed = mock.Mock()
		r._finalize()
		r.mark_completed.assert_called_once()


if __name__ == '__main__':
	unittest.main()

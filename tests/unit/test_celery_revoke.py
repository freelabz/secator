"""Finalize revoked runners: when a run is stopped, its pending ``mark_runner_completed`` link
never completes the runner, so ``on_task_revoked`` completes it with status REVOKED.
"""
import importlib
import types
import unittest
from unittest import mock

from celery import chain
from celery.worker import state as worker_state

import secator.celery as sc
from secator.celery import mark_runner_completed, on_task_revoked, pending_finalizers
from secator.runners._base import Runner


def _passthrough_hooks(self, hook_type, *args, **kwargs):
	return args[0] if args else None


def _runner(has_parent=False, calls=None):
	"""A real runner whose on_end / on_run_end hooks record into ``calls``."""
	calls = calls if calls is not None else []
	mod = importlib.import_module('secator.tasks.httpx')
	with mock.patch.object(Runner, 'run_hooks', _passthrough_hooks):
		runner = mod.httpx(['http://localhost'], has_parent=has_parent, hooks={
			'on_end': [lambda r: calls.append(('on_end', r.status))],
			'on_run_end': [lambda r: calls.append(('on_run_end', r.status))],
		})
	for event in ('on_end', 'on_run_end'):  # keep only the recording hooks (no store I/O)
		runner.resolved_hooks[event] = [h for h in runner.resolved_hooks[event] if h.__name__ == '<lambda>']
	return runner


def _finalizer(runner, task_id, **kwargs):
	return dict(mark_runner_completed.s(runner, **kwargs).set(task_id=task_id))


def _run_finalizer(runner, task_id):
	"""Run mark_runner_completed as the worker would for the chain link ``task_id``."""
	mark_runner_completed.push_request(id=task_id)
	try:
		return mark_runner_completed.run([], runner)
	finally:
		mark_runner_completed.pop_request()


def _request(chain_=None, chord=None, callbacks=None, task='secator.celery.run_command', **kwargs):
	return types.SimpleNamespace(
		id='child', task=task, chain=chain_ or [], chord=chord, callbacks=callbacks or [], **kwargs)


class TestFinalizeRevokedRunners(unittest.TestCase):

	def setUp(self):
		sc._claimed_finalizers.clear()
		# No atomic incr (e.g. the filesystem backend): the claim falls back to this process.
		mock.patch.object(sc.app.backend, 'incr', side_effect=NotImplementedError, create=True).start()
		self.revoked = set()
		mock.patch.object(worker_state, 'revoked', self.revoked).start()
		self.addCleanup(mock.patch.stopall)

	def test_pending_finalizers_in_chain_chord_and_callbacks(self):
		root = _runner()
		fin = _finalizer(root, 'f-root')
		other = dict(sc.join_results.s().set(task_id='other'))
		# chain links are stored next-link-last
		self.assertEqual(pending_finalizers(_request(chain_=[fin, other])), [fin])
		# parallel group: the finalizer sits in the chord body (a chain)
		body = dict(chain(sc.join_results.si(), mark_runner_completed.s(root).set(task_id='f-body')))
		self.assertEqual([s['options']['task_id'] for s in pending_finalizers(_request(chord=body))], ['f-body'])
		self.assertEqual(pending_finalizers(_request(callbacks=[fin])), [fin])
		self.assertEqual(pending_finalizers(_request()), [])

	def test_stopped_run_completes_root_as_revoked_once(self):
		calls = []
		root = _runner(calls=calls)
		self.revoked.add('f-root')
		on_task_revoked(request=_request(chain_=[_finalizer(root, 'f-root')]))
		self.assertTrue(root.done)
		self.assertEqual(root.status, 'REVOKED')
		self.assertEqual(calls, [('on_end', 'REVOKED'), ('on_run_end', 'REVOKED')])
		# A second revoked task of the same run (parallel group): no second completion.
		on_task_revoked(request=_request(chord=_finalizer(root, 'f-root')))
		self.assertEqual(len(calls), 2)

	def test_single_revoked_task_leaves_the_run_alone(self):
		calls = []
		root = _runner(calls=calls)
		on_task_revoked(request=_request(chain_=[_finalizer(root, 'f-root')]))  # f-root not revoked
		self.assertFalse(root.done)
		self.assertEqual(calls, [])

	def test_stopped_scan_completes_nested_runners_too(self):
		calls = []
		scan = _runner(calls=calls)
		workflow = _runner(has_parent=True, calls=calls)
		self.revoked.add('f-scan')  # a stop revokes the run's own id, not its workflows'
		chain_ = [_finalizer(scan, 'f-scan'), _finalizer(workflow, 'f-wf')]  # next-link-last
		on_task_revoked(request=_request(chain_=chain_))
		self.assertEqual((workflow.status, scan.status), ('REVOKED', 'REVOKED'))
		# Only the top-level run fires on_run_end.
		self.assertEqual([c for c in calls if c[0] == 'on_run_end'], [('on_run_end', 'REVOKED')])

	def test_revoked_finalizer_itself(self):
		calls = []
		root = _runner(calls=calls)
		request = _request(task=sc.FINALIZER_TASK, args=([], root), kwargs={'enable_hooks': True})
		request.id = 'f-root'
		on_task_revoked(request=request)
		self.assertEqual(root.status, 'REVOKED')
		self.assertEqual(calls[-1], ('on_run_end', 'REVOKED'))

	def test_normal_finalizer_skipped_after_revoke(self):
		calls = []
		root = _runner(calls=calls)
		self.revoked.add('f-root')
		on_task_revoked(request=_request(chain_=[_finalizer(root, 'f-root')]))
		# The chain resumes (the killed task returned): its own finalizer must not complete again.
		_run_finalizer(_runner(calls=calls), 'f-root')
		self.assertEqual([c for c in calls if c[0] == 'on_run_end'], [('on_run_end', 'REVOKED')])

	def test_redelivered_normal_finalizer_is_not_blocked_by_itself(self):
		calls = []
		_run_finalizer(_runner(calls=calls), 'f-x')
		_run_finalizer(_runner(calls=calls), 'f-x')  # e.g. redelivered after a lost worker
		self.assertEqual([c for c in calls if c[0] == 'on_run_end'], [('on_run_end', 'SUCCESS')] * 2)

	def test_nested_chain_options_in_run_order(self):
		workflow, scan = _runner(has_parent=True), _runner()
		body = dict(sc.join_results.si().set(task_id='body'))
		# A continuation chain stored in options, next-link-last: the scan finalizer runs last.
		body['options']['chain'] = [_finalizer(scan, 'f-scan'), _finalizer(workflow, 'f-wf')]
		ids = [s['options']['task_id'] for s in pending_finalizers(_request(chord=body))]
		self.assertEqual(ids, ['f-wf', 'f-scan'])

	def test_outer_chord_continuation_is_found(self):
		root = _runner()
		inner_body = dict(sc.join_results.si().set(task_id='inner'))
		inner_body['options']['chord'] = _finalizer(root, 'f-outer')
		ids = [s['options']['task_id'] for s in pending_finalizers(_request(chord=inner_body))]
		self.assertEqual(ids, ['f-outer'])

	def test_normal_finalizer_runs_when_not_revoked(self):
		calls = []
		_run_finalizer(_runner(calls=calls), 'f-ok')
		self.assertEqual(calls, [('on_end', 'SUCCESS'), ('on_run_end', 'SUCCESS')])

	def test_claim_uses_atomic_backend_incr(self):
		counts = {}

		def incr(key):
			counts[key] = counts.get(key, 0) + 1
			return counts[key]

		mock.patch.object(sc.app.backend, 'incr', side_effect=incr, create=True).start()
		self.assertTrue(sc.claim_finalizer('f1'))
		self.assertFalse(sc.claim_finalizer('f1'))
		self.assertEqual(sc._claimed_finalizers, set())  # not the in-process fallback

	def test_claim_falls_back_to_process(self):
		self.assertTrue(sc.claim_finalizer('f1'))
		self.assertFalse(sc.claim_finalizer('f1'))
		self.assertTrue(sc.finalizer_claimed('f1'))
		self.assertTrue(sc.claim_finalizer(None))

	def test_claim_falls_back_when_incr_creates_no_key(self):
		# e.g. a memcached client returns None when incrementing a missing key
		mock.patch.object(sc.app.backend, 'incr', return_value=None, create=True).start()
		self.assertTrue(sc.claim_finalizer('f1'))
		self.assertFalse(sc.claim_finalizer('f1'))

	def test_claim_falls_back_without_key_value_backend(self):
		mock.patch.object(sc.app.backend, 'get_key_for_task', side_effect=AttributeError, create=True).start()
		self.assertTrue(sc.claim_finalizer('f1'))
		self.assertFalse(sc.claim_finalizer('f1'))
		self.assertTrue(sc.finalizer_claimed('f1'))
		self.assertFalse(sc.finalizer_claimed('f2'))

	def test_stop_revokes_the_run_id_first(self):
		runner = _runner()
		runner.celery_result = types.SimpleNamespace(id='run')
		# Chunk ids are discovered while polling, after the run's id was registered.
		runner.celery_ids_map = {'child': {'full_name': 'a'}, 'run': {'full_name': 'r'}, 'chunk': {'full_name': 'c'}}
		revoked = []
		with mock.patch('secator.celery.revoke_task', lambda tid, name=None: revoked.append(tid)):
			runner.stop_celery_tasks()
		self.assertEqual(revoked, ['run', 'chunk', 'child'])


if __name__ == '__main__':
	unittest.main()

"""on_run_end hook point + celery_events driver.

on_run_end fires once per top-level run, after every on_end hook, and never for child
runners. The celery_events driver publishes a configured Celery task from it, the same
way whatever store driver the run uses.
"""
import importlib
import importlib.util
import pickle
import unittest
from unittest import mock

from secator.config import CONFIG
from secator.hooks import celery_events, json as json_driver
from secator.runners import Task
from secator.runners._base import HOOKS, Runner

STORE_DRIVERS = ['json', 'sqlite', 'mongodb', 'api']


def _passthrough_hooks(self, hook_type, *args, **kwargs):
	return args[0] if args else None


def _build_task(**run_opts):
	"""A real command runner, built without firing construction-time hooks (no store I/O)."""
	mod = importlib.import_module('secator.tasks.httpx')
	with mock.patch.object(Runner, 'run_hooks', _passthrough_hooks):
		return mod.httpx(['http://localhost'], **run_opts)


def _strip_store_hooks(task):
	"""Keep on_run_end only, so mark_completed() never touches a real store."""
	task.resolved_hooks['on_end'] = []


class TestOnRunEndHookPoint(unittest.TestCase):

	def test_is_a_runner_hook(self):
		self.assertIn('on_run_end', HOOKS)
		self.assertEqual(HOOKS.index('on_run_end'), HOOKS.index('on_end') + 1)

	def _fire(self, has_parent):
		calls = []
		task = _build_task(has_parent=has_parent, hooks={
			'on_end': [lambda r: calls.append('on_end')],
			'on_run_end': [lambda r: calls.append('on_run_end')],
		})
		task.mark_completed()
		task.mark_completed()  # guarded by `done`: never fires twice
		return calls

	def test_fires_once_for_top_level_run_after_on_end(self):
		self.assertEqual(self._fire(has_parent=False), ['on_end', 'on_run_end'])

	def test_never_fires_for_child_runner(self):
		self.assertEqual(self._fire(has_parent=True), ['on_end'])

	def test_survives_pickling(self):
		# A chunked top-level task is completed by a chord callback that unpickles it.
		task = _build_task(has_parent=False, context={'drivers': ['celery_events']})
		restored = pickle.loads(pickle.dumps(task))
		self.assertIn(celery_events.publish_run_end, restored.resolved_hooks['on_run_end'])

	def test_json_report_announce_moved_to_run_end(self):
		for cls_hooks in json_driver.HOOKS.values():
			self.assertNotIn(json_driver.announce_report, cls_hooks['on_end'])
			self.assertEqual(cls_hooks['on_run_end'], [json_driver.finalize_store, json_driver.announce_report])


class TestRunnerSerializedByOlderVersion(unittest.TestCase):
	"""A runner serialized by an older version carries a resolved_hooks dict built from that
	version's HOOKS list, without hook types added since (e.g. on_run_end). Completing it with
	the current version must not raise."""

	def _old_runner(self, calls):
		task = _build_task(has_parent=False)
		task.resolved_hooks['on_end'] = [lambda r: calls.append('on_end')]
		del task.resolved_hooks['on_run_end']
		return task

	def test_run_hooks_missing_type_is_a_noop(self):
		task = _build_task(has_parent=False)
		del task.resolved_hooks['on_run_end']
		self.assertEqual(task.run_hooks('on_run_end', 'x'), 'x')

	def test_mark_completed_survives_missing_on_run_end(self):
		calls = []
		task = self._old_runner(calls)
		task.mark_completed()
		self.assertTrue(task.done)
		self.assertEqual(calls, ['on_end'])

	def test_unpickled_runner_without_on_run_end(self):
		task = _build_task(has_parent=False)
		_strip_store_hooks(task)
		del task.resolved_hooks['on_run_end']
		restored = pickle.loads(pickle.dumps(task))
		self.assertNotIn('on_run_end', restored.resolved_hooks)
		restored.mark_completed()
		self.assertTrue(restored.done)

	def test_register_hooks_seeds_missing_hook_type(self):
		task = _build_task(has_parent=False)
		del task.resolved_hooks['on_run_end']
		hook = lambda r: None  # noqa: E731
		task.register_hooks({'on_run_end': [hook]})
		self.assertEqual(task.resolved_hooks['on_run_end'], [hook])

	def test_run_validators_missing_type_is_a_noop(self):
		task = _build_task(has_parent=False)
		task.resolved_validators.pop('validate_item', None)
		self.assertTrue(task.run_validators('validate_item', None))


class TestCeleryEventsDriver(unittest.TestCase):

	def setUp(self):
		self.send_task = mock.patch('secator.celery.app.send_task').start()
		self.addCleanup(mock.patch.stopall)

	def _configure(self, task_name='myapp.on_run_end', queue='post-run'):
		mock.patch.object(CONFIG.addons.celery_events, 'run_end_task', task_name).start()
		mock.patch.object(CONFIG.addons.celery_events, 'queue', queue).start()

	def _run(self, store, has_parent=False):
		if store == 'mongodb' and importlib.util.find_spec('pymongo') is None:
			self.skipTest('mongodb driver needs the optional pymongo extra')
		context = {'drivers': [store, 'celery_events'], 'workspace_id': 'ws1', 'task_id': 'tid1'}
		task = _build_task(has_parent=has_parent, context=context)
		# The store driver's hooks really are loaded alongside the event driver.
		store_hooks = importlib.import_module(f'secator.hooks.{store}').HOOKS[Task]
		self.assertIn(store_hooks['on_end'][0], task.resolved_hooks['on_end'])
		self.assertEqual(task.resolved_hooks['on_run_end'][-1], celery_events.publish_run_end)
		_strip_store_hooks(task)
		task.mark_completed()
		return task

	def test_publishes_once_on_every_store_driver(self):
		self._configure()
		for store in STORE_DRIVERS:
			with self.subTest(store=store):
				self.send_task.reset_mock()
				task = self._run(store)
				self.send_task.assert_called_once()
				args, kwargs = self.send_task.call_args
				self.assertEqual(args, ('myapp.on_run_end',))
				self.assertEqual(kwargs['queue'], 'post-run')
				payload = kwargs['kwargs']
				self.assertEqual(payload['runner_type'], 'task')
				self.assertEqual(payload['runner_id'], task.context['task_id'])
				self.assertEqual(payload['name'], 'httpx')
				self.assertEqual(payload['workspace_id'], 'ws1')
				self.assertEqual(payload['status'], 'SUCCESS')
				self.assertTrue(payload['end_time'])

	def test_no_op_when_unconfigured_on_every_store_driver(self):
		self._configure(task_name='')
		for store in STORE_DRIVERS:
			with self.subTest(store=store):
				self._run(store)
		self.send_task.assert_not_called()

	def test_child_runner_never_publishes(self):
		self._configure()
		for store in STORE_DRIVERS:
			with self.subTest(store=store):
				self._run(store, has_parent=True)
		self.send_task.assert_not_called()

	def test_default_routing_when_no_queue(self):
		self._configure(queue='')
		self._run('json')
		self.assertIsNone(self.send_task.call_args.kwargs['queue'])

	def test_broker_error_never_fails_the_run(self):
		self._configure()
		self.send_task.side_effect = ConnectionError('broker down')
		task = self._run('json')
		self.assertEqual(task.status, 'SUCCESS')
		self.assertEqual(task.errors, [])

	def test_is_an_available_driver(self):
		# `--driver celery_events` and profile drivers are checked against this list.
		from secator.loader import get_available_drivers
		self.assertIn('celery_events', get_available_drivers())

	def test_hooks_cover_every_runner_type(self):
		for hooks in celery_events.HOOKS.values():
			self.assertEqual(hooks, {'on_run_end': [celery_events.publish_run_end]})
		self.assertIn(Task, celery_events.HOOKS)


if __name__ == '__main__':
	unittest.main()

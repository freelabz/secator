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

	def test_top_level_run_has_no_chunk_id(self):
		self._configure()
		self._run('json')
		self.assertIsNone(self.send_task.call_args.kwargs['kwargs']['runner_chunk_id'])

	def test_payload_names_the_mongodb_doc_of_an_ai_spawned_task(self):
		# A task the `ai` task spawns carries its own task_chunk_id (no `chunk` run opt). The
		# mongodb store keys its doc on that id, never on task_id, so the event must carry it.
		if importlib.util.find_spec('pymongo') is None:
			self.skipTest('mongodb driver needs the optional pymongo extra')
		from secator.hooks import mongodb
		self._configure()
		written = []
		client = mock.MagicMock()
		client.main.__getitem__.return_value.update_one.side_effect = (
			lambda query, update, upsert=False: written.append(str(query['_id'])))
		mock.patch.object(mongodb, 'get_mongodb_client', return_value=client).start()
		context = {'drivers': ['mongodb', 'celery_events'], 'workspace_id': 'ws1',
			'task_id': 'run-scope-uuid', 'task_chunk_id': 'child-uuid'}
		task = _build_task(context=context)
		task.mark_completed()
		payload = self.send_task.call_args.kwargs['kwargs']
		self.assertEqual(written[-1], payload['runner_chunk_id'])
		self.assertNotEqual(written[-1], payload['runner_id'])

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


class TestRunEndHookPhases(unittest.TestCase):
	"""on_run_end goes through the same phased path as every hook event: celery_events is a
	post-phase driver, so it publishes after every persistence hook, whatever the driver order."""

	def setUp(self):
		self.order = []
		self.send_task = mock.patch(
			'secator.celery.app.send_task', side_effect=lambda *a, **kw: self.order.append('publish')).start()
		mock.patch.object(CONFIG.addons.celery_events, 'run_end_task', 'myapp.on_run_end').start()
		self.addCleanup(mock.patch.stopall)

	def test_driver_is_post_phase(self):
		from secator.loader import get_driver_phase
		self.assertEqual(get_driver_phase('celery_events'), 'post')

	def test_on_run_end_sorted_after_persistence_hooks(self):
		# Listed first on purpose: register_hooks() sorts each event by phase.
		task = _build_task(context={'drivers': ['celery_events', 'json']})
		self.assertEqual(
			task.resolved_hooks['on_run_end'],
			[json_driver.finalize_store, json_driver.announce_report, celery_events.publish_run_end],
		)

	def test_publishes_after_the_mongodb_status_write(self):
		if importlib.util.find_spec('pymongo') is None:
			self.skipTest('mongodb driver needs the optional pymongo extra')
		from secator.hooks import mongodb

		def record_write(query, update, upsert=False):
			self.order.append(('write', update['$set']['status']))

		client = mock.MagicMock()
		client.main.__getitem__.return_value.update_one.side_effect = record_write
		mock.patch.object(mongodb, 'get_mongodb_client', return_value=client).start()
		task = _build_task(context={'drivers': ['celery_events', 'mongodb'], 'task_id': str(mongodb.ObjectId())})
		task.mark_completed()
		self.assertEqual(self.order, [('write', 'SUCCESS'), 'publish'])

	def test_failing_post_hook_is_isolated_on_run_end(self):
		# Even with raise_on_error, a failing post-phase hook yields an Error instead of aborting.
		def broken(runner):
			raise RuntimeError('boom')
		broken.__module__ = 'secator.hooks.celery_events'
		task = _build_task(raise_on_error=True, hooks={'on_run_end': [broken]})
		task.mark_completed()
		self.assertTrue(task.done)
		self.assertTrue(any('boom' in str(e.message) or 'broken' in str(e.message) for e in task.errors))

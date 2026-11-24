"""Periodic runner updates (on_interval) are throttled on `last_updated_db`, which every driver's
runner update hook stamps after a successful write."""
import shutil
import tempfile
import time
import unittest
import uuid
from contextlib import contextmanager
from importlib.util import find_spec
from pathlib import Path
from unittest import mock

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Url
from secator.runners import PythonRunner

N_ITEMS = 300


@task()
class interval_probe(PythonRunner):
	input_types = [HOST]
	output_types = [Url]
	n = N_ITEMS

	def yielder(self):
		for i in range(self.n):
			yield Url(url=f'http://h{i}.example.test/', status_code=200)


RUN_OPTS = dict(
	print_item=False, print_line=False, print_start=False, print_end=False,
	quiet=True, sync=True, exporters=[])


@contextmanager
def update_frequency(value):
	"""Temporarily set runners.backend_update_frequency (plain set/restore: the config is a
	pydantic model, so mock.patch.object's delattr-based restore would break it)."""
	previous = CONFIG.runners.backend_update_frequency
	CONFIG.runners.backend_update_frequency = value
	try:
		yield
	finally:
		CONFIG.runners.backend_update_frequency = previous


def _run(**kwargs):
	opts = {**RUN_OPTS, **kwargs}
	runner = interval_probe(['example.test'], **opts)
	items = list(runner)
	return runner, items


def _stamping_hook(calls):
	"""A runner update hook following the driver contract: stamp `last_updated_db` on success."""
	def hook(self):
		calls.append(1)
		self.last_updated_db = time.time()
	return hook


def _interval_hooks(*hooks):
	"""on_interval hooks under test, plus an on_item hook that forgets, on the first finding, the
	stamp left by the default json driver's on_start write, so the first on_interval pass is due
	and the counts below are deterministic."""
	forgotten = []

	def forget_last_update(self, item):
		if isinstance(item, Url) and not forgotten:
			forgotten.append(1)
			self.last_updated_db = None
		return item
	return {'on_item': [forget_last_update], 'on_interval': list(hooks)}


class TestIntervalThrottle(unittest.TestCase):

	def test_on_interval_throttled_on_driver_stamp(self):
		calls = []
		with update_frequency(3600):
			_run(hooks=_interval_hooks(_stamping_hook(calls)), drivers=[])
		self.assertEqual(len(calls), 1, 'on_interval must fire once per update window, not per item')

	def test_every_on_interval_hook_runs_on_a_pass(self):
		"""A hook stamping `last_updated_db` must not skip the hooks registered after it."""
		first, second = [], []
		with update_frequency(3600):
			_run(hooks=_interval_hooks(_stamping_hook(first), _stamping_hook(second)), drivers=[])
		self.assertEqual(len(first), 1)
		self.assertEqual(len(second), 1)

	def test_on_interval_every_item_when_frequency_zero(self):
		calls = []
		with update_frequency(0):
			_run(hooks=_interval_hooks(_stamping_hook(calls)), drivers=[])
		self.assertEqual(len(calls), N_ITEMS)

	def test_on_interval_disabled_with_minus_one(self):
		calls = []
		with update_frequency(-1):
			_run(hooks=_interval_hooks(_stamping_hook(calls)), drivers=[])
		self.assertEqual(calls, [])


class TestDriversStampLastUpdatedDb(unittest.TestCase):
	"""Each driver's runner update hook stamps `last_updated_db`, so its rewrites are bounded."""

	def test_json_driver(self):
		from secator.hooks import json as json_hooks
		writes = []
		real = json_hooks.atomic_json

		def counting(path, *args, **kwargs):
			writes.append(str(path))
			return real(path, *args, **kwargs)

		with update_frequency(3600), mock.patch.object(json_hooks, 'atomic_json', side_effect=counting):
			runner, _ = _run(drivers=['json'])
		info_writes = [p for p in writes if p.endswith('report.json')]
		# on_init + on_start + one interval + on_end (+ run-end), never one per item.
		self.assertLess(len(info_writes), 10, info_writes)
		self.assertIsNotNone(runner.last_updated_db)
		self.assertEqual(runner.status, 'SUCCESS')

	def test_sqlite_driver(self):
		import secator.hooks.sqlite as sqlite_mod
		tmp = tempfile.mkdtemp()
		previous = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(tmp) / 'test.db')
		sqlite_mod._conns.clear()

		def cleanup():
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = previous
			shutil.rmtree(tmp, ignore_errors=True)
		self.addCleanup(cleanup)

		calls = []
		real = sqlite_mod.update_runner

		def counting(self):
			calls.append(1)
			return real(self)

		# Hooks are registered by reference: point the driver's HOOKS at the counting wrapper.
		patched = {
			cls: {k: [counting if f is real else f for f in v] for k, v in hooks.items()}
			for cls, hooks in sqlite_mod.HOOKS.items()
		}
		with update_frequency(3600), mock.patch.dict(sqlite_mod.HOOKS, patched):
			runner, _ = _run(drivers=['sqlite'])
		self.assertLess(len(calls), 10)
		self.assertIsNotNone(runner.last_updated_db)
		self.assertEqual(runner.status, 'SUCCESS')

	@unittest.skipUnless(find_spec('pymongo'), 'pymongo not installed (mongodb addon)')
	def test_mongodb_driver(self):
		from secator.hooks import mongodb
		runner = _FakeRunner({'task_id': 'c' * 24})
		client = mock.MagicMock()
		with mock.patch.object(mongodb, 'get_mongodb_client', return_value=client):
			mongodb.update_runner(runner)
		self.assertIsNotNone(runner.last_updated_db)

	def test_api_driver_create_and_update(self):
		from secator.hooks import api
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with mock.patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws')):
			with mock.patch.object(api, '_make_request', return_value={'id': 'b' * 24}):
				api.update_runner(runner)  # POST (create)
				self.assertIsNotNone(runner.last_updated_db)
				runner.last_updated_db = None
				api.update_runner(runner)  # PUT (update)
				self.assertIsNotNone(runner.last_updated_db)

	def test_api_driver_failed_create_does_not_stamp(self):
		from secator.hooks import api
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with mock.patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws')):
			with mock.patch.object(api, '_make_request', return_value=None):
				api.update_runner(runner)
		self.assertIsNone(runner.last_updated_db)

	def test_discord_driver(self):
		from secator.hooks import discord
		runner = _FakeRunner({})
		with mock.patch.multiple(
			discord, SEND_RUNNER_UPDATES=True,
			_build_runner_embed=mock.DEFAULT, _create_message=mock.DEFAULT,
		) as mocks:
			mocks['_create_message'].return_value = ('1', None)
			discord.update_runner(runner)
		self.assertIsNotNone(runner.last_updated_db)


class _Cfg:
	type = 'task'
	name = 'probe'


class _FakeRunner:
	def __init__(self, context):
		self.config = _Cfg()
		self.context = context
		self.chunk = None
		self.has_parent = False
		self.unique_name = 'probe'
		self.status = 'RUNNING'
		self.last_updated_db = None

	def toDict(self):
		return {'status': self.status, 'chunk': self.chunk, 'context': dict(self.context)}

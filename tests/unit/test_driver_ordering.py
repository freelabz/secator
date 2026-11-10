"""Driver hook phase ordering regression tests.

Hooks run phase by phase: ``pre`` drivers (default, e.g. ``gcs`` and external drivers),
then the persistence drivers (``mongodb`` > ``sqlite`` > ``json``), then ``post`` drivers
(``api``, ``discord``). With both attached, ``api`` running its HTTP ``update_runner`` hook
before ``mongodb`` wrote status straight to the DB left runners stuck in PENDING, so
``mongodb`` (and other persistence drivers) must always prevail over ``api``.
"""

import sys
import types
import unittest
from unittest.mock import patch

from secator.loader import get_driver_phase, order_drivers
from secator.output_types import Error, Url


class TestDriverOrdering(unittest.TestCase):
	def test_mongodb_prevails_over_api(self):
		# The core regression: mongodb must come before api regardless of input order.
		self.assertEqual(order_drivers(['api', 'mongodb']), ['mongodb', 'api'])
		self.assertEqual(order_drivers(['mongodb', 'api']), ['mongodb', 'api'])

	def test_enrichment_gcs_runs_before_backends(self):
		# gcs enriches findings (e.g. screenshot_path) and must run before any
		# backend persists them.
		self.assertEqual(order_drivers(['mongodb', 'gcs']), ['gcs', 'mongodb'])
		self.assertEqual(order_drivers(['api', 'gcs']), ['gcs', 'api'])
		self.assertEqual(order_drivers(['sqlite', 'gcs']), ['gcs', 'sqlite'])

	def test_full_canonical_order(self):
		# pre (gcs), persistence in authority order (mongodb > sqlite > json), post (api, discord).
		self.assertEqual(
			order_drivers(['json', 'sqlite', 'api', 'discord', 'gcs', 'mongodb']),
			['gcs', 'mongodb', 'sqlite', 'json', 'api', 'discord'],
		)

	def test_builtin_phases(self):
		self.assertEqual(get_driver_phase('gcs'), 'pre')
		for driver in ('mongodb', 'sqlite', 'json'):
			self.assertEqual(get_driver_phase(driver), 'persist')
		for driver in ('api', 'discord'):
			self.assertEqual(get_driver_phase(driver), 'post')

	def test_unknown_drivers_default_to_pre_in_order(self):
		# External/unknown drivers default to the pre phase (before persistence), keeping their order.
		self.assertEqual(
			order_drivers(['custom_b', 'api', 'custom_a', 'mongodb']),
			['custom_b', 'custom_a', 'mongodb', 'api'],
		)

	def test_external_driver_declaring_post_phase(self):
		module = types.ModuleType('secator.hooks.custom_post')
		module.HOOK_PHASE = 'post'
		sys.modules[module.__name__] = module
		try:
			self.assertEqual(
				order_drivers(['custom_post', 'api', 'custom_pre', 'json']),
				['custom_pre', 'json', 'custom_post', 'api'],
			)
		finally:
			del sys.modules[module.__name__]

	def test_dedupes_preserving_priority(self):
		self.assertEqual(order_drivers(['api', 'mongodb', 'api']), ['mongodb', 'api'])

	def test_empty(self):
		self.assertEqual(order_drivers([]), [])


def _driver_hook(driver, fun):
	"""Make ``fun`` look like a hook defined in driver module ``secator.hooks.<driver>``."""
	fun.__module__ = f'secator.hooks.{driver}'
	return fun


class TestHookPhases(unittest.TestCase):
	"""Hooks run phase by phase whatever their registration order, and a failing pre / post
	driver hook never aborts the remaining hooks — notably the persistence driver's."""

	def setUp(self):
		import importlib
		self.calls = []
		self.task = importlib.import_module('secator.tasks.httpx').httpx(
			['http://localhost'], enable_hooks=False, dry_run=True, raise_on_error=True)
		self.task.dry_run = False
		self.task.enable_hooks = True
		self.task.resolved_hooks['on_item'] = []

	def _hook(self, driver, name, fail=False):
		def hook(runner, item):
			self.calls.append((name, item.url))
			if fail:
				item.url = 'http://mutated'
				raise RuntimeError('boom')
			return item
		hook.__name__ = name
		return _driver_hook(driver, hook)

	def test_registration_sorted_by_phase(self):
		post = self._hook('api', 'post')
		persist = self._hook('json', 'persist')
		pre = self._hook('custom_pre', 'pre')
		self.task.register_hooks({'on_item': [post, persist, pre]})
		self.assertEqual([h.__name__ for h in self.task.resolved_hooks['on_item']], ['pre', 'persist', 'post'])

	def test_failing_pre_driver_does_not_abort_persistence(self):
		persisted = []

		def persist(runner, item):
			persisted.append(item)
			return item

		failing = self._hook('custom_pre', 'failing', fail=True)
		self.task.register_hooks({'on_item': [failing, _driver_hook('json', persist)]})
		item = Url(url='http://a')
		with patch.object(self.task, 'add_result') as add_result:
			result = self.task.run_hooks('on_item', item, sub='item')
		self.assertIs(result, item)  # passed along as the previous hook left it
		self.assertEqual(persisted, [item])
		self.assertEqual(item.url, 'http://mutated')  # partial in-place mutation is persisted
		error = add_result.call_args[0][0]
		self.assertIsInstance(error, Error)
		self.assertIn('custom_pre', error.message)

	def test_failing_post_driver_does_not_raise(self):
		self.task.register_hooks({'on_item': [self._hook('api', 'post', fail=True)]})
		self.task.run_hooks('on_item', Url(url='http://a'), sub='item')

	def test_failing_persistence_driver_still_raises(self):
		self.task.register_hooks({'on_item': [self._hook('json', 'persist', fail=True)]})
		with self.assertRaises(RuntimeError):
			self.task.run_hooks('on_item', Url(url='http://a'), sub='item')

	def test_phase_filter(self):
		self.task.resolved_hooks['on_item_update'] = []
		self.task.register_hooks({'on_item_update': [self._hook('api', 'post'), self._hook('custom_pre', 'pre')]})
		self.task.run_hooks('on_item_update', Url(url='http://a'), phase='post')
		self.assertEqual(self.calls, [('post', 'http://a')])


class TestQueryBackendOrdering(unittest.TestCase):
	def test_query_engine_selects_mongodb_over_api(self):
		# When both drivers are present, the resolved read backend must be mongodb.
		from secator.query import QueryEngine
		name = QueryEngine.resolve_backend_from_drivers(['api', 'mongodb'])
		self.assertEqual(name, 'mongodb')


class TestDefaultDrivers(unittest.TestCase):
	"""json = implicit local default so there is always a queryable store, without
	overriding a store backend (mongodb/sqlite/api) or the mongodb addon (prod)."""

	def test_no_driver_local_run_defaults_to_json(self):
		from secator.loader import apply_default_drivers
		from secator.query import QueryEngine
		drivers = apply_default_drivers([], mongodb_enabled=False)
		self.assertEqual(drivers, ['json'])
		# The json driver reads via the local (filesystem) query backend.
		self.assertEqual(QueryEngine.resolve_backend_from_drivers(drivers), 'local')

	def test_mongodb_addon_run_stays_mongodb(self):
		from secator.loader import apply_default_drivers
		from secator.query import QueryEngine
		drivers = apply_default_drivers(['mongodb'], mongodb_enabled=True)
		self.assertNotIn('json', drivers)
		self.assertEqual(QueryEngine.resolve_backend_from_drivers(drivers), 'mongodb')

	def test_mongodb_addon_without_explicit_driver_defaults_to_json(self):
		# Addon enabled but no explicit store driver in drivers.defaults: with the result
		# payload dropped, something must still write the store, so json is the default
		# (data integrity) — same as a bare local run.
		from secator.loader import apply_default_drivers
		self.assertEqual(apply_default_drivers([], mongodb_enabled=True), ['json'])

	def test_sqlite_driver_not_overridden(self):
		from secator.loader import apply_default_drivers
		self.assertEqual(apply_default_drivers(['sqlite'], mongodb_enabled=False), ['sqlite'])

	def test_json_not_duplicated(self):
		from secator.loader import apply_default_drivers
		self.assertEqual(apply_default_drivers(['json'], mongodb_enabled=False), ['json'])


if __name__ == '__main__':
	unittest.main()

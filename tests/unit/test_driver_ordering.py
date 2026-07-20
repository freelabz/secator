"""Driver ordering regression tests.

Backends were historically selected via an explicit priority so the authoritative
persistence driver (``mongodb``) would win over the relay driver (``api``). When
backend selection was refactored to "derive from the drivers list" the ordering
guarantee — and its test — was dropped. With both drivers attached, ``api`` could
then run its HTTP ``update_runner`` hook before ``mongodb`` wrote status straight
to the DB, leaving runners stuck in PENDING. These tests pin the ordering so
``mongodb`` (and other DB/storage drivers) always prevail over ``api``.
"""

import unittest

from secator.loader import order_drivers


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
		# Priority (DRIVER_PRIORITY): gcs (enrichment), then backends mongodb >
		# sqlite > api; unranked drivers (discord) keep their order at the end.
		self.assertEqual(
			order_drivers(['sqlite', 'api', 'discord', 'gcs', 'mongodb']),
			['gcs', 'mongodb', 'sqlite', 'api', 'discord'],
		)

	def test_unknown_drivers_kept_at_end_in_order(self):
		# External/unknown drivers sort after known ones, preserving their relative order.
		self.assertEqual(
			order_drivers(['custom_b', 'api', 'custom_a', 'mongodb']),
			['mongodb', 'api', 'custom_b', 'custom_a'],
		)

	def test_dedupes_preserving_priority(self):
		self.assertEqual(order_drivers(['api', 'mongodb', 'api']), ['mongodb', 'api'])

	def test_empty(self):
		self.assertEqual(order_drivers([]), [])


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

# tests/unit/test_fanin_query.py
"""RC#6 fan-in: extractors compute targets by querying the DB (id + _type filter
+ projection) instead of materializing/rehydrating the whole accumulated result
set onto the worker heap. Local (no mongodb addon) keeps the in-memory path."""

import tracemalloc
import unittest
from unittest.mock import patch

import pytest

from secator.output_types import Url, Ip, Target
from secator.runners._helpers import (
	_extractor_fields,
	parse_extractor,
	process_extractor,
	run_extractors,
)


class _Poison(list):
	"""A stand-in for the full fan-in that raises if anything iterates it — proves
	the query path never materializes the whole set."""

	def __iter__(self):
		raise AssertionError('the full fan-in was iterated/materialized')


class TestExtractorProjection(unittest.TestCase):
	def test_includes_referenced_and_mandatory_fields(self):
		parsed = parse_extractor({'type': 'url', 'field': 'url', 'condition': "not url.verified"})
		fields = _extractor_fields(parsed)
		# referenced fields present
		self.assertIn('url', fields)
		self.assertIn('verified', fields)
		# mandatory identity/context always present
		for f in ('_type', '_context', '_source', '_uuid', 'name'):
			self.assertIn(f, fields)
		# a field the extractor never mentions is omitted (this is what bounds memory)
		self.assertNotIn('stored_response_path', fields)
		# operator/keyword tokens are not treated as fields
		self.assertNotIn('not', fields)

	def test_string_literals_not_treated_as_fields(self):
		parsed = parse_extractor({'type': 'ip', 'field': 'host', 'condition': "item.alive == 'stored_response_path'"})
		fields = _extractor_fields(parsed)
		self.assertIn('alive', fields)
		# the quoted value must not leak in as a projected field
		self.assertNotIn('stored_response_path', fields)


class TestProcessExtractorFetch(unittest.TestCase):
	def setUp(self):
		self.ips = [Ip(ip='10.0.0.1', host='h1'), Ip(ip='10.0.0.2', host='h2')]
		self.urls = [Url(url='http://a'), Url(url='http://b')]
		self.all = self.ips + self.urls

	def _fetch(self, calls=None):
		def fetch(_type, fields=None):
			if calls is not None:
				calls.append((_type, fields))
			return [r for r in self.all if r._type == _type]
		return fetch

	def test_fetch_used_instead_of_full_set(self):
		calls = []
		ctx = {'fetch_by_type': self._fetch(calls)}
		# The full set is poison — must never be touched when a fetch is provided.
		out = process_extractor(_Poison(self.all), 'ip.host', ctx=ctx)
		self.assertEqual(sorted(out), ['h1', 'h2'])
		self.assertEqual(calls[0][0], 'ip')  # queried only the extractor's type
		# projection was requested (no condition -> still a bounded field list)
		self.assertIsNotNone(calls[0][1])

	def test_condition_still_runs_on_fetched_subset(self):
		ctx = {'fetch_by_type': self._fetch()}
		out = process_extractor(_Poison(self.all), {'type': 'ip', 'field': 'host', 'condition': "item.ip == '10.0.0.2'"}, ctx=ctx)  # noqa: E501
		self.assertEqual(out, ['h2'])

	def test_run_extractors_query_matches_in_memory(self):
		"""Coordinator #1 vs #2: the query (db) path yields the SAME targets as the
		in-memory (local) path for identical inputs + extractor."""
		opts = {'targets_': ['ip.host']}
		# local / in-memory path (no fetch)
		local_inputs, _, _ = run_extractors(list(self.all), dict(opts), [])
		# db / query path (fetch sources candidates; full set is poison)
		ctx = {'fetch_by_type': self._fetch()}
		db_inputs, _, _ = run_extractors(_Poison(self.all), dict(opts), [], ctx=ctx)
		self.assertEqual(sorted(local_inputs), sorted(db_inputs))
		self.assertEqual(sorted(db_inputs), ['h1', 'h2'])


class TestFanInMemoryBound(unittest.TestCase):
	def test_300k_fanin_does_not_materialize(self):
		"""Coordinator #3: a 300k-id fan-in stays within a tiny heap bound because
		only the (few) findings of the extractor's type are ever fetched/built."""
		# 300k cheap id strings — allocated BEFORE measuring so we bound only the
		# extractor work, not the id list itself.
		ids = ['%024x' % i for i in range(300_000)]
		fetched = [Ip(ip='10.0.0.1', host='only-host')]

		fetch_calls = {'n': 0}

		def fetch(_type, fields=None):
			fetch_calls['n'] += 1
			# The fetch is handed the extractor's type only; it returns a tiny subset,
			# never one object per id.
			return list(fetched) if _type == 'ip' else []

		ctx = {'fetch_by_type': fetch}
		tracemalloc.start()
		try:
			inputs, _, _ = run_extractors(_Poison(ids), {'targets_': ['ip.host']}, [], ctx=ctx)
			_, peak = tracemalloc.get_traced_memory()
		finally:
			tracemalloc.stop()

		self.assertEqual(inputs, ['only-host'])
		self.assertEqual(fetch_calls['n'], 1)
		# Materializing 300k Ip objects would be tens/hundreds of MB. The query path
		# builds one — bound generously at 5MB to stay platform-robust.
		self.assertLess(peak, 5 * 1024 * 1024, f'peak {peak} bytes — fan-in likely materialized')


class TestSplitFanin(unittest.TestCase):
	"""Runner._split_fanin: driver-branch. mongodb off -> eager/local (unchanged);
	mongodb on + child -> keep ids cheap, materialize only carried objects."""

	def setUp(self):
		# Reference the LIVE module the code reads (robust to test_config's
		# clear_modules(), which otherwise leaves a module-top CONFIG stale).
		import secator.runners._base as base_mod

		self.base_mod = base_mod
		Runner = base_mod.Runner

		class _FakeRunner:
			has_parent = True

			def debug(self, *a, **k):
				pass

			_query_fanin_enabled = Runner._query_fanin_enabled
			_split_fanin = Runner._split_fanin

		self.FakeRunner = _FakeRunner
		self._orig = base_mod.CONFIG.addons.mongodb.enabled

	def tearDown(self):
		self.base_mod.CONFIG.addons.mongodb.enabled = self._orig

	def _set_mongodb(self, value):
		self.base_mod.CONFIG.addons.mongodb.enabled = value

	def test_local_path_unchanged_when_mongodb_off(self):
		self._set_mongodb(False)
		r = self.FakeRunner()
		results = [Url(url='http://a'), Target(name='t')]
		prior_ids, out = r._split_fanin(results)
		self.assertIsNone(prior_ids)
		self.assertEqual(out, results)

	def test_lazy_path_keeps_ids_and_carried_objects(self):
		self._set_mongodb(True)
		r = self.FakeRunner()  # has_parent True -> lazy
		target = Target(name='sub.example.com')
		results = ['%024x' % 1, '%024x' % 2, target]  # 2 finding ids + 1 carried object
		prior_ids, out = r._split_fanin(results)
		self.assertEqual(prior_ids, ['%024x' % 1, '%024x' % 2])
		self.assertEqual(out, [target])  # only the carried object is materialized

	def test_root_runner_stays_eager(self):
		self._set_mongodb(True)
		r = self.FakeRunner()
		r.has_parent = False  # root -> eager path (calls get_results)
		with patch('secator.hooks.mongodb.get_results', side_effect=lambda x: list(x)) as gr:
			prior_ids, out = r._split_fanin(['x'])
			self.assertIsNone(prior_ids)
			gr.assert_called_once()


class TestGetResultsFilter(unittest.TestCase):
	"""get_results(uuids, types, fields) pushes the _type filter + projection into
	the Mongo query so an extractor rehydrates only the subset it needs."""

	def setUp(self):
		pytest.importorskip('pymongo')

	def test_type_and_projection_pushed_to_query(self):
		from unittest.mock import MagicMock
		import secator.hooks.mongodb as m

		captured = {}

		def _find(query, projection=None):
			captured['query'] = query
			captured['projection'] = projection
			return [{'_id': m.ObjectId(), '_type': 'ip', 'ip': '10.0.0.1', 'host': 'h1', '_context': {}}]

		client = MagicMock()
		client.main.findings.find.side_effect = _find

		ids = ['%024x' % 1, '%024x' % 2]
		with patch.object(m, 'get_mongodb_client', return_value=client):
			out = list(m.get_results(ids, types=['ip'], fields=['host', '_type', '_context']))

		self.assertEqual(captured['query']['_type'], {'$in': ['ip']})
		self.assertIn('_id', captured['query'])
		self.assertEqual(captured['projection'], {'host': 1, '_type': 1, '_context': 1})
		self.assertEqual(len(out), 1)
		self.assertEqual(out[0]._type, 'ip')

	def test_carried_objects_filtered_by_type(self):
		from unittest.mock import MagicMock
		import secator.hooks.mongodb as m

		client = MagicMock()
		client.main.findings.find.side_effect = lambda q, p=None: []
		# Build carried objects from the SAME OUTPUT_TYPES generation get_results
		# uses, so isinstance() holds even after test_config's clear_modules().
		UrlCls = next(c for c in m.OUTPUT_TYPES if c.get_name() == 'url')
		TargetCls = next(c for c in m.OUTPUT_TYPES if c.get_name() == 'target')
		carried_url = UrlCls(url='http://a')
		carried_target = TargetCls(name='t')
		with patch.object(m, 'get_mongodb_client', return_value=client):
			# only 'target'-typed carried objects should pass through
			out = list(m.get_results([carried_url, carried_target], types=['target']))
		self.assertEqual([o._type for o in out], ['target'])

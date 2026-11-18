"""Base-query parity across query backends + extractor chaining through the api backend.

Every store backend must enforce the same base query. In particular none of them may
require ``_tagged: True``: a finding is written untagged and only gets tagged later by
an out-of-band dedup pass, so a ``_tagged`` filter hides every finding of a run that is
still in progress — a workflow's downstream tasks then resolve no inputs.
"""
import unittest
from unittest import mock

from secator.query import QueryEngine
from secator.query.api import ApiBackend
from secator.query.json import match_query
from secator.query.mongodb import MongoDBBackend
from secator.query.sqlite import SqliteBackend
from secator.runners._helpers import run_extractors

WS = 'ws123'
STORE_BACKENDS = (ApiBackend, MongoDBBackend, SqliteBackend)


class TestBaseQueryParity(unittest.TestCase):

	def test_store_backends_share_the_same_base_query(self):
		queries = {cls.name: cls(workspace_id=WS).get_base_query() for cls in STORE_BACKENDS}
		expected = {'_context.workspace_id': WS, 'is_false_positive': {'$ne': True}}
		for name, base in queries.items():
			with self.subTest(backend=name):
				self.assertEqual(base, expected)

	def test_no_backend_filters_on_tagged(self):
		for cls in STORE_BACKENDS:
			with self.subTest(backend=cls.name):
				merged = cls(workspace_id=WS)._merge_query({'_type': 'port'})
				self.assertNotIn('_tagged', merged)

	def test_caller_supplied_tagged_filter_is_kept(self):
		# Dropping the enforced filter must not strip an explicit one from the caller.
		for cls in STORE_BACKENDS:
			with self.subTest(backend=cls.name):
				merged = cls(workspace_id=WS)._merge_query({'_tagged': True})
				self.assertIs(merged['_tagged'], True)


def _port(host, port, workflow_id='wf1', service_name='', **extra):
	doc = {
		'_type': 'port', 'host': host, 'port': port, 'ip': host, 'service_name': service_name,
		'_context': {'workspace_id': WS, 'workflow_id': workflow_id},
	}
	doc.update(extra)
	return doc


class FakeApiStore:
	"""Minimal stand-in for the api driver's search endpoint: applies the posted query to an
	in-memory list of docs, the way a document store would."""

	def __init__(self, docs):
		self.docs = docs
		self.queries = []

	def __call__(self, method, endpoint, data=None):
		from urllib.parse import parse_qs, urlparse
		self.queries.append(data)
		params = parse_qs(urlparse(endpoint).query)
		skip = int(params.get('skip', ['0'])[0])
		limit = int(params.get('limit', ['0'])[0])
		items = [dict(d) for d in self.docs if match_query(d, data or {})]
		page = items[skip:skip + limit] if limit else items[skip:]
		return {'items': page, 'total': len(items)}


class TestApiWorkflowChaining(unittest.TestCase):
	"""A workflow run with the api driver chains a task's findings into the next task's inputs."""

	def setUp(self):
		self.store = FakeApiStore([
			# Fresh, still-untagged findings of the current run (field explicit or absent).
			_port('10.0.0.1', 22, service_name='ssh', _tagged=False),
			_port('10.0.0.1', 80),
			_port('10.0.0.2', 443, _tagged=False),
			# Same port reported twice (e.g. by two chunks): must not yield duplicate inputs.
			_port('10.0.0.2', 443, _tagged=False),
			# Already tagged by a dedup pass: still a valid input.
			_port('10.0.0.3', 8080, _tagged=True),
			# Marked false positive: excluded by the base query.
			_port('10.0.0.4', 8443, is_false_positive=True),
			# Another run in the same workspace: excluded by the run scope.
			_port('10.9.9.9', 80, workflow_id='other'),
		])
		patcher = mock.patch.object(ApiBackend, '_make_request', side_effect=self.store)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.ctx = {'drivers': ['api'], 'workspace_id': WS, 'workflow_id': 'wf1'}

	def test_engine_uses_api_backend(self):
		self.assertIsInstance(QueryEngine(WS, context=self.ctx).backend, ApiBackend)

	def test_downstream_task_gets_untagged_findings_as_inputs(self):
		opts = {'targets_': [{'type': 'port', 'field': '{host}:{port}'}]}
		inputs, _, messages = run_extractors([], opts, inputs=['seed'], ctx=dict(self.ctx))
		self.assertEqual(messages, [])
		self.assertEqual(sorted(inputs), ['10.0.0.1:22', '10.0.0.1:80', '10.0.0.2:443', '10.0.0.3:8080'])
		for query in self.store.queries:
			self.assertNotIn('_tagged', query)
			self.assertEqual(query['_context.workflow_id'], 'wf1')

	def test_conditional_extractor_on_untagged_findings(self):
		opts = {'targets_': [{'type': 'port', 'field': 'host', 'condition': 'port.port == 22 or port.service_name ~= ssh'}]}
		inputs, _, _ = run_extractors([], opts, inputs=['seed'], ctx=dict(self.ctx))
		self.assertEqual(inputs, ['10.0.0.1'])

	def test_option_extractor_dedupes_values(self):
		opts = {'ports_': [{'type': 'port', 'field': 'port', 'condition': "port.host == '10.0.0.2'"}]}
		_, opts, _ = run_extractors([], opts, inputs=['seed'], ctx=dict(self.ctx))
		self.assertEqual(opts['ports'], ['443'])

	def test_runner_view_counts_untagged_findings(self):
		engine = QueryEngine(WS, context=self.ctx)
		results = engine.search({'_context.workflow_id': 'wf1', '_type': 'port'})
		self.assertEqual(len(results), 5)

	def test_dedupe_limit_counts_unique_findings(self):
		# 10.0.0.2:443 is stored twice: a raw `limit` page must not let the duplicate take a slot.
		engine = QueryEngine(WS, context=self.ctx)
		query = {'_context.workflow_id': 'wf1', '_type': 'port', 'host': {'$in': ['10.0.0.2', '10.0.0.3']}}
		results = engine.search(query, limit=2, dedupe=True)
		self.assertEqual(sorted((r['host'], r['port']) for r in results), [('10.0.0.2', 443), ('10.0.0.3', 8080)])
		self.assertEqual(len(engine.search(query, limit=1, dedupe=True)), 1)


if __name__ == '__main__':
	unittest.main()

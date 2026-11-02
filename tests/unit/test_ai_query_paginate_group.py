import unittest

from secator.ai.actions import ActionContext, _handle_query
from secator.output_types import Error, Info


class _FakeBackend:
	name = 'mongodb'


class _FakeEngine:
	"""Fake QueryEngine that pages an in-memory list via limit/offset and counts."""

	def __init__(self, findings):
		self.findings = findings
		self.backend = _FakeBackend()
		self.search_calls = []
		self.count_calls = 0

	def search(self, query, limit=0, offset=0, **kwargs):
		self.search_calls.append({'query': query, 'limit': limit, 'offset': offset})
		items = self.findings
		if offset:
			items = items[offset:]
		if limit:
			items = items[:limit]
		return [dict(f) for f in items]

	def count(self, query):
		self.count_calls += 1
		return len(self.findings)


def _vuln(uuid, name, matched_at):
	return {
		'_type': 'vulnerability',
		'_uuid': uuid,
		'name': name,
		'matched_at': matched_at,
		'severity': 'high',
		'_timestamp': 1,
		'_context': {},
	}


def _ctx(engine):
	return ActionContext(
		targets=[], model='m',
		context={'workspace_id': 'ws1'},
		_query_engine=engine,
	)


class TestPagination(unittest.TestCase):
	def test_offset_threads_into_backend(self):
		findings = [_vuln(str(i), f'v{i}', f'h{i}') for i in range(10)]
		engine = _FakeEngine(findings)
		action = {'query': {'_type': 'vulnerability'}, 'limit': 3, 'offset': 3}
		out = list(_handle_query(action, _ctx(engine)))
		self.assertEqual(engine.search_calls[0]['offset'], 3)
		self.assertEqual(engine.search_calls[0]['limit'], 3)
		uuids = [r['_uuid'] for r in out if isinstance(r, dict) and r.get('_type') == 'vulnerability']
		self.assertEqual(uuids, ['3', '4', '5'])

	def test_pagination_info_only_when_more(self):
		# 10 findings, full page of 3 at offset 0 -> there IS more -> Info emitted.
		findings = [_vuln(str(i), f'v{i}', f'h{i}') for i in range(10)]
		engine = _FakeEngine(findings)
		out = list(_handle_query({'query': {'_type': 'vulnerability'}, 'limit': 3}, _ctx(engine)))
		infos = [o for o in out if isinstance(o, Info)]
		self.assertEqual(len(infos), 1)
		self.assertIn('offset=3', infos[0].message)
		self.assertEqual(engine.count_calls, 1)

	def test_no_pagination_info_on_partial_page(self):
		# page not full -> no count, no Info note.
		findings = [_vuln(str(i), f'v{i}', f'h{i}') for i in range(2)]
		engine = _FakeEngine(findings)
		out = list(_handle_query({'query': {'_type': 'vulnerability'}, 'limit': 100}, _ctx(engine)))
		self.assertEqual([o for o in out if isinstance(o, Info)], [])
		self.assertEqual(engine.count_calls, 0)

	def test_no_pagination_info_when_full_page_is_all(self):
		# full page but total == page -> no more -> no Info.
		findings = [_vuln(str(i), f'v{i}', f'h{i}') for i in range(3)]
		engine = _FakeEngine(findings)
		out = list(_handle_query({'query': {'_type': 'vulnerability'}, 'limit': 3}, _ctx(engine)))
		self.assertEqual([o for o in out if isinstance(o, Info)], [])


class TestGrouping(unittest.TestCase):
	def test_group_returns_reps_with_count_and_uuid(self):
		findings = [
			_vuln('a1', 'CVE-1', 'host-a'),
			_vuln('a2', 'CVE-1', 'host-b'),
			_vuln('b1', 'CVE-2', 'host-c'),
		]
		engine = _FakeEngine(findings)
		out = list(_handle_query({'query': {'_type': 'vulnerability'}, 'group': True}, _ctx(engine)))
		reps = [o for o in out if isinstance(o, dict) and o.get('_type') == 'vulnerability']
		self.assertEqual(len(reps), 2)  # grouped by name -> 2 groups
		by_name = {r['name']: r for r in reps}
		self.assertEqual(by_name['CVE-1']['_group_count'], 2)
		self.assertEqual(by_name['CVE-2']['_group_count'], 1)
		# _uuid preserved as the drill-down handle
		self.assertTrue(all(r['_uuid'] for r in reps))
		# aggregated matched_at carries both targets of the CVE-1 group
		self.assertIn('host-a', by_name['CVE-1']['matched_at'])
		self.assertIn('host-b', by_name['CVE-1']['matched_at'])

	def test_group_without_single_type_errors(self):
		engine = _FakeEngine([])
		# _type is operator-wrapped (ambiguous) -> clear Error, no results.
		action = {'query': {'_type': {'$in': ['vulnerability', 'port']}}, 'group': True}
		out = list(_handle_query(action, _ctx(engine)))
		errors = [o for o in out if isinstance(o, Error)]
		self.assertEqual(len(errors), 1)
		self.assertIn('_type', errors[0].message)
		self.assertEqual(engine.search_calls, [])

	def test_group_missing_type_errors(self):
		engine = _FakeEngine([])
		out = list(_handle_query({'query': {'severity': 'high'}, 'group': True}, _ctx(engine)))
		self.assertEqual(len([o for o in out if isinstance(o, Error)]), 1)


if __name__ == '__main__':
	unittest.main()

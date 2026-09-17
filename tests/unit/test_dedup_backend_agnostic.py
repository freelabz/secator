"""Backend-agnostic on-demand duplicate tagging (`_dedup.tag_duplicates(engine, ws_id)`).

The generic core reads via `backend._execute_search` and writes each update keyed on the uniform
`_uuid` via `backend._execute_update` — so a fake backend (dicts + the json matcher/setter, the same
primitives every real backend implements) proves the behavior for all of them.
"""
import unittest

from secator.query.json import match_query, _set_nested, get_nested_field
from secator.query.mongodb import _carry_uuid
from secator.hooks._dedup import tag_duplicates, maybe_tag_duplicates


class FakeBackend:
	name = 'fake'

	def __init__(self, findings, ws='ws1'):
		self.docs = findings
		self.workspace_id = ws

	def _execute_search(self, query, limit=0):
		out = [d for d in self.docs if match_query(d, query)]
		return out[:limit] if limit else out

	def _execute_update(self, query, update):
		n = 0
		for d in self.docs:
			if match_query(d, query):
				for k, v in update.get('$set', {}).items():
					_set_nested(d, k, v)
				n += 1
		return n


class FakeEngine:
	def __init__(self, backend):
		self.backend = backend


def _vuln(name, matched_at, uuid):
	return {
		'_type': 'vulnerability', 'name': name, 'matched_at': matched_at, 'severity': 'high',
		'_uuid': uuid, '_context': {'workspace_id': 'ws1'},
	}


class TestGenericTagDuplicates(unittest.TestCase):

	def test_marks_exactly_one_of_a_duplicate_pair(self):
		# Two identical XSS (same name+matched_at, different uuid) + one distinct SQLi, none tagged.
		findings = [_vuln('XSS', 'a', 'u1'), _vuln('XSS', 'a', 'u2'), _vuln('SQLi', 'b', 'u3')]
		n = tag_duplicates(FakeEngine(FakeBackend(findings)), 'ws1')
		self.assertEqual(n, 3)                                   # all three get a tagging update
		dup = [d for d in findings if get_nested_field(d, '_context.workspace_duplicate') is True]
		self.assertEqual(len(dup), 1)                            # exactly one XSS flagged duplicate
		kept = [d for d in findings if get_nested_field(d, '_context.workspace_duplicate') is not True]
		self.assertEqual({d['name'] for d in kept}, {'XSS', 'SQLi'})   # one XSS main + the SQLi survive

	def test_api_backend_is_skipped(self):
		findings = [_vuln('XSS', 'a', 'u1'), _vuln('XSS', 'a', 'u2')]
		be = FakeBackend(findings)
		be.name = 'api'
		self.assertEqual(maybe_tag_duplicates(FakeEngine(be), 'ws1'), 0)   # server tags its own store
		self.assertTrue(all('workspace_duplicate' not in d.get('_context', {}) for d in findings))


class TestBackendIdHelpers(unittest.TestCase):

	def test_mongo_carry_uuid_surfaces_native_id(self):
		doc = _carry_uuid({'_id': 'abc123', '_type': 'port'})
		self.assertEqual(doc.get('_uuid'), 'abc123')
		self.assertNotIn('_id', doc)                             # native id dropped, uniform id surfaced

	def test_mongo_carry_uuid_keeps_existing_uuid(self):
		doc = _carry_uuid({'_id': 'x', '_uuid': 'keep', '_type': 'port'})
		self.assertEqual(doc['_uuid'], 'keep')

	def test_json_set_nested_creates_path(self):
		d = {}
		_set_nested(d, '_context.workspace_duplicate', True)
		self.assertEqual(d, {'_context': {'workspace_duplicate': True}})
		_set_nested(d, '_tagged', True)
		self.assertIs(d['_tagged'], True)                        # bare key = plain assignment


if __name__ == '__main__':
	unittest.main()

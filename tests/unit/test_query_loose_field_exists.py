"""Loose-field inequality operators must ignore findings that lack the field (or carry a null).

Bug: `secator q "severity != 'critical'"` returned findings that have no `severity` at all
(Port, Subdomain, ...). A loose negating operator (`!=` / `not in` / `!~=`) now keeps only
findings that carry a real, differing value — the parser folds `null` into a `$nin` (which every
backend already drops for BOTH absent and null) and pins `$exists` for Mongo. This needs no
backend-specific code, so the result is identical on json, sqlite, and (via the emitted query)
mongo/api.
"""
import json
import sqlite3
import unittest

from secator.query.json import match_query
from secator.query.sqlite import _build_where
from secator.query.utils import python_expr_to_mongo


# Mixed workspace: a Port with NO severity (absent), vulns with high/critical, and one present
# null. "severity != critical" keeps only findings with a real, non-critical value -> just x.
DATASET = [
	{'_type': 'port', 'name': 'p', 'host': 'h1', 'port': 443},   # severity absent
	{'_type': 'vulnerability', 'name': 'x', 'severity': 'high'},
	{'_type': 'vulnerability', 'name': 'y', 'severity': 'critical'},
	{'_type': 'vulnerability', 'name': 'z', 'severity': None},    # severity present but null
]


class TestLooseNegationParser(unittest.TestCase):

	def test_loose_ne_folds_null_and_pins_exists(self):
		self.assertEqual(
			python_expr_to_mongo("severity != 'critical'"),
			{'severity': {'$nin': ['critical', None], '$exists': True}},
		)

	def test_loose_not_in_appends_null(self):
		q = python_expr_to_mongo("severity not in [critical, high]")
		self.assertIn(None, q['severity']['$nin'])
		self.assertTrue(q['severity']['$exists'])

	def test_loose_not_regex_excludes_null_and_pins_exists(self):
		q = python_expr_to_mongo("severity !~= crit")
		self.assertIn('$not', q['severity'])
		self.assertEqual(q['severity']['$nin'], [None])
		self.assertTrue(q['severity']['$exists'])

	def test_typed_ne_passes_through(self):
		# A type-scoped field is already constrained by `_type`; left as a plain $ne.
		self.assertEqual(
			python_expr_to_mongo("vulnerability.severity != critical"),
			{'_type': 'vulnerability', 'severity': {'$ne': 'critical'}},
		)

	def test_positive_in_unaffected(self):
		self.assertEqual(
			python_expr_to_mongo("severity in [high, critical]"),
			{'severity': {'$in': ['high', 'critical']}},
		)


def _filter_sqlite(dataset, q):
	conn = sqlite3.connect(':memory:')
	conn.execute('CREATE TABLE findings (data TEXT)')
	conn.executemany('INSERT INTO findings (data) VALUES (?)', [(json.dumps(d),) for d in dataset])
	where, params = _build_where(q)
	rows = conn.execute(f"SELECT data FROM findings WHERE {where or '1=1'}", params).fetchall()
	return [json.loads(d) for (d,) in rows]


class TestLooseNegationBackends(unittest.TestCase):

	def setUp(self):
		self.q = python_expr_to_mongo("severity != 'critical'")

	def test_json_excludes_absent_and_present_null(self):
		got = [d['name'] for d in DATASET if match_query(d, self.q)]
		self.assertEqual(got, ['x'])  # absent Port + present-null z dropped; critical y dropped

	def test_sqlite_excludes_absent_and_present_null(self):
		got = [d['name'] for d in _filter_sqlite(DATASET, self.q)]
		self.assertEqual(got, ['x'])

	def test_json_and_sqlite_agree(self):
		# "Works for all backends, always": json + sqlite must return the same names.
		json_names = [d['name'] for d in DATASET if match_query(d, self.q)]
		sqlite_names = [d['name'] for d in _filter_sqlite(DATASET, self.q)]
		self.assertEqual(json_names, sqlite_names)


if __name__ == '__main__':
	unittest.main()

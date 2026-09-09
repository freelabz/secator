"""Loose-field inequality operators must ignore findings that lack the field.

Bug: `secator q "severity != 'critical'"` returned findings that don't carry `severity` at all
(Port, Subdomain, ...), because `$ne`/`$nin`/`$not` match absent fields on Mongo/API/json. The
parser now pins `$exists: True` on a loose negating operator ("has the field AND value differs"),
and every backend honors `$exists`. Proven across the parser, the json + sqlite backends, and —
via the emitted query — mongo/api, which handle `$exists` natively.
"""
import json
import sqlite3
import unittest

from secator.query.json import match_query
from secator.query.sqlite import _build_where
from secator.query.utils import python_expr_to_mongo


# A mixed workspace: a Port with no `severity`, and two Vulnerabilities.
DATASET = [
	{'_type': 'port', 'name': 'p', 'host': 'h1', 'port': 443},   # no severity
	{'_type': 'vulnerability', 'name': 'x', 'severity': 'high'},
	{'_type': 'vulnerability', 'name': 'y', 'severity': 'critical'},
]


class TestLooseFieldExistsParser(unittest.TestCase):

	def test_loose_ne_pins_exists(self):
		self.assertEqual(
			python_expr_to_mongo("severity != 'critical'"),
			{'severity': {'$ne': 'critical', '$exists': True}},
		)

	def test_loose_not_in_pins_exists(self):
		q = python_expr_to_mongo("severity not in [critical, high]")
		self.assertTrue(q['severity']['$exists'])
		self.assertIn('$nin', q['severity'])

	def test_loose_not_regex_pins_exists(self):
		q = python_expr_to_mongo("severity !~= crit")
		self.assertTrue(q['severity']['$exists'])
		self.assertIn('$not', q['severity'])

	def test_typed_ne_does_not_pin_exists(self):
		# A type-scoped field is already constrained by `_type`; no $exists needed.
		self.assertEqual(
			python_expr_to_mongo("vulnerability.severity != critical"),
			{'_type': 'vulnerability', 'severity': {'$ne': 'critical'}},
		)

	def test_positive_in_unaffected(self):
		q = python_expr_to_mongo("severity in [high, critical]")
		self.assertNotIn('$exists', q.get('severity', {}))


def _filter_sqlite(dataset, q):
	conn = sqlite3.connect(':memory:')
	conn.execute('CREATE TABLE findings (data TEXT)')
	conn.executemany('INSERT INTO findings (data) VALUES (?)', [(json.dumps(d),) for d in dataset])
	where, params = _build_where(q)
	rows = conn.execute(f"SELECT data FROM findings WHERE {where or '1=1'}", params).fetchall()
	return [json.loads(d) for (d,) in rows]


class TestLooseFieldExistsBackends(unittest.TestCase):

	def setUp(self):
		self.q = python_expr_to_mongo("severity != 'critical'")

	def test_json_backend_excludes_missing_field(self):
		got = [d['name'] for d in DATASET if match_query(d, self.q)]
		self.assertEqual(got, ['x'])  # only the 'high' vuln — not the Port, not the 'critical' vuln

	def test_sqlite_backend_excludes_missing_field(self):
		got = [d['name'] for d in _filter_sqlite(DATASET, self.q)]
		self.assertEqual(got, ['x'])

	def test_mongo_api_query_carries_exists(self):
		# mongo + api pass the query through natively; the emitted $exists is what fixes them.
		self.assertTrue(self.q['severity'].get('$exists'))


if __name__ == '__main__':
	unittest.main()

"""Cross-backend parity: the same query over the same findings returns the same results on
the json, sqlite, mongodb (mongomock) and api drivers.

The api driver forwards the merged query to a remote search endpoint; here that endpoint is
simulated by evaluating the forwarded query on a mongomock collection, so the test checks
what the driver actually sends.
"""
import json
import re
import shutil
import tempfile
from pathlib import Path

import orjson
import pytest

mongomock = pytest.importorskip('mongomock')

from secator.query._base import normalize_query_operators, strip_leading_glob  # noqa: E402

WS = 'ws'


def _finding(uuid, url, **extra):
	return {
		'_type': 'url', '_uuid': uuid, 'url': url, 'is_false_positive': False, '_tagged': True,
		'_context': {'workspace_id': WS}, **extra,
	}


FINDINGS = [
	_finding('u1', 'http://example.com/Admin/login'),
	_finding('u2', 'http://example.com/static/app.js'),
	_finding('u3', 'http://example.com/100%_off'),
	_finding('u4', 'http://example.com/1000_off'),
	_finding('u5', 'http://example.com/admin-old', is_false_positive=True),
]


class _Backends:
	"""Seeds the same findings in every driver and builds one backend per driver."""

	def __init__(self, findings):
		self.findings = findings
		self.tmp = Path(tempfile.mkdtemp())

	def close(self):
		import secator.hooks.sqlite as sqlite_mod
		for conn in sqlite_mod._conns.values():
			conn.close()
		sqlite_mod._conns.clear()
		shutil.rmtree(self.tmp)

	def json(self):
		from secator.query.json import JsonBackend
		run_dir = self.tmp / 'tasks' / '0'
		run_dir.mkdir(parents=True, exist_ok=True)
		with open(run_dir / 'results.ndjson', 'wb') as f:
			for rec in self.findings:
				f.write(orjson.dumps(rec) + b'\n')
		return JsonBackend(WS, context={'report_dir': str(run_dir)})

	def sqlite(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.query.sqlite import SqliteBackend
		db_path = str(self.tmp / 'parity.db')
		conn = sqlite_mod.get_sqlite_conn(db_path)
		conn.executemany(
			'INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) '
			'VALUES (?, ?, ?, ?, ?, ?)',
			[(f['_uuid'], f['_type'], WS, int(f['is_false_positive']), int(f['_tagged']), json.dumps(f))
				for f in self.findings])
		conn.commit()
		return SqliteBackend(WS, config={'db_path': db_path})

	def _collection(self):
		client = mongomock.MongoClient()
		client.main.findings.insert_many([dict(f) for f in self.findings])
		return client

	def mongodb(self):
		from secator.query.mongodb import MongoDBBackend
		backend = MongoDBBackend(WS)
		backend._client = self._collection()
		return backend

	def api(self):
		from secator.query.api import ApiBackend
		client = self._collection()
		backend = ApiBackend(WS)
		backend.sent = []

		def fake_request(method, endpoint, data=None):
			backend.sent.append(data)
			docs = list(client.main.findings.find(data or {}))
			for d in docs:
				d.pop('_id', None)
			return {'items': docs}

		backend._make_request = fake_request
		return backend


@pytest.fixture
def backends():
	b = _Backends(FINDINGS)
	yield b
	b.close()


DRIVERS = ('json', 'sqlite', 'mongodb', 'api')


def _uuids(backend, query):
	return sorted(r['_uuid'] for r in backend.search(dict(query)))


@pytest.mark.parametrize('driver', DRIVERS)
@pytest.mark.parametrize('query, expected', [
	# A finding marked false positive is hidden from normal reads on every driver.
	({'_type': 'url'}, ['u1', 'u2', 'u3', 'u4']),
	# Leading-glob habit: `*admin` means "contains admin" (a leading `*` is an invalid regex).
	({'_type': 'url', 'url': {'$regex': '(?i)*admin'}}, ['u1']),
	({'_type': 'url', 'url': {'$regex': '**\\.js$'}}, ['u2']),
	({'_type': 'url', 'url': {'$not': {'$regex': '(?i)*admin'}}}, ['u2', 'u3', 'u4']),
	# $contains: literal, case-insensitive substring (no LIKE wildcards, no regex metacharacters).
	({'_type': 'url', 'url': {'$contains': 'ADMIN'}}, ['u1']),
	({'_type': 'url', 'url': {'$contains': '100%_'}}, ['u3']),
	({'_type': 'url', 'url': {'$contains': '.js'}}, ['u2']),
	({'$or': [{'url': {'$contains': 'app.JS'}}, {'url': {'$regex': '*login'}}]}, ['u1', 'u2']),
	# $options flags apply on every driver (folded into an inline group).
	({'_type': 'url', 'url': {'$regex': 'ADMIN', '$options': 'i'}}, ['u1']),
	({'_type': 'url', 'url': {'$regex': '(?s)*admin', '$options': 'i'}}, ['u1']),
])
def test_search_parity(backends, driver, query, expected):
	backend = getattr(backends, driver)()
	assert _uuids(backend, query) == expected


@pytest.mark.parametrize('driver', DRIVERS)
def test_scope_only_read_includes_false_positives(backends, driver):
	backend = getattr(backends, driver)()
	results = backend.search({'_type': 'url', '_uuid': 'u5'}, scope_only=True)
	assert [r['_uuid'] for r in results] == ['u5']


def test_api_forwards_normalized_query(backends):
	backend = backends.api()
	backend.search({'_type': 'url', 'url': {'$contains': 'a.b'}})
	sent = backend.sent[-1]
	assert sent['url'] == {'$regex': '(?i)a\\.b'}
	assert sent['is_false_positive'] == {'$ne': True}


def test_normalize_query_operators():
	q = {'a': {'$contains': 'x.y'}, '$and': [{'b': {'$regex': '(?i)**z'}}], 'c': {'$not': {'$regex': '*w'}}}
	out = normalize_query_operators(q)
	assert out == {'a': {'$regex': '(?i)x\\.y'}, '$and': [{'b': {'$regex': '(?i)z'}}], 'c': {'$not': {'$regex': 'w'}}}
	assert q['a'] == {'$contains': 'x.y'}  # input untouched
	with pytest.raises(ValueError):
		normalize_query_operators({'a': {'$contains': 'x', '$regex': 'y'}})


def test_strip_leading_glob():
	assert strip_leading_glob('*foo') == 'foo'
	assert strip_leading_glob('(?i)**foo') == '(?i)foo'
	assert strip_leading_glob('fo*o') == 'fo*o'
	assert strip_leading_glob('(?is)*foo') == '(?is)foo'
	assert strip_leading_glob('(?s)(?i)*foo') == '(?s)(?i)foo'
	assert strip_leading_glob(404) == '404'
	pattern = re.compile('x')
	assert strip_leading_glob(pattern) is pattern


def test_normalize_regex_options():
	assert normalize_query_operators({'a': {'$regex': 'x', '$options': 'si'}}) == {'a': {'$regex': '(?is)x'}}
	assert normalize_query_operators({'a': {'$not': {'$regex': '*x', '$options': 'i'}}}) == {
		'a': {'$not': {'$regex': '(?i)x'}}}
	# Flags no backend reads inline are dropped.
	assert normalize_query_operators({'a': {'$regex': 'x', '$options': 'u'}}) == {'a': {'$regex': 'x'}}

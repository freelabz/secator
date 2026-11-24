"""Datetime-typed finding fields (certificate not_before/not_after, domain dates) written by the
ai task's add_finding / update_finding tools: accepted input formats, rejection of garbage, and
per-driver persistence that matches what the drivers store for a task-produced finding."""
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson

from secator.ai.actions import ActionContext
from secator.ai.tools import TOOLS_BY_NAME
from secator.ai.utils import _coerce_finding_fields
from secator.output_types import Certificate, Domain
from secator.output_types._base import to_datetime
from secator.query import QueryEngine
from secator.query.json import _apply_set, match_query
from secator.serializers.dataclass import DataclassEncoder

HAS_PYMONGO = importlib.util.find_spec('bson') is not None

WS = 'ws1'
UUID = '7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f'
DT = datetime(2026, 11, 21, 20, 10, 23, tzinfo=timezone.utc)
EPOCH = int(DT.timestamp())

ACCEPTED = {
	'iso_space_offset': '2026-11-21 20:10:23+00:00',
	'iso_t_offset': '2026-11-21T20:10:23+00:00',
	'iso_z': '2026-11-21T20:10:23Z',
	'iso_lower_z': '2026-11-21T20:10:23z',
	'iso_naive': '2026-11-21T20:10:23',
	'iso_space_naive': '2026-11-21 20:10:23',
	'iso_other_offset': '2026-11-21T22:10:23+02:00',
	'iso_compact_offset': '2026-11-21T22:10:23+0200',
	'epoch_s': EPOCH,
	'epoch_float': float(EPOCH),
	'epoch_ms': EPOCH * 1000,
	'epoch_s_str': str(EPOCH),
	'mongo_date_iso': {'$date': '2026-11-21T20:10:23Z'},
	'mongo_date_ms': {'$date': EPOCH * 1000},
	'mongo_date_numberlong': {'$date': {'$numberLong': str(EPOCH * 1000)}},
	'datetime_aware': DT,
	'datetime_naive': DT.replace(tzinfo=None),
	'datetime_other_tz': DT.astimezone(timezone(timedelta(hours=-5))),
}
GARBAGE = ['garbage', '', '2026-13-45', True, float('nan'), float('inf'), {'a': 1}, {'$date': 'nope'}, [EPOCH]]


class TestToDatetime(unittest.TestCase):

	def test_accepted_formats(self):
		for name, value in ACCEPTED.items():
			with self.subTest(name):
				out = to_datetime(value)
				self.assertEqual(out, DT)
				self.assertEqual(out.utcoffset(), timedelta(0))

	def test_date_only(self):
		self.assertEqual(to_datetime('2026-11-21'), datetime(2026, 11, 21, tzinfo=timezone.utc))
		self.assertEqual(to_datetime(date(2026, 11, 21)), datetime(2026, 11, 21, tzinfo=timezone.utc))

	def test_fractional_seconds(self):
		self.assertEqual(to_datetime('2026-11-21T20:10:23.5Z'), DT + timedelta(milliseconds=500))
		# nanosecond precision is truncated to microseconds, not rejected
		self.assertEqual(to_datetime('2026-11-21T20:10:23.123456789Z'), DT + timedelta(microseconds=123456))

	def test_short_digit_strings_are_not_epochs(self):
		# a basic ISO date or bare year must never be read as seconds since 1970
		self.assertNotEqual(to_datetime('2026'), datetime(1970, 1, 1, 0, 33, 46, tzinfo=timezone.utc))
		out = to_datetime('20261121')
		self.assertTrue(out is None or out == datetime(2026, 11, 21, tzinfo=timezone.utc))
		self.assertIsNone(to_datetime('1e9'))

	def test_huge_numbers_do_not_raise(self):
		for value in (10 ** 400, -10 ** 400, {'$date': 10 ** 400}, str(10 ** 400)):
			with self.subTest(value=str(value)[:20]):
				self.assertIsNone(to_datetime(value))

	def test_garbage(self):
		for value in GARBAGE:
			with self.subTest(value=value):
				self.assertIsNone(to_datetime(value))


class TestOutputTypeDatetimeFields(unittest.TestCase):

	def test_coerce_and_validate_every_format(self):
		for cls, keys in ((Certificate, ('not_before', 'not_after')),
		                  (Domain, ('creation_date', 'expiration_date', 'updated_date'))):
			for name, value in ACCEPTED.items():
				with self.subTest(cls=cls.__name__, fmt=name):
					data = _coerce_finding_fields(cls, {k: copy.deepcopy(value) for k in keys})
					self.assertEqual(cls.validate_fields(data), [])
					self.assertTrue(all(data[k] == DT for k in keys))

	def test_garbage_rejected_with_format_hint(self):
		data = _coerce_finding_fields(Certificate, {'not_after': 'next tuesday'})
		errors = Certificate.validate_fields(data)
		self.assertEqual(len(errors), 1)
		self.assertIn("'not_after' expected datetime", errors[0])
		self.assertIn('ISO 8601', errors[0])

	def test_schema_names_datetime_format(self):
		self.assertIn('not_after: datetime (ISO 8601', Certificate.schema())

	def test_load_reads_back_every_driver_representation(self):
		# json (orjson) / api (DataclassEncoder) store 'T'-separated ISO, sqlite (json default=str)
		# a space-separated one, mongodb an aware datetime: all must load to the same value.
		cert = Certificate(host='a.com', not_after=DT)
		stored = [
			orjson.loads(orjson.dumps(cert.toDict(), default=str))['not_after'],
			json.loads(json.dumps(cert.toDict(), default=str))['not_after'],
			json.loads(json.dumps(cert.toDict(), cls=DataclassEncoder))['not_after'],
			DT,
			DT.replace(tzinfo=None),  # a non-tz_aware Mongo client returns naive UTC
		]
		for value in stored:
			with self.subTest(value=value):
				self.assertEqual(Certificate.load({'host': 'a.com', 'not_after': value}).not_after, DT)
				self.assertEqual(Domain.load({'domain': 'a.com', 'expiration_date': value}).expiration_date, DT)

	def test_non_utc_aware_datetime_is_converted_not_relabelled(self):
		local = DT.astimezone(timezone(timedelta(hours=2)))
		out = Certificate(host='a.com', not_after=local).not_after
		self.assertEqual(out, DT)
		self.assertEqual(out.utcoffset(), timedelta(0))
		self.assertEqual(out.hour, 20)

	def test_task_produced_datetimes_are_utc(self):
		# Naive datetimes from tasks (testssl, whois parsers) are stored as aware UTC.
		naive = DT.replace(tzinfo=None)
		cert = Certificate(host='a.com', not_before=naive, not_after=naive)
		dom = Domain(domain='a.com', creation_date=naive, expiration_date=naive, updated_date=naive)
		for value in (cert.not_before, cert.not_after, dom.creation_date, dom.expiration_date, dom.updated_date):
			self.assertEqual(value, DT)
			self.assertEqual(value.utcoffset(), timedelta(0))


class _FakeCursor(list):
	def skip(self, n):
		return _FakeCursor(self[n:])

	def limit(self, n):
		return _FakeCursor(self[:n] if n else self)


class _FakeFindings:
	def __init__(self, docs):
		self.docs = docs

	def find(self, query, projection=None):
		return _FakeCursor(copy.deepcopy(d) for d in self.docs if match_query(d, query))

	def update_one(self, query, update):
		for d in self.docs:
			if match_query(d, query):
				_apply_set(d, update['$set'])
				return MagicMock(modified_count=1)
		return MagicMock(modified_count=0)


def _task_cert():
	"""A certificate as a task emits it (datetimes set), before any driver serialization."""
	cert = Certificate(
		host='a.com', subject_cn='a.com', not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
		not_after=datetime(2025, 6, 1, tzinfo=timezone.utc), _uuid=UUID, _context={'workspace_id': WS})
	data = cert.toDict()
	data['_tagged'] = True
	return data


class TestUpdateFindingDatetimePerDriver(unittest.TestCase):
	"""update_finding on a certificate's dates: the stored value has the same representation the
	driver uses for a task-produced certificate, and reads back to the same datetime."""

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.tmp, True)

	def _engine(self, driver):
		engine = QueryEngine(WS, context={'drivers': [driver]} if driver != 'json' else {})
		self.reference = None  # how this driver stores a task-produced datetime
		if driver == 'json':
			# Same serialization as the json driver hook (orjson, default=str).
			(self.tmp / 'results.ndjson').write_text(orjson.dumps(_task_cert(), default=str).decode() + '\n')
			engine.backend.context['report_dir'] = str(self.tmp)
			self.reference = orjson.loads(orjson.dumps({'d': DT}, default=str))['d']
		elif driver == 'sqlite':
			from secator.hooks.sqlite import get_sqlite_conn
			from secator.query.sqlite import SqliteBackend
			db_path = str(self.tmp / 'store.db')
			conn = get_sqlite_conn(db_path)
			conn.execute(
				'INSERT OR REPLACE INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) '
				'VALUES (?, ?, ?, 0, 1, ?)',
				(UUID, 'certificate', WS, json.dumps(_task_cert(), default=str)))  # sqlite hook serialization
			conn.commit()
			engine.backend = SqliteBackend(WS, config={'db_path': db_path})
			self.reference = json.loads(json.dumps({'d': DT}, default=str))['d']
		elif driver == 'mongodb':
			client = MagicMock()
			client.main.findings = _FakeFindings([_task_cert()])  # mongodb hook stores toDict() as-is
			engine.backend._client = client
			self.reference = DT
		elif driver == 'api':
			# Mock the HTTP layer (not _make_request) so the request body serialization is exercised.
			docs = [json.loads(json.dumps(dict(_task_cert(), _id='oid1'), cls=DataclassEncoder))]  # api hook encoder
			self.reference = json.loads(json.dumps({'d': DT}, cls=DataclassEncoder))['d']

			def fake_request(method, url, data=None, **kwargs):
				body = json.loads(data) if data else {}
				resp = MagicMock(status_code=200)
				if method == 'POST':
					resp.json.return_value = {'items': [dict(d) for d in docs if match_query(d, body or {})]}
				else:
					_apply_set(docs[0], body)
					resp.json.return_value = {'success': True}
				return resp
			patcher = patch('secator.query.api.requests.request', side_effect=fake_request)
			patcher.start()
			self.addCleanup(patcher.stop)
		return engine

	def _run(self, engine, tool_name, action):
		tool = TOOLS_BY_NAME[tool_name]
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': WS})
		ctx._query_engine = engine
		return list(tool.run({'action': tool.action, **action}, ctx))

	def _check(self, driver):
		# includes non-UTC offsets: the stored value must be the UTC instant, serialized exactly like
		# a task-produced (UTC) datetime on that driver.
		for name in ('iso_space_offset', 'iso_t_offset', 'iso_other_offset', 'iso_compact_offset', 'iso_naive',
		             'epoch_s', 'epoch_ms', 'mongo_date_iso'):
			with self.subTest(fmt=name):
				engine = self._engine(driver)
				out = self._run(engine, 'update_finding', {
					'_uuid': UUID, 'fields': {'not_before': ACCEPTED[name], 'not_after': ACCEPTED[name]}})
				self.assertEqual([o.message for o in out if o._type == 'error'], [])
				stored = engine.search({'_uuid': UUID}, limit=1, scope_only=True)[0]
				self.assertEqual(stored['not_after'], self.reference)
				self.assertEqual(stored['not_before'], self.reference)
				self.assertEqual(type(stored['not_after']), type(self.reference))
				if isinstance(stored['not_after'], str):
					self.assertTrue(stored['not_after'].endswith('+00:00'), stored['not_after'])
				else:
					self.assertEqual(stored['not_after'].utcoffset(), timedelta(0))
				loaded = Certificate.load(stored)
				self.assertEqual((loaded.not_before, loaded.not_after), (DT, DT))

	def _check_garbage(self, driver):
		engine = self._engine(driver)
		out = self._run(engine, 'update_finding', {'_uuid': UUID, 'fields': {'not_after': 'soon'}})
		errors = [o.message for o in out if o._type == 'error']
		self.assertEqual(len(errors), 1)
		self.assertIn('ISO 8601', errors[0])
		stored = engine.search({'_uuid': UUID}, limit=1, scope_only=True)[0]
		self.assertEqual(Certificate.load(stored).not_after, datetime(2025, 6, 1, tzinfo=timezone.utc))

	def test_json(self):
		self._check('json')
		self._check_garbage('json')

	def test_sqlite(self):
		self._check('sqlite')
		self._check_garbage('sqlite')

	@unittest.skipUnless(HAS_PYMONGO, 'pymongo not installed')
	def test_mongodb(self):
		self._check('mongodb')
		self._check_garbage('mongodb')

	def test_api(self):
		self._check('api')
		self._check_garbage('api')


class TestAddFindingDatetime(unittest.TestCase):

	def _run(self, fields):
		tool = TOOLS_BY_NAME['add_finding']
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': WS})
		return list(tool.run({'action': tool.action, '_type': 'certificate', 'fields': fields}, ctx))

	def test_accepted_formats(self):
		for name, value in ACCEPTED.items():
			if isinstance(value, datetime):
				continue  # a tool call carries JSON only
			with self.subTest(fmt=name):
				out = self._run({'host': 'a.com', 'not_before': value, 'not_after': value})
				self.assertEqual([o.message for o in out if o._type == 'error'], [])
				cert = [o for o in out if o._type == 'certificate'][0]
				self.assertEqual((cert.not_before, cert.not_after), (DT, DT))

	def test_garbage_rejected(self):
		out = self._run({'host': 'a.com', 'not_after': 'whenever'})
		errors = [o.message for o in out if o._type == 'error']
		self.assertEqual(len(errors), 1)
		self.assertIn("'not_after' expected datetime (ISO 8601", errors[0])


if __name__ == '__main__':
	unittest.main()

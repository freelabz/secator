"""`query_workspace(group=True)` for every finding type, and parity across query backends.

Grouping turns a type's findings into one row per group key (port by host, url by host, ...).
Each row must carry EVERY member's `_uuid` (`_group_uuids`, `_group_members`) so a caller can
act on one member without re-querying. Grouping runs on the fetched page, so it must give the
same rows on every backend.
"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secator.ai.actions import ActionContext
from secator.ai.tools.query_workspace import QueryWorkspace
from secator.output_types import (
	Certificate, Domain, Error, ExploitAttempt, Ip, Port, Record, Subdomain, Tag, Technology, Url, UserAccount,
	Vulnerability)
from secator.query.json import match_query
from secator.query.utils import group_findings

_handle_query = QueryWorkspace().run
WS = 'ws1'


def _findings():
	"""Per type: one entity reported twice (two tools), one entity reported once, and the key's
	fallback case (no host / no id / no version / no username)."""
	spec = {
		'ip': [('ip1', Ip(ip='10.0.0.1', host='a.example.com', _source='nmap')),
		       ('ip2', Ip(ip='10.0.0.1', host='alt.example.com', _source='dnsx')),
		       ('ip3', Ip(ip='10.0.0.2'))],
		'port': [('po1', Port(port=22, ip='10.0.0.1', host='a.example.com', _source='nmap')),
		         ('po2', Port(port=22, ip='10.0.0.1', host='a.example.com', state='open', _source='naabu')),
		         ('po3', Port(port=80, ip='10.0.0.1', host='a.example.com')),
		         # no host: keyed by ip:port, so two bare IPs do not merge into ':443'
		         ('po4', Port(port=443, ip='10.0.0.2')), ('po5', Port(port=443, ip='10.0.0.3'))],
		'subdomain': [('sd1', Subdomain(host='x.example.com', domain='example.com', _source='subfinder')),
		              ('sd2', Subdomain(host='x.example.com', domain='example.com', _source='bbot')),
		              ('sd3', Subdomain(host='y.example.com', domain='example.com'))],
		'url': [('ur1', Url(url='http://a.example.com/', host='a.example.com', _source='httpx')),
		        ('ur2', Url(url='http://a.example.com/', host='a.example.com', _source='katana')),
		        ('ur3', Url(url='http://a.example.com/login', host='a.example.com'))],
		'technology': [('te1', Technology(product='nginx', version='1.18', match='a.example.com:80', _source='httpx')),
		               ('te2', Technology(product='nginx', version='1.18', match='b.example.com:80', _source='nmap')),
		               ('te3', Technology(product='nginx', version='1.25', match='a.example.com:443')),
		               ('te4', Technology(product='php', match='a.example.com:80'))],
		'certificate': [('ce1', Certificate(host='a.example.com', fingerprint_sha256='f1', _source='tls')),
		                ('ce2', Certificate(host='a.example.com', fingerprint_sha256='f1', _source='httpx')),
		                ('ce3', Certificate(host='a.example.com', fingerprint_sha256='f2'))],
		'vulnerability': [
			('vu1', Vulnerability(name='Log4Shell', id='CVE-2021-44228', matched_at='http://a.example.com/')),
			('vu2', Vulnerability(name='log4j-rce', id='CVE-2021-44228', matched_at='http://b.example.com/')),
			('vu3', Vulnerability(name='Weak cipher', matched_at='a.example.com:443'))],
		'domain': [('do1', Domain(domain='example.com', _source='whois')),
		           ('do2', Domain(domain='example.com', _source='bbot')),
		           ('do3', Domain(domain='example.org'))],
		'record': [('re1', Record(name='1.2.3.4', type='A', host='a.example.com', _source='dnsx')),
		           ('re2', Record(name='1.2.3.4', type='A', host='a.example.com', _source='bbot')),
		           ('re3', Record(name='1.2.3.5', type='A', host='a.example.com'))],
		'user_account': [
			('ua1', UserAccount(username='alice', site_name='forum', url='http://f/alice', _source='maigret')),
			('ua2', UserAccount(username='alice', site_name='forum', url='http://f/u/alice', _source='sherlock')),
			# same username on another site is another account
			('ua3', UserAccount(username='alice', site_name='wiki', url='http://w/alice')),
			('ua4', UserAccount(username='', email='bob@example.com', site_name='wiki'))],
		'tag': [('ta1', Tag(category='secret', name='aws-key', value='AKIA1', match='http://a.example.com/app.js')),
		        ('ta2', Tag(category='secret', name='aws-key', value='AKIA1', match='http://b.example.com/app.js')),
		        # same category + name, another value: its own row
		        ('ta3', Tag(category='secret', name='aws-key', value='AKIA2', match='http://a.example.com/app.js')),
		        # no category: grouped under the 'general' default
		        ('ta4', Tag(name='email', value='bob@example.com', match='http://a.example.com/'))],
		# no group key: two attempts on the same vulnerability stay two rows
		'exploit_attempt': [
			('ea1', ExploitAttempt(
				name='t', vuln_id='CVE-1', matched_at='http://a.example.com/', verdict='failed', _source='ai')),
			('ea2', ExploitAttempt(
				name='t', vuln_id='CVE-1', matched_at='http://a.example.com/', verdict='success', _source='ai'))],
	}
	items = []
	for i, (uuid, item) in enumerate(u for rows in spec.values() for u in rows):
		item._uuid = uuid
		item._timestamp = 1000 + i
		item._context = {'workspace_id': WS}
		items.append(item)
	return items


# type -> (_group_by, _group_aggregate, {group key: sorted member _uuids})
EXPECTED = {
	'ip': (('ip',), 'host', {'10.0.0.1': ['ip1', 'ip2'], '10.0.0.2': ['ip3']}),
	'port': ((('{host}:{port}', '{ip}:{port}'),), '_source', {
		'a.example.com:22': ['po1', 'po2'], 'a.example.com:80': ['po3'],
		'10.0.0.2:443': ['po4'], '10.0.0.3:443': ['po5']}),
	'subdomain': (('host',), '_source', {'x.example.com': ['sd1', 'sd2'], 'y.example.com': ['sd3']}),
	'url': (('url',), '_source', {'http://a.example.com/': ['ur1', 'ur2'], 'http://a.example.com/login': ['ur3']}),
	# Technology canonicalizes the product to its catalog display name ('php' -> 'PHP').
	'technology': ((('{product}:{version}', 'product'),), 'match', {
		'nginx:1.18': ['te1', 'te2'], 'nginx:1.25': ['te3'], 'PHP': ['te4']}),
	'certificate': (('host', 'fingerprint_sha256'), '_source', {
		'a.example.com | f1': ['ce1', 'ce2'], 'a.example.com | f2': ['ce3']}),
	'vulnerability': ((('id', 'name'),), 'matched_at', {'CVE-2021-44228': ['vu1', 'vu2'], 'Weak cipher': ['vu3']}),
	'domain': (('domain',), '_source', {'example.com': ['do1', 'do2'], 'example.org': ['do3']}),
	'record': (('host', 'type', 'name'), '_source', {
		'a.example.com | A | 1.2.3.4': ['re1', 're2'], 'a.example.com | A | 1.2.3.5': ['re3']}),
	'user_account': (('site_name', ('username', 'email')), '_source', {
		'forum | alice': ['ua1', 'ua2'], 'wiki | alice': ['ua3'], 'wiki | bob@example.com': ['ua4']}),
	'tag': (('category', 'name', 'value'), 'match', {
		'secret | aws-key | AKIA1': ['ta1', 'ta2'], 'secret | aws-key | AKIA2': ['ta3'],
		'general | email | bob@example.com': ['ta4']}),
	'exploit_attempt': ((), None, {'ea1': ['ea1'], 'ea2': ['ea2']}),
}


class _ListEngine:
	"""In-memory engine: applies the query with the json matcher, pages with limit/offset."""

	def __init__(self, docs, name='mongodb'):
		self.docs = docs
		self.backend = type('B', (), {'name': name})()

	def search(self, query, limit=0, offset=0, **kwargs):
		items = [dict(d) for d in self.docs if match_query(d, query)]
		items = items[offset:]
		return items[:limit] if limit else items

	def count(self, query):
		return len([d for d in self.docs if match_query(d, query)])


def _ctx(engine):
	return ActionContext(targets=[], model='m', context={'workspace_id': WS}, _query_engine=engine)


def _rows(out, _type=None):
	return [o for o in out if isinstance(o, dict) and (_type is None or o.get('_type') == _type)]


def _normalize(rows):
	"""Backend-independent view of grouped rows (order of rows and of members may differ)."""
	return sorted(
		(r['_type'], r['_group_key'], r['_group_count'], tuple(sorted(r['_group_uuids'])),
		 tuple(sorted((k, tuple(sorted(v))) for k, v in r['_group_members'].items())), r['_uuid'])
		for r in rows)


class TestGroupEveryType(unittest.TestCase):

	def setUp(self):
		self.docs = [f.toDict() for f in _findings()]
		self.engine = _ListEngine(self.docs)

	def test_each_type_groups_one_row_per_entity_with_every_duplicate_uuid(self):
		by_uuid = {d['_uuid']: d for d in self.docs}
		for _type, (_, agg, groups) in EXPECTED.items():
			with self.subTest(type=_type):
				out = list(_handle_query({'query': {'_type': _type}, 'group': True, 'description': 'd'}, _ctx(self.engine)))
				self.assertEqual([o for o in out if isinstance(o, Error)], [])
				rows = {r['_group_key']: r for r in _rows(out, _type)}
				self.assertEqual({k: sorted(r['_group_uuids']) for k, r in rows.items()}, groups)
				for key, row in rows.items():
					self.assertEqual(row['_group_count'], len(groups[key]))
					member_uuids = sorted(u for us in row['_group_members'].values() for u in us)
					self.assertEqual(member_uuids, groups[key])
					for value, uuids in row['_group_members'].items():
						for u in uuids:  # each member's own value maps to its own _uuid
							self.assertEqual(str(by_uuid[u].get(agg or '_source') or ''), value)
					# the row's _uuid is the newest member
					self.assertEqual(row['_uuid'], max(row['_group_uuids'], key=lambda u: by_uuid[u]['_timestamp']))

	def test_type_without_group_key_is_rejected(self):
		out = list(_handle_query({'query': {'_type': 'ai'}, 'group': True}, _ctx(self.engine)))
		errors = [o for o in out if isinstance(o, Error)]
		self.assertEqual(len(errors), 1)
		self.assertIn('ai', errors[0].message)

	def test_every_finding_type_the_monitor_rechecks_has_a_group_key(self):
		from secator.output_types import FINDING_TYPES
		monitored = {cls.get_name(): cls for cls in FINDING_TYPES if cls.get_name() in EXPECTED}
		self.assertEqual(set(monitored), set(EXPECTED))
		for name, cls in monitored.items():
			with self.subTest(type=name):
				self.assertEqual((tuple(cls._group_by), cls._group_aggregate), EXPECTED[name][:2])


class TestGroupFindingsMembers(unittest.TestCase):

	def test_members_off_by_default(self):
		reps = group_findings([Port(port=1, ip='h', host='h')], ['host'], 'port')
		self.assertFalse(hasattr(reps[0], '_group_uuids'))
		self.assertFalse(hasattr(reps[0], '_group_key'))

	def test_dict_and_object_inputs_carry_the_same_members(self):
		# fresh findings per call: the representative object carries the joined values afterwards
		key = list(Port._group_by)
		ports = [f for f in _findings() if f._type == 'port']
		from_objs = group_findings(ports, key, '_source', with_members=True)
		dicts = [f.toDict() for f in _findings() if f._type == 'port']
		from_dicts = group_findings(dicts, key, '_source', with_members=True)
		self.assertEqual([(r._group_key, r._group_uuids, r._group_members) for r in from_objs],
		                 [(r._group_key, r._group_uuids, r._group_members) for r in from_dicts])

	def test_key_rules_fall_back_in_order(self):
		from secator.query.utils import group_key_part, group_key_label
		rule = ('{host}:{port}', '{ip}:{port}')
		self.assertEqual(group_key_part({'host': 'a', 'ip': '1', 'port': 22}, rule), 'a:22')
		self.assertEqual(group_key_part({'host': '', 'ip': '1', 'port': 22}, rule), '1:22')
		self.assertEqual(group_key_part({'product': 'php', 'version': None}, ('{product}:{version}', 'product')), 'php')
		self.assertEqual(group_key_part({}, ('id', 'name')), '')
		self.assertEqual(group_key_label(Port._group_by), '{host}:{port} or {ip}:{port}')


class _FakeMongoCollection:
	def __init__(self, docs):
		self.docs = docs

	def find(self, query, projection=None):
		docs = [dict(d) for d in self.docs if match_query(d, query)]

		class _Cursor(list):
			def skip(self, n):
				return _Cursor(self[n:])

			def limit(self, n):
				return _Cursor(self[:n] if n else self)
		return _Cursor(docs)

	def count_documents(self, query):
		return len([d for d in self.docs if match_query(d, query)])


class TestGroupBackendParity(unittest.TestCase):
	"""The same findings grouped through each real query backend give the same rows."""

	def setUp(self):
		self.temp_dir = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.temp_dir, True)

	def _api_engine(self, docs):
		from secator.query import QueryEngine
		from secator.query.api import ApiBackend

		def fake_request(method, endpoint, data=None):
			from urllib.parse import parse_qs, urlparse
			params = parse_qs(urlparse(endpoint).query)
			skip, limit = int(params.get('skip', ['0'])[0]), int(params.get('limit', ['0'])[0])
			items = [dict(d) for d in docs if match_query(d, data or {})]
			return {'items': items[skip:skip + limit] if limit else items[skip:], 'total': len(items)}
		patcher = mock.patch.object(ApiBackend, '_make_request', side_effect=fake_request)
		patcher.start()
		self.addCleanup(patcher.stop)
		return QueryEngine(WS, context={'drivers': ['api'], 'workspace_id': WS})

	def _mongodb_engine(self, docs):
		from secator.query import QueryEngine
		from secator.query.mongodb import MongoDBBackend
		client = mock.MagicMock()
		client.main.findings = _FakeMongoCollection(docs)
		patcher = mock.patch.object(MongoDBBackend, '_get_client', return_value=client)
		patcher.start()
		self.addCleanup(patcher.stop)
		return QueryEngine(WS, context={'drivers': ['mongodb'], 'workspace_id': WS})

	def _sqlite_engine(self, findings):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		from secator.query import QueryEngine
		orig = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.temp_dir) / 'test.db')
		sqlite_mod._conns.clear()

		def restore():
			for conn in sqlite_mod._conns.values():
				conn.close()
			sqlite_mod._conns.clear()
			CONFIG.addons.sqlite.path = orig
		self.addCleanup(restore)
		runner = type('R', (), {'config': type('C', (), {'name': 't'})(), 'context': {'workspace_id': WS}})()
		for f in findings:
			sqlite_mod.update_finding(runner, f)
		return QueryEngine(WS, context={'drivers': ['sqlite'], 'workspace_id': WS})

	def _json_engine(self, findings):
		from secator.hooks import json as json_mod
		from secator.query import QueryEngine
		from secator.query.json import JsonBackend
		folder = Path(self.temp_dir) / WS / 'tasks' / 'r1'
		folder.mkdir(parents=True)

		class _R:
			config = type('C', (), {'type': 'task', 'name': 't'})()
			context = {'workspace_id': WS}
			reports_folder = str(folder)
			status = 'RUNNING'
			has_parent = False

			def toDict(self):
				return {'name': 't', 'status': self.status, 'chunk': None, 'context': self.context}
		for f in findings:
			json_mod.update_finding(_R(), f)
		engine = QueryEngine(WS, context={'drivers': [], 'workspace_id': WS})
		engine.backend = JsonBackend(workspace_id=WS, config={'reports_dir': self.temp_dir})
		return engine

	def test_grouped_rows_match_across_backends(self):
		docs = [f.toDict() for f in _findings()]
		engines = {
			'api': self._api_engine(docs),
			'mongodb': self._mongodb_engine(docs),
			'sqlite': self._sqlite_engine(_findings()),
			'json': self._json_engine(_findings()),
		}
		for name, engine in engines.items():
			for _type in EXPECTED:
				with self.subTest(backend=name, type=_type):
					action = {'query': {'_type': _type}, 'group': True}
					out = list(_handle_query(action, _ctx(engine)))
					self.assertEqual([o for o in out if isinstance(o, Error)], [])
					reference = list(_handle_query(action, _ctx(_ListEngine(docs))))
					self.assertEqual(_normalize(_rows(out, _type)), _normalize(_rows(reference, _type)))
					self.assertEqual(len(_rows(out, _type)), len(EXPECTED[_type][2]))


if __name__ == '__main__':
	unittest.main()

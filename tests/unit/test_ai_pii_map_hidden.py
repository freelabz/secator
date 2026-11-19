"""The sensitive-data placeholder map is stored, but never read back by a normal query.

An ai run persists its placeholder -> real value map as an internal ``_type: ai,
ai_type: pii_map`` doc so a resumed run can restore it. Every normal read — the AI's query
tools (which feed results to the model), CLI queries, reports — must exclude it on every
backend; only the restore's explicit ``include_internal=True`` read and writes reach it.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secator.query._base import INTERNAL_AI_TYPES, is_internal_doc

WS = "wshidden"
SECRET = "db.internal.example.org"
PII = {
	"_type": "ai", "ai_type": "pii_map", "content": "", "_uuid": "pii-1",
	"extra_data": {"pii_map": {"[HOST:0123456789ab]": SECRET}, "hash_map": {"0123456789ab": SECRET}},
	"_context": {"workspace_id": WS, "session_id": "s1"}, "is_false_positive": False}
RESPONSE = {
	"_type": "ai", "ai_type": "response", "content": "hello", "_uuid": "ai-1",
	"_context": {"workspace_id": WS, "session_id": "s1"}, "is_false_positive": False}
PORT = {
	"_type": "port", "port": 22, "host": "h", "ip": "1.2.3.4", "_uuid": "port-1",
	"_context": {"workspace_id": WS}, "is_false_positive": False}
DOCS = [PII, RESPONSE, PORT]

# queries a model / CLI user could plausibly send to reach the map
PROBES = [
	{}, {"_type": "ai"}, {"ai_type": "pii_map"}, {"_type": "ai", "ai_type": "pii_map"},
	{"$or": [{"ai_type": "pii_map"}, {"_type": "port"}]}, {"ai_type": {"$in": ["pii_map", "response"]}}]


class _BackendContract:
	"""Shared assertions; subclasses provide self.backend seeded with DOCS."""

	def _uuids(self, results):
		return sorted(r["_uuid"] for r in results)

	def test_search_never_returns_the_map(self):
		for q in PROBES:
			with self.subTest(query=q):
				self.assertNotIn("pii-1", self._uuids(self.backend.search(q)))

	def test_other_docs_still_returned(self):
		self.assertEqual(self._uuids(self.backend.search({})), ["ai-1", "port-1"])
		self.assertEqual(self._uuids(self.backend.search({"_type": "port"})), ["port-1"])
		self.assertEqual(self._uuids(self.backend.search({"ai_type": {"$in": ["pii_map", "response"]}})), ["ai-1"])

	def test_count_and_iterate_exclude_the_map(self):
		self.assertEqual(self.backend.count({"_type": "ai"}), 1)
		rows = [r for batch in self.backend.iterate({}) for r in batch]
		self.assertEqual(self._uuids(rows), ["ai-1", "port-1"])

	def test_restore_read_and_write_still_reach_it(self):
		got = self.backend.search({"_type": "ai", "ai_type": "pii_map"}, include_internal=True)
		self.assertEqual(self._uuids(got), ["pii-1"])
		self.assertTrue(self.backend.update({"_type": "ai", "ai_type": "pii_map"}, {"$set": {"extra_data.x": 1}}))


class TestJsonBackendHidesMap(_BackendContract, unittest.TestCase):
	def setUp(self):
		from secator.query.json import JsonBackend
		self.tmp = tempfile.mkdtemp()
		d = Path(self.tmp) / WS / "tasks" / "0"
		d.mkdir(parents=True)
		(d / "results.ndjson").write_text("\n".join(json.dumps(x) for x in DOCS) + "\n")
		self.backend = JsonBackend(WS, config={"reports_dir": self.tmp})

	def tearDown(self):
		shutil.rmtree(self.tmp)


class TestSqliteBackendHidesMap(_BackendContract, unittest.TestCase):
	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		from secator.query.sqlite import SqliteBackend
		self.sqlite_mod = sqlite_mod
		self.tmp = tempfile.mkdtemp()
		self._orig = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = str(Path(self.tmp) / "t.db")
		sqlite_mod._conns.clear()

		class FakeRunner:
			config = type("C", (), {"name": "ai"})()
			context = {"workspace_id": WS}

		from secator.output_types import Ai, Port
		for d in DOCS:
			d = {k: v for k, v in d.items() if k != "is_false_positive"}
			cls = Ai if d["_type"] == "ai" else Port
			item = cls.load(d)
			item._uuid = d["_uuid"]
			sqlite_mod.update_finding(FakeRunner(), item)
		self.backend = SqliteBackend(workspace_id=WS)

	def tearDown(self):
		from secator.config import CONFIG
		for conn in self.sqlite_mod._conns.values():
			conn.close()
		self.sqlite_mod._conns.clear()
		CONFIG.addons.sqlite.path = self._orig
		shutil.rmtree(self.tmp)


class TestMongoBackendHidesMap(_BackendContract, unittest.TestCase):
	def setUp(self):
		try:
			import mongomock
		except ImportError:
			self.skipTest("mongomock not installed")
		from secator.query.mongodb import MongoDBBackend
		client = mongomock.MongoClient()
		client.main.findings.insert_many([dict(d) for d in DOCS])
		self.backend = MongoDBBackend(WS)
		self.backend._client = client

	def test_restore_read_and_write_still_reach_it(self):
		got = self.backend.search({"_type": "ai", "ai_type": "pii_map"}, include_internal=True)
		self.assertEqual(self._uuids(got), ["pii-1"])


class TestApiBackendSendsExclusion(unittest.TestCase):
	"""The api backend forwards the query: the exclusion must be in what it sends."""

	def _sent(self, **kw):
		from secator.query.api import ApiBackend
		b = ApiBackend(WS)
		with mock.patch.object(b, "_make_request", return_value=[]) as req:
			b.search({"_type": "ai", "ai_type": "pii_map"}, **kw)
		return req.call_args.args[2]

	def test_search_query_excludes_internal_docs(self):
		sent = self._sent()
		self.assertIn({"$or": [{"_type": {"$ne": "ai"}}, {"ai_type": {"$nin": list(INTERNAL_AI_TYPES)}}]}, sent["$and"])
		self.assertEqual(sent["ai_type"], "pii_map")   # the caller's own clause is kept, ANDed

	def test_include_internal_sends_no_exclusion(self):
		self.assertNotIn("$and", self._sent(include_internal=True))


class TestModelFacingPaths(unittest.TestCase):

	def test_union_live_results_drops_the_map_from_disk_and_live(self):
		from secator.ai.utils import _union_live_results
		out = _union_live_results([dict(PII), dict(PORT)], [dict(PII), dict(RESPONSE)], {}, 0)
		self.assertEqual(sorted(r["_uuid"] for r in out), ["ai-1", "port-1"])

	def test_query_workspace_tool_never_yields_the_map(self):
		from secator.ai.actions import ActionContext
		from secator.ai.tools.findings import QueryWorkspace
		from secator.query.json import JsonBackend
		tmp = tempfile.mkdtemp()
		try:
			d = Path(tmp) / WS / "tasks" / "0"
			d.mkdir(parents=True)
			(d / "results.ndjson").write_text("\n".join(json.dumps(x) for x in DOCS) + "\n")
			ctx = ActionContext(targets=[], model="m", context={"workspace_id": WS, "workspace_name": WS})
			ctx.results = [dict(PII)]   # the run's own live (in-memory) map doc
			engine = ctx.get_query_engine()
			self.assertIsInstance(engine.backend, JsonBackend)
			engine.backend.reports_dir = Path(tmp)
			for q in PROBES:
				with self.subTest(query=q):
					out = list(QueryWorkspace().run({"query": q, "limit": 50}, ctx))
					dicts = [o for o in out if isinstance(o, dict)]
					self.assertFalse(any(is_internal_doc(o) for o in dicts))
					self.assertNotIn(SECRET, json.dumps(dicts, default=str))
		finally:
			shutil.rmtree(tmp)

	def test_restore_history_never_feeds_the_map_to_the_model(self):
		from secator.ai.session import restore_history_from_db

		class Engine:
			def search(self, query, **kw):
				return [dict(RESPONSE, message={"role": "assistant", "content": "hello"}), dict(PII)]
		h = restore_history_from_db("s1", Engine())
		self.assertNotIn(SECRET, json.dumps(h.messages))

	def test_session_results_printout_skips_the_map(self):
		from secator.ai.session import print_session_results
		tmp = tempfile.mkdtemp()
		try:
			p = Path(tmp) / "report.json"
			p.write_text(json.dumps({"results": {"ai": [PII, RESPONSE]}}))
			with mock.patch("secator.ai.session.console") as con:
				print_session_results({"report_path": str(p)})
			printed = [c.args[0] for c in con.print.call_args_list]
			self.assertEqual(len(printed), 1)
			self.assertEqual(printed[0].ai_type, "response")
		finally:
			shutil.rmtree(tmp)


class TestApiHookNeverLogsTheMap(unittest.TestCase):

	def test_request_debug_redacts_internal_doc_payload(self):
		from secator.hooks import api as api_hook
		resp = mock.Mock(ok=True)
		# the api may echo the stored doc back: the response log must be redacted too
		resp.json.side_effect = [{"id": "x", "echo": PII}, {"id": "y"}]
		logged = []
		with mock.patch.object(api_hook.requests, "request", return_value=resp):
			with mock.patch.object(api_hook, "debug", lambda *a, **k: logged.append(json.dumps([a, k], default=str))):
				api_hook._make_request("POST", "findings", dict(PII))
				api_hook._make_request("POST", "findings", dict(PORT))
		self.assertFalse(any(SECRET in m for m in logged))
		self.assertTrue(any('1.2.3.4' in m for m in logged))   # normal payloads still logged

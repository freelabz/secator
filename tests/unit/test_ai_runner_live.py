# tests/unit/test_ai_runner_live.py
"""A runner's live status (get_runner) and stopping one (stop_runner)."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext
	from secator.ai.interactivity import AutoBackend
	from secator.ai.tools.runners import GetRunner, StopRunner
	from secator.output_types import Error, Warning
	from secator.query import QueryEngine


def _runner(rtype="task", name="httpx", sync=True, celery_ids=None, **ctx):
	return SimpleNamespace(
		config=SimpleNamespace(type=rtype, name=name), context=dict(ctx), sync=sync, done=False,
		celery_ids_map={i: {} for i in (celery_ids or [])}, stop_process=MagicMock(),
		stop_celery_tasks=MagicMock())


def _engine(backend):
	engine = QueryEngine.__new__(QueryEngine)
	engine.backend = backend
	engine.workspace_id = "ws"
	engine.context = {}
	return engine


def _results(gen):
	out = list(gen)
	return [o for o in out if isinstance(o, dict)], [o for o in out if isinstance(o, (Error, Warning))]


def _doc(status="RUNNING", **ctx):
	return {"name": "httpx", "status": status, "done": status != "RUNNING", "progress": 40,
	        "targets": ["http://a", "http://b", "http://c", "http://d", "http://e", "http://f"],
	        "start_time": time.time() - 30, "end_time": None, "last_updated_db": time.time() - 2,
	        "config": {"type": "task", "name": "httpx", "description": "Probe"}, "context": {"workspace_id": "ws", **ctx}}


def _finding(_type, uuid, **kw):
	return {"_type": _type, "_uuid": uuid, "_context": {"workspace_id": "ws", "task_id": "tid-1",
	        "task_chunk_id": "chunk-1"}, "_timestamp": time.time(), **kw}


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestGetRunnerPerBackend(unittest.TestCase):
	"""get_runner returns the same live view on every query backend."""

	FINDINGS = [_finding("url", "u1", url="http://a"), _finding("url", "u2", url="http://b"),
	            _finding("error", "e1", message="x" * 500)]

	def _check(self, engine, ids=("chunk-1", "tid-1")):
		for rid in ids:
			ctx = ActionContext(targets=[], model="m", context={"workspace_id": "ws"})
			ctx._query_engine = engine
			dicts, errors = _results(GetRunner().run({"runner_id": rid, "tool_call_id": "t"}, ctx))
			self.assertEqual(errors, [], rid)
			view = dicts[0]
			self.assertEqual(view["_type"], "runner_status")
			self.assertEqual((view["status"], view["runner_type"], view["progress"]), ("RUNNING", "task", 40))
			self.assertEqual(view["targets_count"], 6)
			self.assertEqual(len(view["targets"]), 5)
			self.assertGreaterEqual(view["elapsed"], 29)
			self.assertEqual(view["findings"], {"url": 2, "error": 1})
			self.assertTrue(view["errors"][0].endswith("...") and len(view["errors"][0]) < 250)
			self.assertEqual(view["query"], {"_context.task_id": "tid-1"})
			self.assertTrue(view["_context"]["ai_query_result"])

	def test_json(self):
		from secator.query.json import JsonBackend
		root = Path(tempfile.mkdtemp())
		run_dir = root / "ws" / "tasks" / "1"
		run_dir.mkdir(parents=True)
		(run_dir / "report.json").write_text(json.dumps(
			{"info": _doc(task_chunk_id="chunk-1", task_id="tid-1"), "results": {}}))
		(run_dir / "results.ndjson").write_text("\n".join(json.dumps(f) for f in self.FINDINGS) + "\n")
		self._check(_engine(JsonBackend("ws", config={"reports_dir": str(root)}, context={})))

	def _sqlite_engine(self):
		from secator.hooks.sqlite import get_sqlite_conn
		from secator.query.sqlite import SqliteBackend
		db = Path(tempfile.mkdtemp()) / "secator.db"
		conn = get_sqlite_conn(db)
		conn.execute("INSERT INTO tasks (id, workspace_id, data) VALUES (?, ?, ?)",
		             ("chunk-1", "ws", json.dumps(_doc(task_chunk_id="chunk-1", task_id="tid-1"))))
		for f in self.FINDINGS:
			conn.execute("INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) "
			             "VALUES (?, ?, ?, 0, 0, ?)", (f["_uuid"], f["_type"], "ws", json.dumps(f)))
		conn.commit()
		return _engine(SqliteBackend("ws", config={"db_path": str(db)}))

	def test_sqlite(self):
		self._check(self._sqlite_engine())

	def test_sqlite_list_runners_id_resolves(self):
		# sqlite list_runners rows carry no _id, only _id_str ("tasks/chunk-1"), which the
		# list_runners tool shows as `_id`: get_runner and stop_runner must resolve it.
		from secator.ai.runner_history import filter_runners
		engine = self._sqlite_engine()
		listed = filter_runners(engine.list_runners(workspace_id="ws", runner_type="task"))
		self.assertEqual(listed[0]["_id"], "tasks/chunk-1")
		self._check(engine, ids=("tasks/chunk-1",))
		ctx = ActionContext(targets=[], model="m", context={"workspace_id": "ws"})
		ctx._query_engine = engine
		with patch("secator.celery.revoke_task") as revoke:
			dicts, errors = _results(StopRunner().run(
				{"runner_id": "tasks/chunk-1", "reason": "r", "tool_call_id": "t"}, ctx))
		# Found: it reaches the ownership gate (not started by this run, so a non-interactive
		# run denies it) instead of "not found".
		self.assertEqual(dicts, [])
		self.assertEqual(len(errors), 1)
		self.assertIn("did not approve stopping task httpx", errors[0].message)
		revoke.assert_not_called()

	def _mocked(self, cls):
		"""mongodb/api: get_runner keys on the doc id only; the context id resolves via list_runners."""
		doc = {**_doc(task_chunk_id="chunk-1", task_id="tid-1"), "_id": "chunk-1"}
		backend = cls.__new__(cls)

		def search(q, *a, **k):
			return [f for f in self.FINDINGS if f["_context"]["task_id"] == q.get("_context.task_id")]
		with patch.object(cls, "get_runner", side_effect=lambda rid, runner_type: doc if rid == "chunk-1" else None):
			with patch.object(cls, "list_runners", return_value=[doc]), patch.object(cls, "search", side_effect=search):
				self._check(_engine(backend))

	def test_mongodb(self):
		from secator.query.mongodb import MongoDBBackend
		self._mocked(MongoDBBackend)

	def test_api(self):
		from secator.query.api import ApiBackend
		self._mocked(ApiBackend)

	def test_workflow_children_and_unknown(self):
		wf = {"_id": "wf-1", "name": "recon", "status": "RUNNING", "context": {"workflow_id": "wf-1", "workspace_id": "ws"}}
		kids = [{"_id": "k1", "name": "httpx", "status": "SUCCESS", "progress": 100,
		         "context": {"workflow_id": "wf-1", "task_id": "k1"}},
		        {"_id": "k2", "name": "nuclei", "status": "RUNNING", "progress": 10,
		         "context": {"workflow_id": "wf-1", "task_id": "k2"}},
		        {"_id": "k3", "name": "other", "status": "RUNNING", "context": {"workflow_id": "wf-2"}}]
		engine = MagicMock()
		engine.get_runner.side_effect = lambda rid, t: wf if (rid, t) == ("wf-1", "workflow") else None
		engine.list_runners.side_effect = lambda workspace_id=None, runner_type=None, has_parent=None: \
			kids if runner_type == "task" and has_parent else []
		engine.search.return_value = []
		ctx = ActionContext(targets=[], model="m", context={"workspace_id": "ws"})
		ctx._query_engine = engine
		dicts, _ = _results(GetRunner().run({"runner_id": "wf-1"}, ctx))
		self.assertEqual(dicts[0]["children_done"], "1/2")
		self.assertEqual([c["name"] for c in dicts[0]["children"]], ["httpx", "nuclei"])
		self.assertEqual(dicts[0]["query"], {"_context.workflow_id": "wf-1"})
		_, errors = _results(GetRunner().run({"runner_id": "nope"}, ctx))
		self.assertIn("not found", errors[0].message)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStopRunner(unittest.TestCase):

	def setUp(self):
		self.engine = MagicMock()
		self.docs = {}
		self.engine.get_runner.side_effect = lambda rid, t: self.docs.get((rid, t))
		self.engine.list_runners.return_value = []
		self.ctx = ActionContext(targets=["a"], model="m", results=[], session_id="sess-1",
		                         context={"workspace_id": "ws", "task_id": "ai-task", "celery_id": "ai-celery"})
		self.ctx._query_engine = self.engine

	def _stop(self, rid, backend=None):
		self.ctx.backend = backend
		return _results(StopRunner().run({"runner_id": rid, "reason": "useless", "tool_call_id": "t"}, self.ctx))

	def _doc(self, rid, rtype="task", status="RUNNING", **ctx):
		doc = {"_id": rid, "name": "httpx", "status": status, "context": {f"{rtype}_id": rid, "workspace_id": "ws", **ctx}}
		self.docs[(rid, rtype)] = doc
		return doc

	def test_own_in_process_runner_stops_without_asking(self):
		runner = _runner(task_chunk_id="chunk-1", task_id="tid-1")
		runner.process = object()  # a command process is running
		self.ctx.record_runner(runner, "chunk-1", "tid-1")
		self._doc("chunk-1", task_chunk_id="chunk-1")
		self.docs[("chunk-1", "task")]["context"]["task_id"] = "tid-1"
		backend = MagicMock()
		dicts, errors = self._stop("tid-1", backend)
		self.assertEqual(errors, [])
		backend.ask_user.assert_not_called()
		self.assertTrue(dicts[0]["stopped"])
		self.assertIn("killed its running command", dicts[0]["message"])
		runner.stop_process.assert_called()

	def test_own_runner_with_nothing_to_stop_says_so(self):
		runner = _runner(task_chunk_id="chunk-1", task_id="tid-1")  # sync, no process right now
		self.ctx.record_runner(runner, "chunk-1", "tid-1")
		self._doc("chunk-1")
		dicts, _ = self._stop("chunk-1", MagicMock())
		self.assertFalse(dicts[0]["stopped"])
		self.assertIn("Could not stop", dicts[0]["message"])
		self.assertIn("runs synchronously in this turn and cannot be stopped from here yet", dicts[0]["message"])
		self.assertEqual(dicts[0]["refused_reason"],
		                 "it runs synchronously in this turn and cannot be stopped from here yet")
		runner.stop_process.assert_not_called()

	def test_own_async_runner_with_nothing_to_stop_says_so(self):
		runner = _runner(sync=False, task_chunk_id="chunk-1", task_id="tid-1")  # no Celery task yet
		self.ctx.record_runner(runner, "chunk-1", "tid-1")
		self._doc("chunk-1")
		dicts, _ = self._stop("chunk-1", MagicMock())
		self.assertFalse(dicts[0]["stopped"])
		self.assertIn("no command or Celery task to stop right now", dicts[0]["refused_reason"])

	def test_own_dispatched_runner_revokes_its_celery_tasks(self):
		runner = _runner(sync=False, celery_ids=["cel-1", "cel-2"], task_chunk_id="chunk-1", task_id="tid-1")
		self.ctx.record_runner(runner, "chunk-1", "tid-1")
		self._doc("chunk-1")
		self.docs[("chunk-1", "task")]["status"] = "RUNNING"
		dicts, _ = self._stop("chunk-1", MagicMock())
		runner.stop_celery_tasks.assert_called_once()
		self.assertEqual(dicts[0]["revoked_celery_ids"], ["cel-1", "cel-2"])
		self.assertIn("still reads RUNNING", dicts[0]["message"])  # what the store says after the stop

	def _foreign(self, **ctx):
		self._doc("scan-9", "scan", celery_ids=["cel-9", "ai-celery"], **ctx)
		self.docs[("scan-9", "scan")]["name"] = "big-scan"

	@patch("secator.celery.revoke_task")
	def test_foreign_runner_asks_and_deny_keeps_it(self, revoke):
		self._foreign()
		backend = MagicMock()
		backend.ask_user.return_value = {"answer": "deny"}
		dicts, warnings = self._stop("scan-9", backend)
		self.assertEqual(backend.ask_user.call_args.kwargs["permission_type"], "stop_runner")
		self.assertEqual(dicts, [])
		self.assertIn("did not approve", warnings[0].message)
		revoke.assert_not_called()

	@patch("secator.celery.revoke_task")
	def test_foreign_runner_approved_revokes_its_tasks_only(self, revoke):
		self._foreign(celery_id="cel-top")
		backend = MagicMock()
		backend.ask_user.return_value = {"answer": "allow"}
		dicts, _ = self._stop("scan-9", backend)
		# Its dispatched tasks + its own task id (top-level runner); never the ai task's own id.
		self.assertEqual([c.args for c in revoke.call_args_list], [("cel-9", "big-scan"), ("cel-top", "big-scan")])
		self.assertTrue(dicts[0]["stopped"])
		self.assertEqual(dicts[0]["revoked_celery_ids"], ["cel-9", "cel-top"])

	@patch("secator.celery.revoke_task")
	def test_child_runner_inherited_celery_id_is_not_revoked(self, revoke):
		self._foreign(celery_id="parent-celery")
		self.docs[("scan-9", "scan")]["has_parent"] = True
		backend = MagicMock()
		backend.ask_user.return_value = {"answer": "allow"}
		self._stop("scan-9", backend)
		self.assertEqual([c.args[0] for c in revoke.call_args_list], ["cel-9"])

	@patch("secator.celery.revoke_task")
	def test_foreign_runner_non_interactive_is_denied(self, revoke):
		self._foreign()
		_, warnings = self._stop("scan-9", AutoBackend())
		self.assertIn("did not approve", warnings[0].message)
		revoke.assert_not_called()

	@patch("secator.celery.revoke_task")
	def test_subagent_runner_is_owned(self, revoke):
		self.ctx.subagent_sessions.add("sub-1")
		self._foreign(session_id="sub-1")
		backend = MagicMock()
		dicts, _ = self._stop("scan-9", backend)
		backend.ask_user.assert_not_called()
		self.assertTrue(dicts[0]["stopped"])

	@patch("secator.celery.revoke_task")
	def test_runner_of_another_runs_subagent_asks(self, revoke):
		"""Same conversation, but a subagent this ai task did not spawn: not ours."""
		self._foreign(session_id="sub-old", parent_session_id="sess-1")
		backend = MagicMock()
		backend.ask_user.return_value = {"answer": "deny"}
		self._stop("scan-9", backend)
		backend.ask_user.assert_called_once()
		revoke.assert_not_called()

	def test_other_workspace_runner_is_not_found(self):
		self._doc("scan-9", "scan")
		self.docs[("scan-9", "scan")]["context"]["workspace_id"] = "other-ws"
		_, errors = self._stop("scan-9", MagicMock())
		self.assertIn("not found", errors[0].message)
		del self.docs[("scan-9", "scan")]["context"]["workspace_id"]  # no owner: not ours either
		_, errors = self._stop("scan-9", MagicMock())
		self.assertIn("not found", errors[0].message)

	def test_unknown_runner(self):
		_, errors = self._stop("nope", MagicMock())
		self.assertIn("not found", errors[0].message)

	def test_finished_runner_is_a_no_op(self):
		self._doc("tid-5", status="SUCCESS")
		backend = MagicMock()
		dicts, _ = self._stop("tid-5", backend)
		self.assertFalse(dicts[0]["stopped"])
		self.assertIn("already finished", dicts[0]["message"])
		backend.ask_user.assert_not_called()

	def test_cannot_stop_itself_or_its_parent(self):
		_, errors = self._stop("ai-task", MagicMock())
		self.assertIn("this AI run itself", errors[0].message)
		# Reached by another id: its doc names the ai task's id.
		self._doc("doc-7")
		self.docs[("doc-7", "task")]["context"]["task_id"] = "ai-task"
		_, errors = self._stop("doc-7", MagicMock())
		self.assertIn("this AI run itself", errors[0].message)
		# A runner whose own Celery task is the ai task's (top-level doc of the run).
		self._doc("doc-8", celery_id="ai-celery")
		_, errors = self._stop("doc-8", MagicMock())
		self.assertIn("this AI run itself", errors[0].message)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStopRunnerCliPrompt(unittest.TestCase):
	"""The local terminal asks a plain yes/no for stopping a runner this run did not start."""

	def _ask(self, choice):
		from secator.ai.interactivity import CLIBackend
		with patch("secator.rich.InteractiveMenu") as menu:
			menu.return_value.show.return_value = choice
			res = CLIBackend().ask_user("Stop scan big-scan?", ["allow", "deny"], "s", prompt_type="permission",
			                            permission_type="stop_runner", value="scan-9", engine=None)
		self.assertEqual(menu.call_args.args[0], "Stop scan big-scan?")
		return res

	def test_choices(self):
		self.assertEqual(self._ask((0, None)), {"answer": "allow"})
		self.assertEqual(self._ask((1, None)), {"answer": "deny"})
		self.assertEqual(self._ask(None), {"answer": "deny"})


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRunnerRulesPrompt(unittest.TestCase):

	def test_rules_per_mode(self):
		from secator.ai.prompts import get_system_prompt
		scan = get_system_prompt("scan")
		self.assertIn("A RUNNING runner's findings are stored as it finds them", scan)
		self.assertIn("get_runner(runner_id=<id>)", scan)
		self.assertIn('query_workspace(query={"_context.scan_id": "<run_id>"})', scan)
		self.assertIn("These results are PARTIAL until the runner is done", scan)
		self.assertIn('"_timestamp": {"$gt"', scan)
		self.assertIn("stop_runner(runner_id=<id>, reason=...)", scan)
		chat = get_system_prompt("chat")  # read-only: reads partial results, cannot stop runners
		self.assertIn("get_runner(", chat)
		self.assertNotIn("stop_runner", chat)
		monitor = get_system_prompt("monitor")
		self.assertNotIn("get_runner", monitor)
		self.assertNotIn("stop_runner", monitor)

	def test_tools_exposed_per_mode(self):
		from secator.ai.prompts import MODES
		for mode in ("scan", "exploit", "research", "contribute", "chat"):
			self.assertIn("get_runner", MODES[mode]["allowed_actions"], mode)
		for mode in ("scan", "exploit", "research", "contribute"):
			self.assertIn("stop_runner", MODES[mode]["allowed_actions"], mode)
		self.assertNotIn("stop_runner", MODES["chat"]["allowed_actions"])


if __name__ == '__main__':
	unittest.main()

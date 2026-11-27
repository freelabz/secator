# tests/unit/test_ai_background.py
"""Tests for background jobs in the ai task (background tool calls + subagents)."""

import json
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext
	from secator.ai.tools.runners import _resolve_shell_timeout
	from secator.ai.background import (
		BackgroundJobs, BackgroundLimitError, add_background_hooks, register_runner_hook,
		wants_background, CANCELLED, DONE, RUNNING,
	)
	from secator.ai.interactivity import RemoteBackend, UserInputTimeout, CLIBackend
	from secator.ai.tools.runners import CheckBackgroundJobs, CancelBackgroundJob
	from secator.output_types import Ai, Error, Url
	from secator.runners import Task


class _Gate:
	"""A fake dispatch whose 'slow' actions block until released (or cancelled)."""

	def __init__(self):
		self.release = threading.Event()
		self.runners = []

	def dispatch(self, action, ctx):
		ctx_ = {"tool_call_id": action.get("tool_call_id"), "tool_call_name": action.get("tool_call_name")}
		if action.get("name") == "slow" or action.get("action") == "subagent":
			runner = SimpleNamespace(stop_process=MagicMock(side_effect=lambda **kw: self.release.set()),
			                         sync=True, celery_ids_map={})
			self.runners.append(runner)
			register_runner_hook(runner)  # what the child runner's on_init hook does
			yield Ai(content=action.get("name", "ai"), ai_type="task",
			         extra_data={"runner_id": "runner-1"}, _context=ctx_)
			self.release.wait(10)
			if action.get("action") == "subagent":
				yield Url(url="http://example.com/admin", _context=ctx_)
				yield Ai(content="Subagent handback: admin panel found", ai_type="response", _context=ctx_)
				return
			yield Url(url="http://example.com/slow", _context=ctx_)
			return
		yield Ai(content="fast output", ai_type="shell_output", _context=ctx_)


class _FakeHistory:
	def __init__(self):
		self.tool_results = []
		self.users = []

	def get_action_budget(self, model):
		return 10000

	def add_tool_result(self, name, tc_id, content, runner_id="", runner_type=""):
		self.tool_results.append((name, tc_id, content))

	def add_user(self, content):
		self.users.append(content)


def _fake_runner(mgr):
	from secator.tasks.ai import ai as AiTask
	persisted = []
	fake = MagicMock()
	fake.backend = CLIBackend()
	fake.session_id = "sess-bg"
	fake.model = "test-model"
	fake.encryptor = None
	fake.context = {"session_id": "sess-bg"}
	fake.history = _FakeHistory()
	fake.background = mgr
	fake._isolation_ctx = None
	fake.add_result = lambda item, **kw: persisted.append(item)
	fake._submit_background = lambda *a: AiTask._submit_background(fake, *a)
	fake._drain_background_items = lambda: AiTask._drain_background_items(fake)
	fake._drain_background = lambda: AiTask._drain_background(fake)
	return fake, persisted


def _action(tc_id, background=None, **kw):
	a = {"action": "task", "name": "fast", "targets": ["example.com"], "description": "d",
	     "tool_call_id": tc_id, "tool_call_name": "run_task", **kw}
	if background is not None:
		a["background"] = background
	return a


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBackgroundDispatch(unittest.TestCase):

	def setUp(self):
		self.gate = _Gate()
		self.mgr = BackgroundJobs(max_jobs=3)
		self.ctx = ActionContext(targets=["example.com"], model="m", results=[], background=self.mgr)
		self.addCleanup(self.gate.release.set)

	def _dispatch(self, fake, actions):
		from secator.tasks.ai import ai as AiTask
		with patch("secator.tasks.ai.safe_dispatch_action", self.gate.dispatch):
			return list(AiTask._dispatch_and_collect(fake, actions, self.ctx))

	def test_mixed_batch_returns_after_foreground_only(self):
		fake, _ = _fake_runner(self.mgr)
		start = time.time()
		yielded = self._dispatch(fake, [_action("tc-bg", True, name="slow"), _action("tc-fg")])
		self.assertLess(time.time() - start, 5)
		# Both calls got a tool result: the background ack and the foreground output.
		ids = [tc for _, tc, _ in fake.history.tool_results]
		self.assertEqual(sorted(ids), ["tc-bg", "tc-fg"])
		ack = [y for y in yielded if isinstance(y, Ai) and y.ai_type == "background_job"]
		self.assertEqual(len(ack), 1)
		self.assertIn("bg-1", ack[0].content)
		self.assertEqual(self.mgr.get("bg-1").status, RUNNING)

	def test_polling_returns_result_later(self):
		fake, persisted = _fake_runner(self.mgr)
		self._dispatch(fake, [_action("tc-bg", True, name="slow")])
		tool = CheckBackgroundJobs()
		first = list(tool.run({"tool_call_id": "tc-p1", "tool_call_name": "check_background_jobs"}, self.ctx))
		self.assertEqual(first[0]["status"], RUNNING)
		self.assertFalse(any(d.get("_type") == "url" for d in first))
		self.gate.release.set()
		self.mgr.get("bg-1").thread.join(5)
		later = list(tool.run({"job_ids": ["bg-1"], "tool_call_id": "tc-p2",
		                       "tool_call_name": "check_background_jobs"}, self.ctx))
		self.assertEqual(later[0]["status"], DONE)
		urls = [d for d in later if d.get("_type") == "url"]
		self.assertEqual(len(urls), 1)
		# Re-surfaced under THIS poll's call, and flagged so the loop doesn't re-persist it.
		self.assertEqual(urls[0]["_context"]["tool_call_id"], "tc-p2")
		self.assertTrue(urls[0]["_context"]["ai_query_result"])
		# A second poll returns only the status (results already read).
		again = list(tool.run({"job_ids": ["bg-1"], "tool_call_id": "tc-p3"}, self.ctx))
		self.assertEqual([d["_type"] for d in again], ["background_job"])
		# The ai task drains + persists the job's items and records its final status once.
		from secator.tasks.ai import ai as AiTask
		AiTask._drain_background_items(fake)
		AiTask._drain_background_items(fake)
		self.assertTrue(any(isinstance(p, Url) for p in persisted))
		records = [p for p in persisted if isinstance(p, Ai) and p.ai_type == "background_job"
		           and p.extra_data.get("status") == DONE]
		self.assertEqual(len(records), 1)
		self.assertEqual(records[0].extra_data["runner_ids"], ["runner-1"])

	def test_cancel(self):
		fake, _ = _fake_runner(self.mgr)
		self._dispatch(fake, [_action("tc-bg", True, name="slow")])
		# Wait for the runner to register on the job.
		for _ in range(100):
			if self.mgr.get("bg-1").runners:
				break
			time.sleep(0.01)
		out = list(CancelBackgroundJob().run({"job_id": "bg-1", "tool_call_id": "tc-c"}, self.ctx))
		self.assertEqual(out[0]["status"], CANCELLED)
		self.assertTrue(self.gate.runners[0].revoked)  # its runner doc ends REVOKED, not SUCCESS
		runner = self.gate.runners[0]
		runner.stop_process.assert_called()
		self.assertTrue(runner.stop_requested)  # cooperative stop (subagent loops)
		self.mgr.get("bg-1").thread.join(5)
		self.assertEqual(self.mgr.get("bg-1").status, CANCELLED)  # not overwritten by thread end
		err = list(CancelBackgroundJob().run({"job_id": "bg-9", "tool_call_id": "tc-c"}, self.ctx))
		self.assertIsInstance(err[0], Error)

	def test_max_concurrency_limit(self):
		self.mgr.max_jobs = 1
		fake, _ = _fake_runner(self.mgr)
		self._dispatch(fake, [_action("tc-1", True, name="slow"), _action("tc-2", True, name="slow")])
		self.assertEqual(len(self.mgr.running()), 1)
		results = dict((tc, content) for _, tc, content in fake.history.tool_results)
		self.assertIn("Too many background jobs", results["tc-2"])
		with self.assertRaises(BackgroundLimitError):
			self.mgr.submit(_action("tc-3", True, name="slow"), self.ctx, self.gate.dispatch)
		self.gate.release.set()
		self.mgr.get("bg-1").thread.join(5)
		self.mgr.submit(_action("tc-4", True), self.ctx, self.gate.dispatch)  # slot free again

	def test_cleanup_on_ai_task_end(self):
		from secator.tasks.ai import ai as AiTask
		fake, persisted = _fake_runner(self.mgr)
		self._dispatch(fake, [_action("tc-bg", True, name="slow")])
		AiTask._teardown_background(fake)
		job = self.mgr.get("bg-1")
		self.assertEqual(job.status, CANCELLED)
		self.assertFalse(job.thread.is_alive())
		records = [p for p in persisted if isinstance(p, Ai) and p.ai_type == "background_job"
		           and p.extra_data.get("status") == CANCELLED]
		self.assertEqual(len(records), 1)
		self.assertEqual(records[0].extra_data["runner_ids"], ["runner-1"])

	def test_background_subagent_does_not_block_and_hands_back_later(self):
		fake, _ = _fake_runner(self.mgr)
		sub = {"action": "subagent", "objective": "find admin panels", "targets": ["example.com"],
		       "description": "Hunt admin panels", "tool_call_id": "tc-sub", "tool_call_name": "run_subagent"}
		start = time.time()
		self._dispatch(fake, [sub, _action("tc-fg")])  # no `background` flag: subagents default to background
		self.assertLess(time.time() - start, 5)
		self.assertEqual(self.mgr.get("bg-1").status, RUNNING)
		self.gate.release.set()
		self.mgr.get("bg-1").thread.join(5)
		polled = list(CheckBackgroundJobs().run({"tool_call_id": "tc-p"}, self.ctx))
		self.assertEqual(polled[0]["status"], DONE)
		handback = [d for d in polled if d.get("_type") == "ai" and d.get("ai_type") == "response"]
		self.assertEqual(len(handback), 1)
		self.assertIn("handback", handback[0]["content"])
		self.assertTrue(any(d.get("_type") == "url" for d in polled))  # its findings too

	def test_status_block(self):
		self.assertEqual(self.mgr.status_block(), "")
		self.mgr.submit(_action("tc-bg", True, name="slow"), self.ctx, self.gate.dispatch)
		block = self.mgr.status_block()
		self.assertIn("bg-1 [running", block)
		self.assertIn("check_background_jobs", block)
		self.assertNotIn("FINISHED", block)
		self.gate.release.set()
		self.mgr.get("bg-1").thread.join(5)
		block = self.mgr.status_block()
		self.assertIn("FINISHED since you last read them: bg-1", block)
		self.assertIn("your analysis", block)
		self.mgr.poll(["bg-1"])  # read: no longer listed
		self.assertEqual(self.mgr.status_block(), "")

	def test_check_never_waits(self):
		props = CheckBackgroundJobs.schema["function"]["parameters"]["properties"]
		self.assertNotIn("wait", props)
		self.mgr.submit(_action("tc-bg", True, name="slow"), self.ctx, self.gate.dispatch)
		start = time.time()
		polled = list(CheckBackgroundJobs().run({"wait": 60, "tool_call_id": "tc-p"}, self.ctx))
		self.assertLess(time.time() - start, 2)
		self.assertEqual(polled[0]["status"], RUNNING)

	def test_lost_detached_job_ends_after_task_max_timeout(self):
		from secator.config import CONFIG
		store = MagicMock()
		store.get_runner_status.return_value = {"status": "RUNNING", "done": False, "progress": 0}
		mgr = BackgroundJobs(max_jobs=1, store=store)
		mgr.REFRESH_EVERY = 0
		job = mgr.submit(_action("tc", True, name="nuclei"), self.ctx, lambda a, c: iter(()))
		job.thread.join(5)
		job.status, job.detached = RUNNING, True
		job.runners.append(SimpleNamespace(config=SimpleNamespace(type="task"), context={"task_chunk_id": "r"}))
		# (plain setattr: patch.object would delattr the pydantic field on exit)
		self.addCleanup(setattr, CONFIG.celery, "task_max_timeout", CONFIG.celery.task_max_timeout)
		CONFIG.celery.task_max_timeout = -1
		mgr.refresh(force=True)
		self.assertIsNotNone(job.running_since)  # the store saw it RUNNING: the clock starts
		job.running_since -= 10 * 24 * 3600
		mgr.refresh(force=True)
		self.assertEqual(job.status, RUNNING)  # no task max timeout: never declared lost
		CONFIG.celery.task_max_timeout = 60
		job.running_since = time.time() - 30
		mgr.refresh(force=True)
		self.assertEqual(job.status, RUNNING)
		# Queue time does not count: submitted long ago, but running for 30s only.
		job.started = time.time() - 10 * 24 * 3600
		mgr.refresh(force=True)
		self.assertEqual(job.status, RUNNING)
		job.running_since = time.time() - 60 - mgr.DETACHED_GRACE - 1
		mgr.refresh(force=True)
		self.assertEqual(job.status, "failed")
		self.assertIn("lost", job.error)

	def test_limits_default_from_config(self):
		from secator.config import CONFIG
		from secator.tasks.ai import ai as AiTask
		self.assertEqual(CONFIG.addons.ai.background_max_jobs, 3)
		self.assertEqual(AiTask.opts["background_max_jobs"]["default"], CONFIG.addons.ai.background_max_jobs)
		# Background jobs have no timeout: no max-wait option or config.
		self.assertNotIn("background_max_wait", AiTask.opts)
		from secator.config import AiAddon
		self.assertNotIn("background_max_wait", AiAddon.model_fields)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBackgroundHelpers(unittest.TestCase):

	def test_wants_background(self):
		self.assertTrue(wants_background({"action": "task", "background": True}))
		self.assertFalse(wants_background({"action": "task"}))
		self.assertTrue(wants_background({"action": "shell", "background": "true"}))
		self.assertTrue(wants_background({"action": "subagent"}))
		self.assertFalse(wants_background({"action": "subagent", "background": False}))
		self.assertFalse(wants_background({"action": "query", "background": True}))

	def test_add_background_hooks_copies(self):
		driver_hook = MagicMock()
		hooks = {Task: {"on_init": [driver_hook]}}
		out = add_background_hooks(hooks)
		self.assertEqual(hooks[Task]["on_init"], [driver_hook])  # input untouched
		self.assertEqual(out[Task]["on_init"], [driver_hook, register_runner_hook])
		register_runner_hook(MagicMock())  # outside a job thread: no-op

	def test_background_shell_has_no_short_default_timeout(self):
		from secator.config import CONFIG
		original = CONFIG.celery.task_max_timeout
		self.addCleanup(setattr, CONFIG.celery, "task_max_timeout", original)
		self.addCleanup(setattr, CONFIG.security, "shell_default_timeout", CONFIG.security.shell_default_timeout)
		CONFIG.security.shell_default_timeout = 30  # independent of the operator's config
		CONFIG.celery.task_max_timeout = -1
		self.assertEqual(_resolve_shell_timeout({"command": "x"}), 30)
		self.assertEqual(_resolve_shell_timeout({"command": "x", "background": True}), -1)
		CONFIG.celery.task_max_timeout = 7200
		self.assertEqual(_resolve_shell_timeout({"command": "x", "background": True}), 7200)
		self.assertEqual(_resolve_shell_timeout({"command": "x", "background": True, "timeout": 60}), 60)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBackgroundGuardrails(unittest.TestCase):

	def test_background_call_goes_through_guardrails(self):
		"""A background call is checked (and denied) exactly like a foreground one."""
		from secator.tasks.ai import ai as AiTask
		seen = []

		def _deny(action, ctx):
			seen.append(dict(action))
			return "Action denied: target example.com not approved"
			yield  # pragma: no cover

		fake = MagicMock()
		fake.dangerous = False
		fake.encryptor = None
		fake.is_subagent = False
		tc = SimpleNamespace(id="tc-1", function=SimpleNamespace(
			name="run_task", arguments=json.dumps({
				"name": "nuclei", "targets": ["example.com"], "description": "Scan", "background": True})))
		with patch("secator.tasks.ai.check_guardrails", _deny), patch("secator.rich.display_denial"):
			gen = AiTask._process_tool_calls(fake, [tc], MagicMock())
			try:
				while True:
					next(gen)
			except StopIteration as stop:
				actions = stop.value
		self.assertEqual(actions, [])
		self.assertTrue(seen and seen[0]["background"] is True)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestIdleTimerHold(unittest.TestCase):
	"""Remote backend: the idle input timer is frozen while background jobs run (capped)."""

	def _backend(self, hold, answers):
		backend = RemoteBackend(timeout=2, query_engine=MagicMock(), poll_interval=1)
		backend.hold_while = hold
		backend._resolve_answer = MagicMock(side_effect=answers)
		backend.poll_steers = MagicMock(return_value=[])
		return backend

	def test_timer_runs_without_jobs(self):
		backend = self._backend(lambda: False, [None] * 10)
		with patch("secator.ai.interactivity.sleep"):
			with self.assertRaises(UserInputTimeout):
				backend._poll_for_answer("s", "stopped")
		self.assertEqual(backend._resolve_answer.call_count, 3)  # 2 ticks + final check

	def test_timer_frozen_while_jobs_run(self):
		ticks = iter([True] * 5 + [False] * 10)
		backend = self._backend(lambda: next(ticks), [None] * 20)
		with patch("secator.ai.interactivity.sleep"):
			with self.assertRaises(UserInputTimeout):
				backend._poll_for_answer("s", "stopped")
		self.assertEqual(backend._resolve_answer.call_count, 8)  # 5 frozen + 2 ticks + final

	def test_user_answer_still_honoured_during_hold(self):
		backend = self._backend(lambda: True, [None, None, "stop"])
		with patch("secator.ai.interactivity.sleep"):
			self.assertEqual(backend._poll_for_answer("s", "stopped"), "stop")

	def test_timer_restarts_from_last_job_end(self):
		# 1 idle tick, then a job runs (timer held at zero), then the job ends: the timeout
		# counts again from the job's end (2 more ticks), not from the turn end (1 more tick).
		ticks = iter([False] + [True] * 5 + [False] * 10)
		backend = self._backend(lambda: next(ticks), [None] * 20)
		with patch("secator.ai.interactivity.sleep"):
			with self.assertRaises(UserInputTimeout):
				backend._poll_for_answer("s", "stopped")
		self.assertEqual(backend._resolve_answer.call_count, 9)  # 1 tick + 5 held + 2 ticks + final

	def test_hold_has_no_bound(self):
		mgr = BackgroundJobs(max_jobs=1)
		self.assertFalse(mgr.should_hold_idle())  # no job running
		gate = _Gate()
		self.addCleanup(gate.release.set)
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=mgr)
		job = mgr.submit(_action("tc", True, name="slow"), ctx, gate.dispatch)
		job.started -= 10 * 24 * 3600  # running for 10 days: still held, never cancelled
		self.assertTrue(mgr.should_hold_idle())
		backend = RemoteBackend(timeout=1, query_engine=MagicMock(), poll_interval=1)
		backend.hold_while = mgr.should_hold_idle
		self.assertEqual(backend.idle_tick(10_000, 1), 0)
		self.assertEqual(job.status, RUNNING)
		gate.release.set()
		job.thread.join(5)
		self.assertFalse(mgr.should_hold_idle())
		self.assertEqual(backend.idle_tick(0, 1), 1)

	def test_stop_grace_wait_held_while_job_runs(self):
		# Interactive run whose model called a choiceless `stop`: the follow-up grace wait is an
		# idle timer too, held while a job runs; a follow-up message then resumes the run.
		from secator.tasks.ai import ai as AiTask
		polls = iter([[]] * 6 + [["So ?"]])
		backend = self._backend(lambda: True, [])
		backend.poll_steers = MagicMock(side_effect=lambda sid: next(polls))
		fake = MagicMock()
		fake.backend = backend
		fake.session_id = "s"
		fake.encryptor = None
		fake.history = _FakeHistory()
		with patch("secator.tasks.ai.time.sleep"):
			self.assertTrue(AiTask._grace_wait_for_followup(fake))
		self.assertEqual(fake.history.users, ["So ?"])


class _FakeStore:
	"""Stands in for the run's QueryEngine: runner status + findings by runner id."""

	def __init__(self):
		self.status = "RUNNING"
		self.findings = []
		self.status_calls = []
		self.search_calls = []

	def get_runner_status(self, runner_id, runner_type):
		self.status_calls.append((runner_id, runner_type))
		if runner_id != "rid-1":
			return None
		return {"id": runner_id, "status": self.status, "done": self.status != "RUNNING", "progress": 40}

	def search(self, query, limit=0, offset=0):
		self.search_calls.append(query)
		if getattr(self, "fail", False):
			raise RuntimeError("store down")
		found = list(self.findings)[offset:]
		return found[:limit] if limit else found


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStoreBackedJobs(unittest.TestCase):
	"""A job dispatched to Celery is fire-and-forget: tracked by runner id in the store."""

	def setUp(self):
		from secator.ai.background import current_job
		self.store = _FakeStore()
		self.mgr = BackgroundJobs(max_jobs=3, store=self.store)
		self.mgr.REFRESH_EVERY = 0
		self.ctx = ActionContext(targets=["example.com"], model="m", results=[], background=self.mgr)
		self.celery_runner = SimpleNamespace(
			sync=False, celery_ids_map={"celery-1": {}}, stop_celery_tasks=MagicMock(),
			config=SimpleNamespace(type="task"), context={"task_chunk_id": "rid-1", "task_id": "tid-1"})

		def detached_dispatch(action, ctx):
			job = current_job()
			register_runner_hook(self.celery_runner)  # child runner's on_init
			job.detached = job.can_detach  # what _run_runner does for a Celery dispatch
			yield Ai(content="nuclei", ai_type="task", extra_data={"runner_id": "rid-1"},
			         _context={"tool_call_id": action["tool_call_id"]})
			# returns right away: no thread waits on the Celery result
		self.dispatch = detached_dispatch

	def test_detached_job_polled_from_store(self):
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.assertTrue(job.detached)
		self.assertEqual(job.status, RUNNING)  # thread gone, runner still running elsewhere
		self.assertIn(job, self.mgr.running())
		self.assertEqual(job.store_status["status"], "RUNNING")
		self.assertIn("[running 40%]", job.summary())
		self.store.findings = [{"_type": "vulnerability", "_uuid": "u1", "name": "CVE-2021-41773"}]
		self.store.status = "SUCCESS"
		(polled_job, items), = self.mgr.poll(["bg-1"])
		self.assertEqual(polled_job.status, DONE)
		self.assertEqual([i.get("_uuid") for i in items if isinstance(i, dict)], ["u1"])
		self.assertEqual(self.store.search_calls[-1], {"_context.task_chunk_id": "rid-1"})
		(_, again), = self.mgr.poll(["bg-1"])
		self.assertEqual(again, [])  # store results are not reported twice

	def test_in_process_job_results_reported_once(self):
		"""An in-process job's results come from its own buffer only: the store copies of the same
		findings (persisted by the drain, with a _uuid) are not reported again."""
		def inproc(action, ctx):
			register_runner_hook(self.celery_runner)
			yield Url(url="http://example.com/a", _context={"tool_call_id": action["tool_call_id"]})
		job = self.mgr.submit(_action("tc", True, name="httpx"), self.ctx, inproc)
		job.thread.join(5)
		self.assertFalse(job.detached)
		self.store.findings = [{"_type": "url", "_uuid": "u-a", "url": "http://example.com/a"},
		                       {"_type": "stat", "_uuid": "u-s"}]
		(_, first), = self.mgr.poll(["bg-1"])
		self.assertEqual([getattr(i, "url", None) for i in first], ["http://example.com/a"])
		(_, again), = self.mgr.poll(["bg-1"])
		self.assertEqual(again, [])  # finished and read: only its status from now on

	def test_detached_job_store_results_skip_execution_items(self):
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.store.findings = [{"_type": "url", "_uuid": "u1"}, {"_type": "stat", "_uuid": "u2"},
		                       {"_type": "progress", "_uuid": "u3"}]
		(_, items), = self.mgr.poll(["bg-1"])
		self.assertEqual([i.get("_uuid") for i in items if isinstance(i, dict)], ["u1"])

	def test_detached_job_store_results_are_paged(self):
		"""More findings than one store page: every one is reported once, across polls."""
		self.mgr.STORE_PAGE = 2
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.store.findings = [{"_type": "url", "_uuid": f"u{i}"} for i in range(5)]
		(_, items), = self.mgr.poll(["bg-1"])
		self.assertEqual([i["_uuid"] for i in items if isinstance(i, dict)], [f"u{i}" for i in range(5)])
		self.store.findings.append({"_type": "url", "_uuid": "u5"})
		(_, more), = self.mgr.poll(["bg-1"])
		self.assertEqual([i["_uuid"] for i in more if isinstance(i, dict)], ["u5"])

	def test_detached_store_reorder_does_not_skip_a_finding(self):
		"""A store may move an updated finding after newer ones: no unread finding is skipped."""
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.store.findings = [{"_type": "url", "_uuid": "A"}, {"_type": "url", "_uuid": "B"}]
		self.mgr.poll(["bg-1"])
		self.store.findings = [{"_type": "url", "_uuid": "B"}, {"_type": "url", "_uuid": "C"},
		                       {"_type": "url", "_uuid": "A"}]  # C appended, then A updated (moved last)
		(_, items), = self.mgr.poll(["bg-1"])
		self.assertEqual([i["_uuid"] for i in items if isinstance(i, dict)], ["C"])

	def test_failed_store_read_keeps_finished_job_unread(self):
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.store.status = "SUCCESS"
		self.store.fail = True
		(polled, _), = self.mgr.poll(["bg-1"])
		self.assertEqual(polled.status, DONE)
		self.assertFalse(job.final_read)
		self.assertIn(job, self.mgr.unread())  # still in the status block
		self.store.fail = False
		self.store.findings = [{"_type": "url", "_uuid": "u1"}]
		(_, items), = self.mgr.poll(["bg-1"])
		self.assertEqual([i["_uuid"] for i in items if isinstance(i, dict)], ["u1"])
		self.assertTrue(job.final_read)

	@patch('secator.ai.tools._runner._child_preamble')
	@patch('secator.ai.tools._runner.TemplateLoader')
	@patch('secator.ai.tools._runner.Task')
	def test_refused_call_is_not_detached(self, mock_task_cls, _tpl, preamble):
		"""A call refused by the persistence preamble starts no child: its job must not be detached
		(it would stay running, waiting on a runner that never existed)."""
		from secator.ai.background import BackgroundJob, _THREAD_JOBS
		from secator.ai.tools._runner import _run_runner
		from secator.output_types import Warning as WarningOut
		preamble.return_value = (None, WarningOut(message="persistence refused"))
		mock_task_cls.get_task_class.return_value.would_chunk.return_value = False
		job = BackgroundJob(id="bg-1", action={}, can_detach=True)
		mgr = BackgroundJobs(max_jobs=3)
		mgr.jobs[job.id] = job
		ctx = ActionContext(targets=["example.com"], model="m", sync=False, background=mgr)
		_THREAD_JOBS[threading.get_ident()] = job
		try:
			out = list(_run_runner({"action": "task", "name": "nuclei", "targets": ["example.com"]}, ctx, "task"))
		finally:
			_THREAD_JOBS.pop(threading.get_ident(), None)
		self.assertIsInstance(out[-1], WarningOut)
		self.assertFalse(job.detached)
		mock_task_cls.assert_not_called()

	def test_background_shell_cancelled_before_start_does_not_run(self):
		from secator.ai.background import BackgroundJob, _THREAD_JOBS
		from secator.ai.tools.runners import RunShell
		job = BackgroundJob(id="bg-1", action={})
		job.cancel_event.set()
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=self.mgr)
		_THREAD_JOBS[threading.get_ident()] = job
		try:
			with patch('secator.tasks.command.command') as mock_cmd:
				out = list(RunShell().run({"action": "shell", "command": "echo hi", "tool_call_id": "t"}, ctx))
		finally:
			_THREAD_JOBS.pop(threading.get_ident(), None)
		mock_cmd.return_value.run.assert_not_called()
		self.assertIn("cancelled before it started", [getattr(i, "content", "") for i in out][-1])

	def test_detached_job_failed_runner(self):
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.store.status = "FAILURE"
		self.mgr.refresh(force=True)
		self.assertEqual(job.status, "failed")

	def test_cancel_detached_job_revokes(self):
		job = self.mgr.submit(_action("tc", True, name="nuclei"), self.ctx, self.dispatch)
		job.thread.join(5)
		self.mgr.cancel("bg-1")
		self.celery_runner.stop_celery_tasks.assert_called_once()
		self.assertEqual(job.status, CANCELLED)

	def test_no_store_never_detaches(self):
		mgr = BackgroundJobs(max_jobs=3)
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=mgr)
		job = mgr.submit(_action("tc", True, name="nuclei"), ctx, self.dispatch)
		job.thread.join(5)
		self.assertFalse(job.detached)
		self.assertEqual(job.status, DONE)

	@patch('secator.ai.tools._runner.TemplateLoader')
	@patch('secator.ai.tools._runner.Task')
	def test_run_runner_dispatches_fire_and_forget_in_a_job(self, mock_task_cls, _tpl):
		"""Inside a store-backed job, a Celery-dispatched child gets no_poll (no blocking poll)."""
		from secator.ai.background import BackgroundJob, _THREAD_JOBS
		from secator.ai.tools._runner import _run_runner
		mock_runner = MagicMock()
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner
		mock_task_cls.get_task_class.return_value.would_chunk.return_value = False
		job = BackgroundJob(id="bg-1", action={}, can_detach=True)
		mgr = BackgroundJobs(max_jobs=3)
		mgr.jobs[job.id] = job
		ctx = ActionContext(targets=["example.com"], model="m", sync=False, background=mgr)
		_THREAD_JOBS[threading.get_ident()] = job
		try:
			list(_run_runner({"action": "task", "name": "nuclei", "targets": ["example.com"]}, ctx, "task"))
		finally:
			_THREAD_JOBS.pop(threading.get_ident(), None)
		run_opts = mock_task_cls.call_args.kwargs["run_opts"]
		self.assertTrue(run_opts.get("no_poll"))
		self.assertTrue(job.detached)
		# A subagent running in this job's thread (its own registry) keeps its calls foreground.
		job.detached = False
		sub_ctx = ActionContext(targets=["example.com"], model="m", sync=False,
		                        background=BackgroundJobs(max_jobs=3))
		_THREAD_JOBS[threading.get_ident()] = job
		try:
			list(_run_runner({"action": "task", "name": "nuclei", "targets": ["example.com"]}, sub_ctx, "task"))
		finally:
			_THREAD_JOBS.pop(threading.get_ident(), None)
		self.assertFalse(mock_task_cls.call_args.kwargs["run_opts"].get("no_poll"))
		self.assertFalse(job.detached)
		# Outside a job (foreground): unchanged.
		list(_run_runner({"action": "task", "name": "nuclei", "targets": ["example.com"]}, ctx, "task"))
		self.assertFalse(mock_task_cls.call_args.kwargs["run_opts"].get("no_poll"))

	@patch('secator.ai.tools._runner.TemplateLoader')
	@patch('secator.ai.tools._runner.Task')
	def test_run_runner_keeps_polling_a_task_that_may_chunk(self, mock_task_cls, _tpl):
		"""A dispatched task that may chunk keeps its polling thread: its chunk ids are learned
		by polling, so a cancel can revoke them."""
		from secator.ai.background import BackgroundJob, _THREAD_JOBS
		from secator.ai.tools._runner import _run_runner
		mock_runner = MagicMock()
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner
		mock_task_cls.get_task_class.return_value.would_chunk.return_value = True
		job = BackgroundJob(id="bg-1", action={}, can_detach=True)
		mgr = BackgroundJobs(max_jobs=3)
		mgr.jobs[job.id] = job
		ctx = ActionContext(targets=["a.com", "b.com"], model="m", sync=False, background=mgr)
		_THREAD_JOBS[threading.get_ident()] = job
		try:
			list(_run_runner({"action": "task", "name": "nuclei", "targets": ["a.com", "b.com"]}, ctx, "task"))
		finally:
			_THREAD_JOBS.pop(threading.get_ident(), None)
		self.assertFalse(mock_task_cls.call_args.kwargs["run_opts"].get("no_poll"))
		self.assertFalse(job.detached)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestGetRunnerStatusPerDriver(unittest.TestCase):
	"""get_runner_status(runner_id) reads the live runner doc on every query backend."""

	def test_sqlite(self):
		import tempfile
		from pathlib import Path
		from secator.hooks.sqlite import get_sqlite_conn
		from secator.query.sqlite import SqliteBackend
		db = Path(tempfile.mkdtemp()) / "secator.db"
		conn = get_sqlite_conn(db)
		doc = {"status": "RUNNING", "done": False, "progress": 10,
		       "context": {"task_chunk_id": "rid-1", "task_id": "tid-1"}}
		conn.execute("INSERT INTO tasks (id, workspace_id, data) VALUES (?, ?, ?)", ("tid-1", "ws", json.dumps(doc)))
		conn.commit()
		backend = SqliteBackend("ws", config={"db_path": str(db)})
		for rid in ("tid-1", "rid-1"):  # by row key or by the chunk id in its context
			st = backend.get_runner_status(rid, "task")
			self.assertEqual((st["status"], st["done"], st["progress"]), ("RUNNING", False, 10))
		self.assertIsNone(backend.get_runner_status("nope", "task"))

	def test_json(self):
		import tempfile
		from pathlib import Path
		from secator.query.json import JsonBackend
		root = Path(tempfile.mkdtemp())
		run_dir = root / "ws" / "tasks" / "1"
		run_dir.mkdir(parents=True)
		info = {"status": "SUCCESS", "done": True, "progress": 100, "config": {"type": "task"},
		        "context": {"task_chunk_id": "rid-1"}}
		(run_dir / "report_task_nuclei_1.json").write_text(json.dumps({"info": info, "results": {}}))
		backend = JsonBackend("ws", config={"reports_dir": str(root)}, context={})
		st = backend.get_runner_status("rid-1", "task")
		self.assertEqual((st["status"], st["done"]), ("SUCCESS", True))
		self.assertIsNone(backend.get_runner_status("rid-1", "workflow"))

	def test_json_prefers_the_final_report_of_a_runner(self):
		"""A dispatcher's stale child report and the worker's live report carry the same ids."""
		import os
		import tempfile
		from pathlib import Path
		from secator.query.json import JsonBackend
		root = Path(tempfile.mkdtemp())
		run_dir = root / "ws" / "tasks" / "1"
		run_dir.mkdir(parents=True)
		ctx = {"task_chunk_id": "rid-1"}
		stale = {"status": "RUNNING", "done": False, "config": {"type": "task"}, "context": ctx}
		final = {"status": "SUCCESS", "done": True, "config": {"type": "task"}, "context": ctx}
		(run_dir / "report.json").write_text(json.dumps({"info": final, "results": {}}))
		(run_dir / "report_nuclei.json").write_text(json.dumps({"info": stale, "results": {}}))
		os.utime(run_dir / "report.json", (1, 1))  # the final report is the OLDER file
		backend = JsonBackend("ws", config={"reports_dir": str(root)}, context={})
		st = backend.get_runner_status("rid-1", "task")
		self.assertEqual((st["status"], st["done"]), ("SUCCESS", True))

	def test_mongodb_and_api_use_get_runner(self):
		from secator.query.mongodb import MongoDBBackend
		from secator.query.api import ApiBackend
		for cls in (MongoDBBackend, ApiBackend):
			backend = cls.__new__(cls)
			with patch.object(cls, "get_runner", return_value={"status": "revoked", "done": True}):
				st = backend.get_runner_status("rid-1", "task")
			self.assertEqual(st["status"], "REVOKED")


if __name__ == '__main__':
	unittest.main()

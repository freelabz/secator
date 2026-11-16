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
	from secator.ai.tools.run_shell import _resolve_shell_timeout
	from secator.ai.background import (
		BackgroundJobs, BackgroundLimitError, add_background_hooks, register_runner_hook,
		wants_background, CANCELLED, DONE, RUNNING,
	)
	from secator.ai.interactivity import RemoteBackend, UserInputTimeout, CLIBackend
	from secator.ai.tools.background_jobs import CheckBackgroundJobs, CancelBackgroundJob
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
		self.mgr = BackgroundJobs(max_jobs=3, max_wait=10)
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
		later = list(tool.run({"job_ids": ["bg-1"], "wait": 5, "tool_call_id": "tc-p2",
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
		polled = list(CheckBackgroundJobs().run({"wait": 5, "tool_call_id": "tc-p"}, self.ctx))
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

	def test_hold_is_capped_by_max_wait(self):
		mgr = BackgroundJobs(max_jobs=1, max_wait=0)
		self.assertFalse(mgr.should_hold_idle())  # no job running
		gate = _Gate()
		self.addCleanup(gate.release.set)
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=mgr)
		mgr.submit(_action("tc", True, name="slow"), ctx, gate.dispatch)
		self.assertFalse(mgr.should_hold_idle())  # cap (0s) reached
		mgr.max_wait = 60
		mgr._hold_since = None
		self.assertTrue(mgr.should_hold_idle())


if __name__ == '__main__':
	unittest.main()

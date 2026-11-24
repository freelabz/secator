# tests/unit/test_ai_background_wake.py
"""Event-driven background jobs: the end of a turn waits for the FIRST of a job finishing
(the model is woken with its results) and the user's next message.

Runs the REAL ai loop + RemoteBackend + background registry with a scripted LLM (no network,
no real LLM), reusing the conversation harness of test_ai_conversation_e2e.
"""
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.background import BackgroundJobs, CANCELLED, DONE
	from secator.ai.interactivity import (
		AutoBackend, BACKGROUND_WAKE, CLIBackend, RemoteBackend, TUIBackend, UserInputTimeout)
	from secator.output_types import Url
	from tests.unit.test_ai_conversation_e2e import ChannelEngine, _drive, _make_task

NOTE = "[System note, not a user message]"


def _action(name):
	return {"action": "task", "name": name, "targets": ["example.com"], "description": f"run {name}",
	        "tool_call_id": f"tc-{name}", "tool_call_name": "run_task"}


class _Jobs:
	"""Background jobs started by the scripted model: each blocks on its own gate."""

	def __init__(self):
		self.gates = {}

	def dispatch(self, action, ctx):
		from secator.ai.background import current_job
		gate = self.gates.setdefault(action["name"], threading.Event())
		job = current_job()
		deadline = time.time() + 10
		while not gate.wait(0.01):
			if job.cancel_event.is_set() or time.time() > deadline:
				return
		yield Url(url=f"http://example.com/{action['name']}", _context={"tool_call_id": action["tool_call_id"]})

	def start(self, task, name):
		self.gates.setdefault(name, threading.Event())
		return task.background.submit(_action(name), task._isolation_ctx, self.dispatch)

	def finish(self, task, name):
		self.gates[name].set()
		task.background.get(next(j.id for j in task.background.jobs.values() if j.action["name"] == name)).thread.join(5)

	def release_all(self):
		for g in self.gates.values():
			g.set()


def _scripted(steps):
	"""LLM whose n-th call runs ``steps[n](messages)`` and replies content-only."""
	calls = []

	def _fn(messages, model, temp, api_base, api_key, tools=None):
		calls.append([dict(m) for m in messages])
		if len(calls) <= len(steps) and steps[len(calls) - 1]:
			steps[len(calls) - 1](messages)
		return {"content": f"reply {len(calls)}", "tool_calls": [], "usage": {"tokens": 5, "cost": 0.0},
		        "finish_reason": "stop"}
	return _fn, calls


def _last_user(messages):
	return [m for m in messages if m.get("role") == "user"][-1]["content"]


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestBackgroundWakeLoop(unittest.TestCase):

	def setUp(self):
		self.jobs = _Jobs()
		self.addCleanup(self.jobs.release_all)

	def _task(self, steps, answers=None, max_wait=30, backend=None):
		engine = ChannelEngine(answers=answers or [])
		fn, calls = _scripted(steps)
		task = _make_task(engine, fn, seed_user="scan example.com")
		task.backend = backend or RemoteBackend(timeout=0.05, query_engine=engine, poll_interval=0.01)
		task.background_max_wait = max_wait
		return task, calls

	def test_job_end_wakes_the_model_with_its_results(self):
		def start(_):
			self.jobs.start(task, "nuclei")
			threading.Timer(0.3, self.jobs.gates["nuclei"].set).start()
		task, calls = self._task([start])
		_drive(task)
		# Turn 1 starts the job and ends; the user never writes; the job end wakes turn 2.
		# No user timeout while the job ran (0.05s timeout vs a 0.3s job); once it finished
		# and nothing runs, the timeout applies again and the run parks.
		self.assertEqual(len(calls), 2)
		note = _last_user(calls[1])
		self.assertIn(NOTE, note)
		self.assertIn("bg-1 [done", note)
		self.assertIn("http://example.com/nuclei", note)
		self.assertIn("<workspace_data>", note)
		job = task.background.get("bg-1")
		self.assertTrue(job.final_read)
		self.assertTrue(job.woken)
		# Its results were read by the wake: the status block does not list it again.
		self.assertNotIn("<background_jobs>", note)

	def test_user_message_wakes_normally(self):
		task, calls = self._task([None], answers=["what did you find?"])
		_drive(task)
		self.assertEqual(len(calls), 2)
		self.assertEqual(_last_user(calls[1]), "what did you find?")

	def test_user_message_and_job_end_together_one_wake_each_in_order(self):
		def start_and_finish(_):
			self.jobs.start(task, "nuclei")
			self.jobs.finish(task, "nuclei")  # ends while the model is in its turn
		task, calls = self._task([start_and_finish], answers=["status?"])
		_drive(task)
		self.assertEqual(len(calls), 3)
		# Wake 1: the user's message (with the status block telling the job is finished).
		self.assertTrue(_last_user(calls[1]).startswith("status?"))
		self.assertIn("FINISHED and not read yet: bg-1", _last_user(calls[1]))
		# Wake 2: the job end, with its results. No third wake for the same job.
		self.assertIn(NOTE, _last_user(calls[2]))
		self.assertIn("http://example.com/nuclei", _last_user(calls[2]))

	def test_several_jobs_finishing_together_one_wake(self):
		def start_two(_):
			self.jobs.start(task, "a")
			self.jobs.start(task, "b")
			self.jobs.finish(task, "a")
			self.jobs.finish(task, "b")
		task, calls = self._task([start_two])
		_drive(task)
		self.assertEqual(len(calls), 2)
		note = _last_user(calls[1])
		self.assertIn("http://example.com/a", note)
		self.assertIn("http://example.com/b", note)

	def test_status_block_every_turn_and_max_wait_cap(self):
		def start_two(_):
			self.jobs.start(task, "fast")
			self.jobs.start(task, "server")  # never finishes on its own

		def finish_fast(_):
			self.jobs.finish(task, "fast")
		task, calls = self._task([start_two, finish_fast, None], answers=["go on"], max_wait=1)
		start = time.time()
		_drive(task)
		# 1: starts jobs. 2: user message. 3: woken by `fast` ending. 4: woken by the cap:
		# `server` is cancelled. Then nothing runs and the user timeout ends the run.
		self.assertEqual(len(calls), 4)
		self.assertLess(time.time() - start, 8)
		for turn in (1, 2):
			self.assertIn("<background_jobs>", _last_user(calls[turn]))
			self.assertIn("bg-2 [running", _last_user(calls[turn]))
		self.assertIn("http://example.com/fast", _last_user(calls[2]))
		cap = _last_user(calls[3])
		self.assertIn("No background job finished within 1s: cancelled bg-2", cap)
		self.assertEqual(task.background.get("bg-2").status, CANCELLED)

	def test_non_interactive_run_waits_then_wakes_with_results(self):
		def start(_):
			self.jobs.start(task, "nuclei")
			threading.Timer(0.2, self.jobs.gates["nuclei"].set).start()
		task, calls = self._task([start], backend=AutoBackend())
		_drive(task)
		self.assertEqual(len(calls), 2)
		self.assertIn("http://example.com/nuclei", _last_user(calls[1]))
		self.assertEqual(task.background.get("bg-1").status, DONE)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestBackendWake(unittest.TestCase):

	def test_remote_wake_expires_its_prompt(self):
		engine = ChannelEngine()
		engine.insert({"_type": "ai", "ai_type": "stopped", "status": "pending", "_context": {"session_id": "s"},
		               "extra_data": {"prompt_uuid": "p1"}})
		backend = RemoteBackend(timeout=5, query_engine=engine, poll_interval=0.01)
		backend.wake_when = lambda: True
		res = backend.ask_user("next?", [], "s", prompt_uuid="p1", background_wake=True)
		self.assertEqual(res["answer"], BACKGROUND_WAKE)
		self.assertEqual(engine.docs[0]["status"], "timed_out")

	def test_remote_answer_wins_over_wake(self):
		engine = ChannelEngine(answers=["hi"])
		engine.insert({"_type": "ai", "ai_type": "stopped", "status": "pending", "_context": {"session_id": "s"},
		               "extra_data": {"prompt_uuid": "p1"}})
		backend = RemoteBackend(timeout=5, query_engine=engine, poll_interval=0.01)
		backend.wake_when = lambda: True
		self.assertEqual(backend.ask_user("next?", [], "s", prompt_uuid="p1", background_wake=True)["answer"], "hi")

	def test_remote_no_wake_for_permission_prompts(self):
		engine = ChannelEngine()
		backend = RemoteBackend(timeout=0.03, query_engine=engine, poll_interval=0.01)
		backend.wake_when = lambda: True
		with self.assertRaises(UserInputTimeout):
			backend.ask_user("allow?", [], "s", prompt_type="permission", prompt_uuid="p1", background_wake=True)

	def test_remote_idle_timeout_only_while_no_job_runs(self):
		mgr = BackgroundJobs(max_jobs=3, max_wait=600)
		backend = RemoteBackend(timeout=10, poll_interval=1)
		backend.hold_while = mgr.should_hold_idle
		mgr.running = lambda: ["bg-1"]
		self.assertEqual(backend.idle_tick(3, 1), 3)  # frozen
		mgr.running = lambda: []
		self.assertEqual(backend.idle_tick(3, 1), 4)  # counts again

	def test_cli_prompt_cannot_be_woken_and_waits_on_jobs(self):
		from secator.tasks.ai import ai as AiTask
		self.assertFalse(CLIBackend.can_wake)
		fake = MagicMock()
		fake.background.running.return_value = ["bg-1"]
		for backend, expected in ((CLIBackend(), True), (AutoBackend(), True), (RemoteBackend(), False),
		                          (TUIBackend(), False)):
			fake.backend = backend
			self.assertIs(AiTask._should_wait_background(fake), expected, type(backend).__name__)

	def test_stop_request_ends_a_blocked_wait(self):
		from secator.tasks.ai import ai as AiTask
		fake = SimpleNamespace(backend=AutoBackend(), stop_requested=False)
		self.assertFalse(AiTask._background_interrupt(fake))
		fake.stop_requested = True
		self.assertTrue(AiTask._background_interrupt(fake))

	def test_tui_backend_passes_the_wake_check(self):
		tui = MagicMock()
		tui.tui_ask_user.return_value = {"answer": BACKGROUND_WAKE}
		backend = TUIBackend()
		backend.wake_when = lambda: True
		with patch("secator.rich.get_tui", return_value=tui):
			self.assertEqual(backend.ask_user("next?", [], "s", background_wake=True)["answer"], BACKGROUND_WAKE)
			self.assertTrue(tui.tui_ask_user.call_args.kwargs["wake"]())
			backend.ask_user("allow?", [], "s", prompt_type="permission", background_wake=True)
			self.assertNotIn("wake", tui.tui_ask_user.call_args.kwargs)

	def test_tui_does_not_wake_a_user_who_is_typing(self):
		from secator.tui.app import TUIApp
		ev = threading.Event()
		box = SimpleNamespace(text="half a sentence")
		resolved = []
		app = SimpleNamespace(_pending_ask=(ev, {}, [], "stopped"), _active_choice=None,
		                      query_one=lambda *a: box, _restore_input=lambda: None,
		                      _resolve_pending=resolved.append)
		self.assertFalse(TUIApp._wake_pending(app, ev))
		box.text = ""
		self.assertTrue(TUIApp._wake_pending(app, ev))
		self.assertEqual(resolved, [BACKGROUND_WAKE])
		self.assertFalse(TUIApp._wake_pending(app, threading.Event()))  # another prompt: untouched


if __name__ == '__main__':
	unittest.main()

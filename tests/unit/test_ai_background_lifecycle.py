# tests/unit/test_ai_background_lifecycle.py
"""Run lifecycle around background jobs, through the REAL ai loop (scripted LLM, no network):

- an interactive run never wakes the model on its own: new turns come from the user only,
and a user message sent while a job runs sees the job in the status block;
- a non-interactive run waits (no bound) for running jobs, then gives the model a turn;
- the iteration cap (a hard limit) ends the run without waiting, and the run teardown
cancels the jobs still running;
- a background shell killed at its max run time ends its job as "timed out after Ns";
- a restore after a crash tells the model, once, which jobs were lost.
"""
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.actions import ActionContext
	from secator.ai.background import (
		BackgroundJobs, register_runner_hook, lost_jobs, CANCELLED, DONE, FAILED, RUNNING)
	from secator.ai.interactivity import AutoBackend
	from secator.output_types import Ai
	from secator.tasks.ai import ai as AiTask
	from tests.unit.test_ai_conversation_e2e import ChannelEngine, _make_task, _drive, _ctx


def _llm(script):
	"""Scripted call_llm: each step is ``fn(task, messages) -> response dict``."""
	calls = []

	def _fn(messages, model, temp, api_base, api_key, tools=None):
		step = script[min(len(calls), len(script) - 1)]
		calls.append([dict(m) for m in messages])
		return step(messages)
	return _fn, calls


def _content(text):
	return {"content": text, "tool_calls": [], "usage": {"tokens": 10, "cost": 0.0}, "finish_reason": "stop"}


class _Gate:
	"""Dispatch for one slow background job, released by the test (or a cancel)."""

	def __init__(self):
		self.release = threading.Event()

	def dispatch(self, action, ctx):
		runner = SimpleNamespace(stop_process=MagicMock(side_effect=lambda **kw: self.release.set()),
		                         sync=True, celery_ids_map={})
		register_runner_hook(runner)
		yield Ai(content="nuclei", ai_type="task", extra_data={"runner_id": "rid-1", "runner_type": "task"},
		         _context={"tool_call_id": action["tool_call_id"]})
		self.release.wait(10)


def _submit(task, gate, tc_id="tc-bg"):
	action = {"action": "task", "name": "nuclei", "targets": ["example.com"], "background": True,
	          "description": "Scan for CVEs", "tool_call_id": tc_id, "tool_call_name": "run_task"}
	ctx = ActionContext(targets=["example.com"], model="m", results=[], background=task.background)
	return task.background.submit(action, ctx, gate.dispatch)


def _last_user(messages):
	return [m for m in messages if m.get("role") == "user"][-1]["content"]


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestInteractiveRun(unittest.TestCase):

	def setUp(self):
		self.gate = _Gate()
		self.addCleanup(self.gate.release.set)

	def test_no_auto_wake_when_a_job_ends(self):
		"""The job ends while the run waits for the user: no model turn is started for it,
		and the idle timer (held while it ran) then ends the run as usual."""
		e = ChannelEngine(answers=[])

		def turn1(messages):
			_submit(t, self.gate)
			threading.Timer(0.1, self.gate.release.set).start()
			return _content("Started a nuclei scan in the background.")
		fn, calls = _llm([turn1])
		t = _make_task(e, fn)
		_drive(t)
		self.assertEqual(len(calls), 1)  # no wake on the job's end
		self.assertEqual(t.background.get("bg-1").status, DONE)

	def test_user_message_mid_job_sees_it_running(self):
		"""A user message ("So ?") sent while the job runs starts a turn whose status block lists
		the job as running."""
		e = ChannelEngine(answers=["So ?"])

		def turn1(messages):
			_submit(t, self.gate)
			return _content("Started a nuclei scan in the background.")

		def turn2(messages):
			self.gate.release.set()
			return _content("Still scanning.")
		fn, calls = _llm([turn1, turn2])
		t = _make_task(e, fn)
		_drive(t)
		self.assertEqual(len(calls), 2)
		last = _last_user(calls[1])
		self.assertIn("So ?", last)
		self.assertIn("<background_jobs>", last)
		self.assertIn("bg-1 [running", last)
		self.assertIn("Do not comment on jobs still running", last)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestNonInteractiveRun(unittest.TestCase):

	def setUp(self):
		self.gate = _Gate()
		self.addCleanup(self.gate.release.set)

	def _task(self, fn, cap=8):
		t = _make_task(ChannelEngine(), fn, initial_cap=cap)
		t.backend = AutoBackend()
		t.interactive = "auto"
		t.mode = "scan"
		return t

	def test_waits_for_jobs_then_gives_one_turn(self):
		def turn1(messages):
			_submit(t, self.gate)
			threading.Timer(0.3, self.gate.release.set).start()
			return _content("Scan started, nothing else to do.")
		fn, calls = _llm([turn1, lambda m: _content("nuclei found CVE-2021-41773.")])
		t = self._task(fn)
		_drive(t)
		self.assertEqual(len(calls), 2)  # one turn after the wait, then the run ends
		last = _last_user(calls[1])
		self.assertIn("A background job finished", last)
		self.assertIn("FINISHED since you last read them: bg-1", last)
		self.assertEqual(t.background.get("bg-1").status, DONE)
		self.assertFalse(t.background.running())

	def test_job_finished_during_the_turn_gets_one_turn(self):
		"""A job that finished while the model was thinking (none running at the end of the turn)
		still gets the model one turn to report it; then the run ends even if it was not read."""
		def turn1(messages):
			job = _submit(t, self.gate)
			self.gate.release.set()
			job.thread.join(5)
			return _content("Scan started.")
		fn, calls = _llm([turn1, lambda m: _content("Done."), lambda m: _content("should not run")])
		t = self._task(fn)
		_drive(t)
		self.assertEqual(len(calls), 2)
		self.assertIn("FINISHED since you last read them: bg-1", _last_user(calls[1]))

	def test_iteration_cap_ends_without_waiting_and_teardown_cancels(self):
		def turn1(messages):
			_submit(t, self.gate)
			tc = MagicMock()
			tc.id = "tc-q"
			tc.function.name = "check_background_jobs"
			tc.function.arguments = "{}"
			return {"content": "", "tool_calls": [tc], "usage": {"tokens": 10, "cost": 0.0}}
		fn, calls = _llm([turn1])
		t = self._task(fn, cap=1)
		_drive(t)
		self.assertEqual(len(calls), 1)
		job = t.background.get("bg-1")
		self.assertEqual(job.status, RUNNING)  # the cap did not wait for it
		AiTask._teardown_background(t)  # the run's `finally`
		self.assertEqual(job.status, CANCELLED)
		records = [i for i in t.emitted if isinstance(i, Ai) and i.ai_type == "background_job"
		           and i.extra_data.get("status") == CANCELLED]
		self.assertEqual(len(records), 1)

	def test_explicit_stop_ends_without_waiting(self):
		"""The model calls `stop` while a job runs: the run ends at once (no wait, no extra turn);
		the run teardown then cancels the job."""
		def turn1(messages):
			_submit(t, self.gate)
			tc = MagicMock()
			tc.id = "tc-stop"
			tc.function.name = "stop"
			tc.function.arguments = '{"reason": "Nothing more to do."}'
			return {"content": "", "tool_calls": [tc], "usage": {"tokens": 10, "cost": 0.0}}
		fn, calls = _llm([turn1, lambda m: _content("should not run")])
		t = self._task(fn)
		_drive(t)
		self.assertEqual(len(calls), 1)
		job = t.background.get("bg-1")
		self.assertEqual(job.status, RUNNING)
		AiTask._teardown_background(t)
		self.assertEqual(job.status, CANCELLED)

	def test_cancelled_by_parent_ends_at_next_turn(self):
		"""A parent cancelling this run (subagent) sets stop_requested: the run ends without
		another model turn."""
		def turn1(messages):
			_submit(t, self.gate)
			t.stop_requested = True
			return _content("Scan started.")
		fn, calls = _llm([turn1, lambda m: _content("should not run")])
		t = self._task(fn)
		start = time.time()
		_drive(t)
		self.assertLess(time.time() - start, 5)  # the wait ended on the cancel, not on the job
		self.assertEqual(len(calls), 1)
		self.assertEqual(t.background.get("bg-1").status, RUNNING)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestBackgroundShellTimeout(unittest.TestCase):

	def test_timed_out_shell_job_status(self):
		mgr = BackgroundJobs(max_jobs=1)

		def dispatch(action, ctx):
			yield Ai(content="[timed out after 7s]", ai_type="shell_output",
			         extra_data={"runner_id": "r", "timed_out": True, "timeout": 7})
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=mgr)
		job = mgr.submit({"action": "shell", "command": "nc -lvp 4444", "background": True,
		                  "tool_call_id": "tc", "tool_call_name": "run_shell"}, ctx, dispatch)
		job.thread.join(5)
		self.assertEqual(job.status, FAILED)
		self.assertEqual(job.error, "timed out after 7s")
		self.assertIn("timed out after 7s", mgr.status_block())


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestLostJobsAfterRestore(unittest.TestCase):

	def _docs(self):
		ctx = {**_ctx(), "tool_call_id": "tc-1"}
		return [
			# run 1: bg-1 ended (cancelled), bg-2 lost (still running in its latest record)
			{"_type": "ai", "ai_type": "background_job", "_timestamp": 1, "_context": ctx,
			 "extra_data": {"job_id": "bg-1", "status": "running", "tool": "run_task", "runner_ids": []}},
			{"_type": "ai", "ai_type": "background_job", "_timestamp": 2, "_context": ctx,
			 "extra_data": {"job_id": "bg-1", "status": "cancelled", "tool": "run_task", "runner_ids": ["r1"]}},
			{"_type": "ai", "ai_type": "background_job", "_timestamp": 3,
			 "_context": {**_ctx(), "tool_call_id": "tc-2"},
			 "extra_data": {"job_id": "bg-2", "status": "running", "tool": "run_workflow",
			                "description": "Full recon", "runner_ids": ["wf-9"], "runner_type": "workflow"}},
			# a subagent's own job: not this conversation's
			{"_type": "ai", "ai_type": "background_job", "_timestamp": 4,
			 "_context": {**_ctx(), "tool_call_id": "tc-3", "subagent": "x"},
			 "extra_data": {"job_id": "bg-1", "status": "running", "tool": "run_task"}},
		]

	def test_lost_jobs(self):
		lost = lost_jobs(self._docs())
		self.assertEqual([j["job_id"] for j in lost], ["bg-2"])
		self.assertEqual(lost[0]["tool_call_id"], "tc-2")

	def test_note_injected_once_and_jobs_marked_lost(self):
		e = ChannelEngine(docs=self._docs())
		t = _make_task(e, None)
		t._note_lost_background_jobs(e)
		messages = [{"role": "user", "content": "So ?"}]
		first = t._with_background_status(messages)
		note = first[-1]["content"]
		self.assertIn("<lost_background_jobs>", note)
		self.assertIn("bg-2 run_workflow - Full recon (query key `_context.workflow_id`: wf-9)", note)
		self.assertIn("query_workspace", note)
		self.assertNotIn("bg-1", note)
		self.assertEqual(t._with_background_status(messages), messages)  # only once
		# recorded as lost: a later restore does not report it again
		t2 = _make_task(e, None)
		t2._note_lost_background_jobs(e)
		self.assertFalse(getattr(t2, "_lost_background_note", ""))

	def test_same_job_id_in_two_runs(self):
		"""Job ids restart per run: jobs are told apart by their tool call id."""
		docs = [
			{"_timestamp": 1, "_context": {"tool_call_id": "a"}, "extra_data": {"job_id": "bg-1", "status": "running"}},
			{"_timestamp": 2, "_context": {"tool_call_id": "a"}, "extra_data": {"job_id": "bg-1", "status": "done"}},
			{"_timestamp": 3, "_context": {"tool_call_id": "b"}, "extra_data": {"job_id": "bg-1", "status": "running"}},
			# a final record with the same (rounded) timestamp as its running record wins
			{"_timestamp": 4, "_context": {"tool_call_id": "c"}, "extra_data": {"job_id": "bg-2", "status": "done"}},
			{"_timestamp": 4, "_context": {"tool_call_id": "c"}, "extra_data": {"job_id": "bg-2", "status": "running"}},
		]
		self.assertEqual([j["tool_call_id"] for j in lost_jobs(docs)], ["b"])

	def test_task_job_query_key_and_detached_still_running(self):
		docs = [{"_type": "ai", "ai_type": "background_job", "_timestamp": 1,
		         "_context": {**_ctx(), "tool_call_id": "tc-9"},
		         "extra_data": {"job_id": "bg-1", "status": "running", "tool": "run_task", "detached": True,
		                        "runner_ids": ["chunk-1"], "runner_type": "task"}}]
		e = ChannelEngine(docs=docs)
		e.get_runner_status = lambda rid, rtype: {"status": "RUNNING", "done": False}
		t = _make_task(e, None)
		t._note_lost_background_jobs(e)
		note = t._lost_background_note
		self.assertIn("query key `_context.task_chunk_id`: chunk-1", note)
		self.assertIn("still running on a worker", note)

	def test_runner_ids_recorded_while_running(self):
		"""The drain records a running job's runner ids once known, so a crash still leaves them."""
		from tests.unit.test_ai_background import _fake_runner
		mgr = BackgroundJobs(max_jobs=1)
		gate = _Gate()
		self.addCleanup(gate.release.set)
		fake, persisted = _fake_runner(mgr)
		ctx = ActionContext(targets=["example.com"], model="m", results=[], background=mgr)
		job = mgr.submit({"action": "task", "name": "nuclei", "background": True, "tool_call_id": "tc",
		                  "tool_call_name": "run_task"}, ctx, gate.dispatch)
		for _ in range(50):
			if job.items:
				break
			threading.Event().wait(0.02)
		AiTask._drain_background_items(fake)
		AiTask._drain_background_items(fake)  # no change: no second record
		records = [p for p in persisted if isinstance(p, Ai) and p.ai_type == "background_job"]
		self.assertEqual(len(records), 1)
		self.assertEqual((records[0].extra_data["status"], records[0].extra_data["runner_ids"]),
		                 (RUNNING, ["rid-1"]))


if __name__ == '__main__':
	unittest.main()

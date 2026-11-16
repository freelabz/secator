"""Local history persistence: the session is saved at every end of turn, atomically.

A local session used to write ``history.json`` only when the run EXITED cleanly. Quitting
the interactive UI while it waited for the next prompt (or a crash / kill there) never
reached those exit paths, so every turn since the last clean exit was lost and a resume
replayed a stale (or no) history. These tests run the REAL ai runner (scripted LLM, no
network), kill it while it waits for the user, and resume from what was saved.
"""
import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

from secator.definitions import ADDONS_ENABLED

HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.history import ChatHistory
	from secator.ai.interactivity import InteractivityBackend
	from secator.ai.session import list_sessions, save_history
	from secator.config import CONFIG
	from secator.tasks.ai import ai as AiTask


class _Killed(BaseException):
	"""Simulates the process dying while it waits for the user (no except/finally save)."""


def _core(msg):
	"""The model-facing fields of a message (drops private bookkeeping like token caches)."""
	return {k: v for k, v in msg.items() if not k.startswith("_")}


def _scripted_llm(calls):
	"""Odd calls: a tool call (update_plan); even calls: a content-only reply (end of turn)."""
	def fake(messages, *a, **k):
		calls.append([dict(m) for m in messages])
		n = len(calls)
		if n % 2 == 1:
			return {"content": f"working on it ({n})", "usage": {}, "tool_calls": [NS(
				id=f"call_{n}", type="function",
				function=NS(name="update_plan", arguments=json.dumps({"items": [{"text": f"step {n}"}]})))]}
		return {"content": f"reply {n}", "tool_calls": [], "usage": {}}
	return fake


if HAS_AI:
	class _Backend(InteractivityBackend):
		interactive = True

		def __init__(self, answers, kill_when_exhausted):
			self.answers = list(answers)
			self.kill = kill_when_exhausted

		def get_initial_prompt(self, inputs, **context):
			return "first question"

		def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
			if prompt_type == "permission":
				return {"answer": "allow"}
			if self.answers:
				return {"answer": self.answers.pop(0)}
			if self.kill:
				raise _Killed()
			return None


@unittest.skipUnless(HAS_AI, "ai addon not installed")
class TestSaveHistoryAtomic(unittest.TestCase):

	def test_failed_write_keeps_previous_file_and_leaves_no_temp(self):
		with tempfile.TemporaryDirectory() as tmp:
			h = ChatHistory()
			h.messages = [{"role": "user", "content": "kept"}]
			save_history(h, tmp)
			h.messages = [{"role": "user", "content": "new"}]
			with mock.patch("secator.ai.session.json.dump", side_effect=OSError("disk full")):
				save_history(h, tmp, debug_fn=lambda *a, **k: None)
			self.assertEqual(json.loads((Path(tmp) / "history.json").read_text()), [{"role": "user", "content": "kept"}])
			self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["history.json"])

	def test_write_replaces_whole_file(self):
		with tempfile.TemporaryDirectory() as tmp:
			h = ChatHistory()
			h.messages = [{"role": "user", "content": "a" * 1000}]
			save_history(h, tmp)
			h.messages = [{"role": "user", "content": "b"}]
			save_history(h, tmp)
			self.assertEqual(json.loads((Path(tmp) / "history.json").read_text()), [{"role": "user", "content": "b"}])


@unittest.skipUnless(HAS_AI, "ai addon not installed")
class TestKilledSessionResume(unittest.TestCase):

	def _run(self, backend, calls, resume=False):
		aimod = sys.modules["secator.tasks.ai"]
		with contextlib.ExitStack() as stack:
			stack.enter_context(mock.patch.object(aimod, "call_llm", _scripted_llm(calls)))
			stack.enter_context(mock.patch.object(aimod, "create_backend", lambda *a, **k: backend))
			stack.enter_context(mock.patch.object(aimod, "show_session_picker", lambda: list_sessions()[0]))
			stack.enter_context(mock.patch.object(aimod.time, "sleep", lambda *a: None))
			task = AiTask(
				[], mode="chat", model="gpt-4o", interactive="local", headless=True, sync=True,
				print_item=False, print_line=False, print_cmd=False, sensitive=False, resume=resume)
			for _ in task:
				pass

	def test_killed_while_waiting_then_resumed_keeps_all_turns_in_order(self):
		with tempfile.TemporaryDirectory() as tmp, mock.patch.object(CONFIG.dirs, "reports", Path(tmp)):
			# 3 turns (each: tool call + tool result + reply), killed waiting for the 4th prompt.
			# (The runner core records the BaseException as an Error; the ai loop's own
			# exit-path saves are never reached — same as a real kill/quit.)
			self._run(_Backend(["second question", "third question"], kill_when_exhausted=True), [])

			sessions = list_sessions()
			self.assertEqual(len(sessions), 1, "killed session must still be resumable")
			saved = json.loads(Path(sessions[0]["history_path"]).read_text())
			users = [m["content"] for m in saved if m["role"] == "user" and not m["content"].startswith("{")]
			self.assertEqual(users, ["first question", "second question", "third question"])
			self.assertEqual([m["content"] for m in saved if m["role"] == "assistant" and not m.get("tool_calls")],
			                 ["reply 2", "reply 4", "reply 6"])
			# every tool call is followed by its result
			self.assertEqual([m["tool_call_id"] for m in saved if m["role"] == "tool"], ["call_1", "call_3", "call_5"])

			# resume: the model is handed the full saved transcript, in order, then the new prompt
			calls = []
			self._run(_Backend(["after resume"], kill_when_exhausted=False), calls, resume=True)
			sent = [_core(m) for m in calls[0] if m["role"] != "system"]
			expected = [_core(m) for m in saved if m["role"] != "system"]
			self.assertEqual(sent, expected + [{"role": "user", "content": "after resume"}])

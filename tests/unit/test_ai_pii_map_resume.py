"""Sensitive-data placeholder map across a resume.

With ``--sensitive`` the ai task replaces hosts/IPs/emails with ``[TYPE:hash]`` placeholders
before anything reaches the model, and maps them back in tool-call arguments and display.
The placeholder -> value map lives in memory; it used to be persisted / restored only for the
remote channel, so a LOCALLY resumed session started with an empty map and the model's tool
calls ran with the literal placeholder (e.g. ``http://[HOST:...]``).

These run the REAL ai runner (scripted LLM, local json store): session A masks a host, the
session is resumed, and a tool call carrying A's placeholder must be unmasked; a placeholder
no map can resolve must be rejected, never run.
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
	from secator.ai.encryption import SensitiveDataEncryptor, find_placeholders
	from secator.ai.interactivity import InteractivityBackend
	from secator.ai.session import list_sessions
	from secator.config import CONFIG
	from secator.tasks.ai import ai as AiTask

HOST = "internal-target.example.com"


def _plan_call(call_id, text):
	return NS(id=call_id, type="function",
	          function=NS(name="update_plan", arguments=json.dumps({"items": [{"text": text}]})))


if HAS_AI:
	class _Backend(InteractivityBackend):
		interactive = True

		def __init__(self, first_prompt, answers=()):
			self.first_prompt = first_prompt
			self.answers = list(answers)

		def get_initial_prompt(self, inputs, **context):
			return self.first_prompt

		def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
			if prompt_type == "permission":
				return {"answer": "allow"}
			return {"answer": self.answers.pop(0)} if self.answers else None


@unittest.skipUnless(HAS_AI, "ai addon not installed")
class TestFindPlaceholders(unittest.TestCase):

	def test_finds_bracketed_garbled_and_bare_hex_forms(self):
		args = {"cmd": "curl http://[HOST:shhfurirind]/", "list": ["x", {"t": "IPV4:0123456789ab"}]}
		self.assertEqual(find_placeholders(args), ["[HOST:shhfurirind]", "IPV4:0123456789ab"])

	def test_plain_values_pass(self):
		self.assertEqual(find_placeholders({"url": "http://host.example.com:8080/a", "n": 3}), [])


@unittest.skipUnless(HAS_AI, "ai addon not installed")
class TestPlaceholderMapSurvivesResume(unittest.TestCase):

	def _run(self, backend, llm, resume=False):
		aimod = sys.modules["secator.tasks.ai"]
		items = []
		with contextlib.ExitStack() as stack:
			stack.enter_context(mock.patch.object(aimod, "call_llm", llm))
			stack.enter_context(mock.patch.object(aimod, "create_backend", lambda *a, **k: backend))
			stack.enter_context(mock.patch.object(aimod, "show_session_picker", lambda: list_sessions()[0]))
			stack.enter_context(mock.patch.object(aimod.time, "sleep", lambda *a: None))
			task = AiTask(
				[], mode="chat", model="gpt-4o", interactive="local", headless=True, sync=True,
				print_item=False, print_line=False, print_cmd=False, sensitive=True, resume=resume)
			for item in task:
				items.append(item.toDict() if hasattr(item, "toDict") else item)
		return items

	def test_old_placeholder_unmasked_after_resume_and_unknown_rejected(self):
		placeholder = SensitiveDataEncryptor().encrypt(HOST)
		self.assertNotEqual(placeholder, HOST)
		bogus = "[HOST:shhfurirind]"

		# --- session A: the user's prompt mentions the host; the model only sees the placeholder
		seen_a = []

		def llm_a(messages, *a, **k):
			seen_a.append(messages)
			return {"content": "noted", "tool_calls": [], "usage": {}}

		with tempfile.TemporaryDirectory() as tmp, mock.patch.object(CONFIG.dirs, "reports", Path(tmp)):
			self._run(_Backend(f"look at {HOST}"), llm_a)
			sent = json.dumps(seen_a[0])
			self.assertIn(placeholder, sent)
			self.assertNotIn(HOST, sent)

			# --- resume: the model reuses A's placeholder, then a placeholder no map knows
			calls = []

			def llm_b(messages, *a, **k):
				calls.append(messages)
				if len(calls) == 1:
					return {"content": "", "usage": {}, "tool_calls": [
						_plan_call("c1", f"probe {placeholder}"), _plan_call("c2", f"curl http://{bogus}/")]}
				return {"content": "done", "tool_calls": [], "usage": {}}

			items = self._run(_Backend("", ["continue"]), llm_b, resume=True)

		plans = [i for i in items if isinstance(i, dict) and i.get("ai_type") == "plan"]
		self.assertEqual(len(plans), 1, "only the resolvable call may run")
		self.assertEqual(plans[0]["extra_data"]["items"][0]["text"], f"probe {HOST}")

		rejected = [i for i in items if isinstance(i, dict) and i.get("ai_type") == "tool_result"
		            and (i.get("extra_data") or {}).get("error")]
		self.assertEqual(len(rejected), 1)
		self.assertIn(bogus, rejected[0]["extra_data"]["reason"])
		# the model is told why (tool result for c2), and never sees the real host
		tool_msgs = [m for m in calls[1] if m.get("role") == "tool" and m.get("tool_call_id") == "c2"]
		self.assertIn("unknown sensitive-data placeholder", tool_msgs[0]["content"])
		self.assertNotIn(HOST, json.dumps(calls[1]))

	def test_same_value_maps_to_same_placeholder_across_runs(self):
		# deterministic salted hash: a value re-seen after a resume gets the SAME placeholder
		self.assertEqual(SensitiveDataEncryptor().encrypt(HOST), SensitiveDataEncryptor().encrypt(HOST))

	def test_tool_call_debug_log_never_holds_decrypted_values(self):
		placeholder = SensitiveDataEncryptor().encrypt(HOST)
		logged = []
		calls = []

		def llm(messages, *a, **k):
			calls.append(1)
			if len(calls) == 1:
				return {"content": "", "usage": {}, "tool_calls": [_plan_call("c1", f"probe {placeholder}")]}
			return {"content": "done", "tool_calls": [], "usage": {}}

		with tempfile.TemporaryDirectory() as tmp, mock.patch.object(CONFIG.dirs, "reports", Path(tmp)):
			with mock.patch.object(AiTask, "debug", lambda self, msg, *a, **k: logged.append(str(msg))):
				items = self._run(_Backend(f"look at {HOST}"), llm)
		# the call did run with the real value...
		plans = [i for i in items if isinstance(i, dict) and i.get("ai_type") == "plan"]
		self.assertEqual(plans[0]["extra_data"]["items"][0]["text"], f"probe {HOST}")
		# ...but the tool-call debug line only ever carries the placeholder
		tool_logs = [m for m in logged if m.startswith("[tool_call]")]
		self.assertTrue(tool_logs)
		self.assertTrue(all(HOST not in m for m in tool_logs), tool_logs)

	def test_prompt_placeholders_persisted_before_first_llm_call(self):
		# The map used to be persisted only after a turn's tool dispatch, so while the first
		# call ran the session's stored map was empty although the model had only received
		# placeholders: a reader of the stored map saw "nothing encrypted".
		email, ip = "admin@example.org", "10.0.0.12"
		events = []

		def _persist(runner_self):
			events.append(("persist", dict(runner_self.encryptor.pii_map)))

		def llm(messages, *a, **k):
			events.append(("call", json.dumps(messages)))
			return {"content": "done", "tool_calls": [], "usage": {}}

		prompt = f"Re-check http://{HOST}:8080 and mail {email} about {ip}"
		with tempfile.TemporaryDirectory() as tmp, mock.patch.object(CONFIG.dirs, "reports", Path(tmp)):
			with mock.patch.object(AiTask, "_persist_pii_map", _persist):
				self._run(_Backend(prompt), llm)

		calls = [i for i, e in enumerate(events) if e[0] == "call"]
		self.assertTrue(calls)
		first = calls[0]
		for value in (HOST, email, ip):
			self.assertNotIn(value, events[first][1])
		persisted = {}
		for kind, payload in events[:first]:
			if kind == "persist":
				persisted.update(payload)
		self.assertEqual({HOST, email, ip} - set(persisted.values()), set())

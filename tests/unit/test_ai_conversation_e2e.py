"""End-to-end mock-LLM conversations through the REAL ai runner + RemoteBackend +
restore, with a simulated web answer channel (an in-memory FakeQueryEngine).

These are the always-green guardrails for the two AI resume/repeat fixes:
  - RC1: `_maybe_resume_remote` re-append guard (`_prompt_already_tail`) — must NOT
    re-append a turn restore already rebuilt, but MUST still apply a genuinely-new
    answer once and continue (the legit answer-after-stop respawn).
  - RC2: the `_prompt_and_redetect` iteration-budget auto-extension is bounded by
    `_MAX_FOLLOWUP_EXTENSIONS`, so an endlessly re-answered follow-up TERMINATES
    instead of spinning to the worker deadline.

No network / no real LLM: `call_llm` is scripted, token counting + context-window +
isolation are stubbed; the loop, `_prompt_and_redetect`, `_maybe_resume_remote`,
restore and RemoteBackend polling all run REAL.
"""
import unittest
import uuid
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.history import ChatHistory
	from secator.ai.interactivity import RemoteBackend
	from secator.output_types import Ai as AiOut
	from secator.tasks.ai import ai as AiTask

SID = "sess-e2e"


def _ctx():
	return {"session_id": SID}


def _get(doc, dotted):
	cur = doc
	for part in dotted.split('.'):
		if not isinstance(cur, dict):
			return None
		cur = cur.get(part)
	return cur


def _match(doc, query):
	for k, v in query.items():
		actual = _get(doc, k)
		if isinstance(v, dict) and '$in' in v:
			if actual not in v['$in']:
				return False
		elif actual != v:
			return False
	return True


class ChannelEngine:
	"""In-memory workspace channel + a scripted web answer channel.

	`answers`: the sequence of user answers the UI submits. On each worker poll for
	a follow-up answer, the latest pending follow-up is flipped to answered with the
	next scripted answer. `standing=True` re-serves answers[0] forever (models the
	observed runaway: the same pasted message re-answering every new follow-up).
	When the script is exhausted (and not standing) follow-ups simply time out — the
	worker parks, exactly like a real chat waiting for the user.
	"""

	def __init__(self, docs=None, answers=None, standing=False):
		self.docs = [dict(d) for d in (docs or [])]
		self.answers = list(answers or [])
		self.standing = standing
		self.idx = 0
		self.backend = type("B", (), {"name": "mongodb"})()

	def _serve_answer(self):
		pend = [d for d in self.docs if d.get("ai_type") == "follow_up" and d.get("status") == "pending"]
		if not pend:
			return
		if self.standing:
			ans = self.answers[0] if self.answers else None
		else:
			ans = self.answers[self.idx] if self.idx < len(self.answers) else None
			if ans is not None:
				self.idx += 1
		if ans is None:
			return
		pend.sort(key=lambda d: d.get("_timestamp", 0))
		pend[-1]["status"] = "answered"
		pend[-1]["answer"] = ans

	def search(self, query, limit=None):
		if query.get("status") == "answered" and query.get("ai_type") == "follow_up":
			self._serve_answer()
		out = [dict(d) for d in self.docs if _match(d, query)]
		return out[:limit] if limit else out

	def update(self, query, update):
		n = 0
		for d in self.docs:
			if _match(d, query):
				d.update(update.get('$set', {}))
				n += 1
		return n

	def insert(self, doc):
		self.docs.append(dict(doc))


def _make_task(engine, call_llm_fn, initial_cap=8, seed_user="initial prompt", run_prompt=None):
	t = object.__new__(AiTask)
	t.inputs = []
	t.model = "gpt-4o"
	t.intent_model = "gpt-4o"
	t.api_key = t.api_base = None
	t.encryptor = None
	t.dry_run = t.verbose = False
	t.temp = 0.0
	t.context = {"session_id": SID, "celery_id": str(uuid.uuid4())}
	t.scope = None
	t.max_workers = 1
	t.is_subagent = False
	t._sync = True
	t.interactive = "remote"
	t.session_id = SID
	t.session_name = "sess"
	t.permission_engine = None
	t.in_scope = t.out_of_scope = None
	t.isolated = False
	t.max_iterations = initial_cap
	t.max_tokens_total = 100000
	t.mode = "chat"
	t.prompt = None
	t.run_opts = {"prompt": run_prompt if run_prompt is not None else ""}
	t.history = ChatHistory(model="gpt-4o")
	t.history.set_system("SYS")
	if seed_user:
		t.history.add_user(seed_user)
	t.history.count_tokens_by_role = lambda model: {"total": 50, "system": 10, "user": 20, "assistant": 20, "tool": 0}
	t.tool_schemas = []
	t.debug = lambda *a, **k: None
	t.backend = RemoteBackend(timeout=0.02, query_engine=engine, poll_interval=0.004)
	t.emitted = []

	def add_result(item, **k):
		t.emitted.append(item)
		if isinstance(item, AiOut):
			engine.insert({
				"_type": "ai", "ai_type": item.ai_type, "content": item.content,
				"status": getattr(item, "status", None), "_timestamp": len(engine.docs) + 1,
				"_uuid": str(uuid.uuid4()), "extra_data": item.extra_data or {},
				"_context": {"session_id": SID},
			})
	t.add_result = add_result
	# Stub only the non-loop collaborators; the loop/resume/redetect run REAL.
	t._drain_steers = lambda: iter(())
	t._summarize_auto = lambda: iter(())
	t._summarize_user = lambda: iter(())
	t._drain_history_usage = lambda: None
	t._persist_pii_map = lambda: None
	t._restore_pii_map = lambda: None
	t._teardown_isolation = lambda: None
	t._mark_turn_completed = lambda: None
	t._save_history = lambda: None
	t._detect_mode = lambda force=False: None
	t._rebuild_prompt_and_tools = lambda: None
	t._system_prompt_for = lambda m: "SYS"
	t._get_query_engine = lambda: engine
	t._call_llm_fn = call_llm_fn
	return t


def _drive(task, method="_run_loop"):
	"""Persist the initial user turn (like run()/resume does), then drive the real
	generator with all LLM/token/context collaborators patched to the mock."""
	import secator.ai.actions as _act
	# For a plain run, emit the seed prompt as a persisted `prompt` doc (run() does this).
	emitted = []
	with patch("secator.tasks.ai.call_llm", task._call_llm_fn), \
			patch("secator.tasks.ai.init_llm", lambda **k: None), \
			patch.object(_act.ActionContext, "get_query_engine", lambda self: task._get_query_engine()), \
			patch("secator.tasks.ai.get_context_window", lambda m: 128000), \
			patch("secator.tasks.ai.format_llm_status", lambda *a, **k: ""):
		emitted.extend(list(getattr(task, method)()))
	task.emitted.extend(emitted)
	return task


def content_only_llm(text="Here is my analysis. What next?"):
	def _fn(messages, model, temp, api_base, api_key, tools=None):
		return {"content": text, "tool_calls": [], "usage": {"tokens": 50, "cost": 0.0}, "finish_reason": "stop"}
	return _fn


def _user_turns(history):
	return [m['content'] for m in history.messages if m.get('role') == 'user']


def _prompt_docs(task):
	return [e for e in task.emitted if isinstance(e, AiOut) and e.ai_type == "prompt"]


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestConversationE2E(unittest.TestCase):

	# Scenario 1: unanswered prompt -> task stops (timeout) -> reboot with NO answer
	# -> the initial prompt is NOT re-appended, and no loop.
	def test_unanswered_then_reboot_no_answer_no_reappend(self):
		# Phase 1: fresh run, model asks; channel never answers -> parks (UserInputTimeout).
		e = ChannelEngine(answers=[])
		e.insert({"_type": "ai", "ai_type": "prompt", "content": "check workspace",
				  "_timestamp": 1, "_context": _ctx()})
		t1 = _make_task(e, content_only_llm(), seed_user="check workspace")
		_drive(t1, "_run_loop")
		# Phase 2: reboot carrying the SAME initial prompt (no genuinely-new input).
		t2 = _make_task(e, content_only_llm(), seed_user=None, run_prompt="check workspace")
		_drive(t2, "_maybe_resume_remote")
		self.assertEqual(_user_turns(t2.history).count("check workspace"), 1)   # not re-appended
		self.assertEqual([p.content for p in _prompt_docs(t2)], [])             # no dup prompt doc

	# Scenario 2 (THE legit flow): answered follow_up -> task stops -> reboot WITH the
	# answer -> the answer is applied EXACTLY ONCE and the conversation CONTINUES.
	def test_answered_followup_reboot_continues_answer_once(self):
		e = ChannelEngine(answers=[])
		# Prior conversation already on the channel, follow_up answered after the stop.
		e.docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "scan the target", "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "which host?", "_timestamp": 2, "_context": _ctx()},
			{"_type": "ai", "ai_type": "follow_up", "content": "which host?", "status": "answered",
			 "answer": "scanme.nmap.org", "_timestamp": 3,
			 "extra_data": {"prompt_uuid": "u1"}, "_context": _ctx()},
		]
		# Reboot carrying that answer; after the resumed run's next content-only turn the
		# channel gives nothing, so it parks (a normal "waiting for user" stop).
		t = _make_task(e, content_only_llm(), seed_user=None, run_prompt="scanme.nmap.org")
		_drive(t, "_maybe_resume_remote")
		# The answer is present exactly once (threaded by restore, NOT re-appended)...
		self.assertEqual(_user_turns(t.history), ["scan the target", "scanme.nmap.org"])
		self.assertEqual([p.content for p in _prompt_docs(t)], [])
		# ...and the resumed run CONTINUED: it produced at least one assistant response.
		responses = [e_ for e_ in t.emitted if isinstance(e_, AiOut) and e_.ai_type == "response"]
		self.assertGreaterEqual(len(responses), 1)

	# Scenario 2b: an answer that is NOT already in history must still be emitted once.
	def test_reboot_with_new_answer_emits_it_once(self):
		e = ChannelEngine(answers=[])
		e.docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "scan the target", "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "done", "_timestamp": 2, "_context": _ctx()},
		]
		t = _make_task(e, content_only_llm(), seed_user=None, run_prompt="now exploit SSH")
		_drive(t, "_maybe_resume_remote")
		self.assertEqual(_user_turns(t.history), ["scan the target", "now exploit SSH"])
		self.assertEqual([p.content for p in _prompt_docs(t)], ["now exploit SSH"])

	# Scenario 3: steer mid-flight -> consumed once -> reboot -> present once, not re-served.
	def test_steer_consumed_once_across_reboot(self):
		e = ChannelEngine(answers=[])
		e.insert({"_type": "ai", "ai_type": "steer", "content": "focus on the API",
				  "status": "pending", "_timestamp": 2, "_uuid": "st1", "_context": _ctx()})
		backend = RemoteBackend(timeout=1, query_engine=e, poll_interval=0.001)
		self.assertEqual(backend.poll_steers(SID), ["focus on the API"])   # drained live
		self.assertEqual(backend.poll_steers(SID), [])                     # consumed
		from secator.ai.session import restore_history_from_db
		hist = restore_history_from_db(SID, e)
		self.assertEqual(sum("focus on the API" in m for m in _user_turns(hist)), 1)

	# Scenario 4: the channel re-answers EVERY follow_up with the same standing message
	# -> the loop is now BOUNDED (terminates) instead of running to the deadline.
	def test_runaway_standing_answer_loop_terminates(self):
		with patch("secator.tasks.ai._MAX_FOLLOWUP_EXTENSIONS", 6):
			e = ChannelEngine(answers=["identifier,asset_type,instruction"], standing=True)
			t = _make_task(e, content_only_llm(), seed_user="initial prompt")
			_drive(t, "_run_loop")   # returns => it terminated, did not spin forever
		csv = [p for p in _prompt_docs(t) if p.content == "identifier,asset_type,instruction"]
		self.assertGreaterEqual(len(csv), 6)
		self.assertLessEqual(len(csv), 8 + 6 + 1)   # bounded ~ initial_cap + ceiling

	# Scenario 5: two/three concurrent respawns -> no duplicate prompt docs pile up.
	def test_concurrent_respawns_no_duplicate_prompts(self):
		e = ChannelEngine(answers=[])
		e.docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace overview",
			 "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "scanning", "_timestamp": 2, "_context": _ctx()},
		]
		for _ in range(3):
			t = _make_task(e, content_only_llm(), seed_user=None, run_prompt="check workspace overview")
			# Only exercise the resume re-append decision (no loop needed here).
			t._run_loop = lambda: iter(())
			_drive(t, "_maybe_resume_remote")
		n = len([d for d in e.docs if d.get("ai_type") == "prompt" and d.get("content") == "check workspace overview"])
		self.assertEqual(n, 1)

	# Scenario 6: a genuinely long legit back-and-forth (many DISTINCT real answers)
	# must NOT be falsely capped by the ceiling.
	def test_long_legit_backandforth_not_capped(self):
		answers = [f"do step {i}" for i in range(30)]
		e = ChannelEngine(answers=answers)          # 30 distinct answers, then parks
		t = _make_task(e, content_only_llm(), seed_user="initial prompt")
		_drive(t, "_run_loop")
		served = [p.content for p in _prompt_docs(t)]
		# Every distinct answer was applied exactly once, in order — none dropped/capped
		# (30 << default ceiling 200).
		self.assertEqual(served, answers)


if __name__ == "__main__":
	unittest.main()

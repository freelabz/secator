"""Deterministic simulation of AI chat-message REPEAT on stopped/timed-out resume.

Reproduces (no network / no real LLM) the canary transcript symptom (workspace
bb_21_arcbbc, session 30c1e268): on resume the initial prompt is re-appended and
a prior user message (a follow-up answer / a pasted-CSV steer) is re-served as a
brand-new `prompt` — NOT one broker message redelivered, but DISTINCT task
invocations each rebuilding history and re-emitting the same user turn.

Harness: a stateful in-memory FakeQueryEngine with the Mongo semantics the resume
path relies on (dotted-path equality + `$in` + `$set`), driving the REAL
`restore_history_from_db`, `RemoteBackend` polling, and `ai._maybe_resume_remote`.

Scenario -> result matrix (asserted below):
  1. follow_up timed out, resumes w/ answered prompt  -> REPEAT (answer x2)   [bug]
  2. new input is a steer (mid-flight)                -> consumed once        [ok]
  3. steer while active, then resume                  -> consumed once        [ok]
  4. 2-3 concurrent respawns                          -> REPEAT (Nx prompt)   [bug]
  5. answer #1 re-served to a later follow_up         -> REPEAT (CSV x2)      [bug]
  6. resume, NO new user input                        -> REPEAT (prompt x2)   [bug]
Scenarios 1/4/5/6 reproduced the repeat pre-fix; with the RC1 guard
(`_prompt_already_tail`) + the RC2 extension ceiling applied, all pass.
"""
import copy
import unittest
import uuid
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.session import restore_history_from_db
	from secator.ai.interactivity import RemoteBackend
	from secator.output_types import Ai as AiOut
	from secator.ai.history import ChatHistory
	from secator.tasks.ai import ai as AiTask

SID = "sess-30c1e268"


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


class FakeQueryEngine:
	"""In-memory stand-in for the workspace Mongo QueryEngine (records + serves
	`_type:"ai"` docs the RemoteBackend + restore query/insert/update)."""

	def __init__(self, docs=None, backend_name="mongodb"):
		self.docs = [copy.deepcopy(d) for d in (docs or [])]
		self.backend = type("B", (), {"name": backend_name})()

	def search(self, query, limit=None):
		out = [d for d in self.docs if _match(d, query)]
		return copy.deepcopy(out[:limit] if limit else out)

	def update(self, query, update):
		n = 0
		for d in self.docs:
			if _match(d, query):
				d.update(update.get('$set', {}))
				n += 1
		return n

	def insert(self, doc):
		self.docs.append(copy.deepcopy(doc))


def _make_resume_task(engine, prompt, celery_id="celery-1"):
	"""Minimal real `ai` task exposing exactly what `_maybe_resume_remote` reads.

	Only the LLM/mode/isolation collaborators are stubbed; the resume logic,
	`_resolve_prompt`, `restore_history_from_db` and `_emit_user_prompt` are REAL."""
	t = object.__new__(AiTask)
	t.interactive = "remote"
	t.session_id = SID
	t.session_name = "sess"
	t.model = "test-model"
	t.encryptor = None
	t.mode = "chat"
	t.is_subagent = False
	t.run_opts = {"prompt": prompt}
	t.context = {"session_id": SID, "celery_id": celery_id}
	t.history = ChatHistory(model="test-model")
	t.prompt = None
	t.debug = lambda *a, **k: None
	t.persisted = []
	t.add_result = lambda item, **k: t.persisted.append(item)
	t._get_query_engine = lambda: engine
	t._detect_mode = lambda *a, **k: None
	t._system_prompt_for = lambda mode: "SYS"
	t._run_loop = lambda: iter(())
	t._teardown_isolation = lambda: None
	return t


def _user_turns(history):
	return [m['content'] for m in history.messages if m.get('role') == 'user']


def _resume(engine, prompt, celery_id="c1"):
	"""Drive the real resume path; return (task, emitted_prompt_docs)."""
	t = _make_resume_task(engine, prompt, celery_id)
	yielded = list(t._maybe_resume_remote())
	prompt_docs = [y for y in yielded if getattr(y, "ai_type", None) == "prompt"]
	return t, prompt_docs


def _persist_emitted(engine, prompt_docs, start_ts):
	"""Simulate the on_item hook persisting an emitted `prompt` Ai back to Mongo."""
	for i, p in enumerate(prompt_docs):
		engine.insert({
			"_type": "ai", "ai_type": "prompt", "content": p.content,
			"_timestamp": start_ts + i, "_context": _ctx(),
			"message": {"role": "user", "content": p.content},
		})


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestAiResumeRepeat(unittest.TestCase):

	# --- Scenario 1: follow_up timed out, resume with the answered prompt ---
	def test_s1_answered_followup_not_double_injected(self):
		docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "Scan the target", "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "Which host?", "_timestamp": 2, "_context": _ctx()},
			{"_type": "ai", "ai_type": "follow_up", "content": "Which host?", "status": "answered",
			 "answer": "scanme.nmap.org", "_timestamp": 3,
			 "extra_data": {"prompt_uuid": "u1"}, "_context": _ctx()},
		]
		# The API respawns the task carrying the just-given answer as run_opts["prompt"].
		t, prompt_docs = _resume(FakeQueryEngine(docs), "scanme.nmap.org")
		# restore already threads the answered follow_up as the tail user turn, so the
		# answer must appear EXACTLY once — not re-appended by the resume prompt.
		self.assertEqual(_user_turns(t.history), ["Scan the target", "scanme.nmap.org"])
		self.assertEqual([p.content for p in prompt_docs], [])

	# --- Scenario 2: new user input is a mid-flight steer (consumed once) ---
	def test_s2_steer_consumed_exactly_once(self):
		eng = FakeQueryEngine([
			{"_type": "ai", "ai_type": "steer", "content": "focus on the API",
			 "status": "pending", "_timestamp": 3, "_uuid": "st1", "_context": _ctx()},
		])
		backend = RemoteBackend(timeout=1, query_engine=eng, poll_interval=0.001)
		self.assertEqual(backend.poll_steers(SID), ["focus on the API"])
		self.assertEqual(backend.poll_steers(SID), [])  # already consumed

	# --- Scenario 3: steer submitted while active, then run ends + resume ---
	def test_s3_active_steer_consumed_then_restored_once(self):
		eng = FakeQueryEngine([
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace", "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "steer", "content": "CSV_SCOPE",
			 "status": "pending", "_timestamp": 2, "_uuid": "st1", "_context": _ctx()},
		])
		backend = RemoteBackend(timeout=1, query_engine=eng, poll_interval=0.001)
		backend.poll_steers(SID)  # active run drains it -> consumed
		# Resume: history rebuilt fresh; the consumed steer appears once (as a real turn),
		# and is NOT re-served as a new pending prompt.
		hist = restore_history_from_db(SID, eng)
		interjections = [m for m in _user_turns(hist) if "CSV_SCOPE" in m]
		self.assertEqual(len(interjections), 1)
		# steer stays consumed (not flipped back to pending by resume)
		self.assertEqual(backend.poll_steers(SID), [])

	# --- Scenario 4: two/three concurrent respawns of the same session ---
	def test_s4_concurrent_respawns_no_prompt_pileup(self):
		eng = FakeQueryEngine([
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace overview",
			 "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "scanning now", "_timestamp": 2, "_context": _ctx()},
		])
		for n in range(3):
			_, prompt_docs = _resume(eng, "check workspace overview", celery_id=f"c{n}")
			_persist_emitted(eng, prompt_docs, start_ts=100 + 10 * n)
		prompt_count = len([d for d in eng.docs
			if d.get("ai_type") == "prompt" and d.get("content") == "check workspace overview"])
		# Exactly the ONE original prompt doc — no per-respawn duplicate pileup.
		self.assertEqual(prompt_count, 1)

	# --- Scenario 5: answer #1 must not be re-served to a later follow_up ---
	def test_s5_prior_answer_not_reserved(self):
		csv = "identifier,asset_type,instruction,eligible_for_bounty"
		docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace", "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "next step?", "_timestamp": 2, "_context": _ctx()},
			# follow_up #1 answered with the CSV, already persisted as its own prompt turn
			{"_type": "ai", "ai_type": "follow_up", "content": "next?", "status": "answered",
			 "answer": csv, "_timestamp": 3, "extra_data": {"prompt_uuid": "u1"}, "_context": _ctx()},
			{"_type": "ai", "ai_type": "prompt", "content": csv, "_timestamp": 4, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "ran recon", "_timestamp": 5, "_context": _ctx()},
		]
		# API re-serves the SAME CSV as the respawn prompt (the observed loop).
		t, prompt_docs = _resume(FakeQueryEngine(docs), csv)
		csv_turns = [m for m in _user_turns(t.history) if m == csv]
		self.assertEqual(len(csv_turns), 1)          # served exactly once
		self.assertEqual([p.content for p in prompt_docs], [])

	# --- Scenario 6: resume when prior docs exist but NO new user input ---
	def test_s6_no_new_input_does_not_reappend_initial_prompt(self):
		docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace overview",
			 "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "scanning now", "_timestamp": 2, "_context": _ctx()},
		]
		# API respawns still carrying the initial prompt (no genuinely-new message).
		t, prompt_docs = _resume(FakeQueryEngine(docs), "check workspace overview")
		self.assertEqual(_user_turns(t.history), ["check workspace overview"])
		self.assertEqual([p.content for p in prompt_docs], [])

	# --- Guard: a genuinely NEW prompt must still be emitted (no over-suppression) ---
	def test_new_prompt_still_emitted(self):
		docs = [
			{"_type": "ai", "ai_type": "prompt", "content": "check workspace overview",
			 "_timestamp": 1, "_context": _ctx()},
			{"_type": "ai", "ai_type": "response", "content": "done", "_timestamp": 2, "_context": _ctx()},
		]
		t, prompt_docs = _resume(FakeQueryEngine(docs), "now exploit the SSH host")
		self.assertEqual(_user_turns(t.history), ["check workspace overview", "now exploit the SSH host"])
		self.assertEqual([p.content for p in prompt_docs], ["now exploit the SSH host"])


# =============================================================================
# ROOT CAUSE #2: the WITHIN-RUN loop (all docs under ONE celery_id).
#
# Evidence: under a single celery_id the run emitted ~15 follow_ups + ~15 `prompt`
# docs whose content is the pasted scope CSV. Those token-bearing `prompt` docs
# (extra_data keys tokens|context_window|by_role) are written by
# `_prompt_and_redetect` (secator/tasks/ai.py) as content=<the answer ask_user
# returned> — i.e. REAL user-message turns, not telemetry. So ask_user returned
# the CSV ~15 times in one run.
#
# These tests drive the REAL `_run_loop` with a scripted content-only LLM and a
# FakeQueryEngine that models the api's answer channel:
#   - "first": answer the standing CSV ONCE  -> secator serves it exactly once,
#     the next follow_up times out, loop exits. PROVES secator does NOT re-serve a
#     prior answer (prompt_uuid scoping in `_poll_for_answer` is correct).
#   - "every": the api re-answers each new pending follow_up with the same CSV
#     (because the model keeps asking "what's next?" and the CSV was never an
#     actionable answer) -> the loop runs unbounded: each answer does
#     `self.max_iterations += extra_iters` in `_prompt_and_redetect`, cancelling
#     `iteration += 1`, so the `while iteration < max_iterations` cap NEVER bites.
# => within-run repeat = (external re-answer, in secator-api/UI) x (secator has no
#    effective iteration cap / no same-answer loop-breaker). NOT the RC1 re-append.
# =============================================================================

if HAS_AI:
	from secator.ai.history import ChatHistory
	from secator.tasks.ai import ai as AiTask

CSV = "identifier,asset_type,instruction,eligible_for_bounty"


class _ApiAnswerEngine(FakeQueryEngine):
	"""FakeQueryEngine that also models secator-api's answer channel: just before
	the worker polls for an answer, flip the latest pending follow_up to
	answered=CSV. ``answer_cap`` bounds how many times (so the test terminates)."""

	def __init__(self, answer_cap):
		super().__init__(backend_name="mongodb")
		self.answer_cap = answer_cap
		self.answered = 0

	def _api_answer(self):
		if self.answered >= self.answer_cap:
			return
		pend = [d for d in self.docs if d.get("ai_type") == "follow_up" and d.get("status") == "pending"]
		if not pend:
			return
		pend.sort(key=lambda d: d.get("_timestamp", 0))
		pend[-1]["status"] = "answered"
		pend[-1]["answer"] = CSV
		self.answered += 1

	def search(self, query, limit=None):
		if query.get("status") == "answered" and query.get("ai_type") == "follow_up":
			self._api_answer()
		return super().search(query, limit)


def _drive_content_only_loop(engine, initial_cap=8):
	"""Drive the REAL ai._run_loop with a content-only LLM (every turn triggers
	`_prompt_and_redetect`). Returns (task, all_emitted_items)."""
	t = object.__new__(AiTask)
	t.inputs = []
	t.model = "gpt-4o"
	t.intent_model = "gpt-4o"
	t.api_key = t.api_base = None
	t.encryptor = None
	t.dry_run = t.verbose = False
	t.temp = 0.0
	t.context = {"session_id": SID, "celery_id": "27a13627"}
	t.scope = None
	t.max_workers = 1
	t.is_subagent = False
	t._sync = True
	t.interactive = "remote"
	t.session_id = SID
	t.permission_engine = None
	t.in_scope = t.out_of_scope = None
	t.isolated = False
	t.max_iterations = initial_cap
	t.max_tokens_total = 100000
	t.mode = "chat"
	t.history = ChatHistory(model="gpt-4o")
	t.history.set_system("SYS")
	t.history.add_user("initial prompt")
	t.history.count_tokens_by_role = lambda model: {"total": 50, "system": 10, "user": 20, "assistant": 20, "tool": 0}
	t.tool_schemas = []
	t.debug = lambda *a, **k: None
	t.backend = RemoteBackend(timeout=0.03, query_engine=engine, poll_interval=0.005)
	emitted = []

	def add_result(item, **k):
		emitted.append(item)
		if isinstance(item, AiOut):
			engine.insert({
				"_type": "ai", "ai_type": item.ai_type, "content": item.content,
				"status": getattr(item, "status", None), "_timestamp": len(engine.docs) + 1,
				"_uuid": str(uuid.uuid4()), "extra_data": item.extra_data or {},
				"_context": {"session_id": SID},
			})
	t.add_result = add_result
	# Stub the heavy/irrelevant collaborators; the loop, _prompt_and_redetect and
	# RemoteBackend polling run REAL.
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

	def fake_call_llm(messages, model, temp, api_base, api_key, tools=None):
		return {"content": "Here is my analysis. What next?", "tool_calls": [],
				"usage": {"tokens": 50, "cost": 0.0}, "finish_reason": "stop"}

	import secator.ai.actions as _act
	with patch("secator.tasks.ai.call_llm", fake_call_llm), \
			patch("secator.tasks.ai.init_llm", lambda **k: None), \
			patch.object(_act.ActionContext, "get_query_engine", lambda self: engine), \
			patch("secator.tasks.ai.get_context_window", lambda m: 128000), \
			patch("secator.tasks.ai.format_llm_status", lambda *a, **k: ""):
		emitted.extend(list(t._run_loop()))
	return t, emitted


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestWithinRunLoop(unittest.TestCase):

	def _csv_prompts(self, emitted):
		return [p for p in emitted if isinstance(p, AiOut) and p.ai_type == "prompt" and p.content == CSV]

	# secator serves a standing answer EXACTLY ONCE, then the next follow_up times
	# out -> the within-run repeat is NOT secator re-serving a prior answer.
	def test_secator_serves_answer_once_then_exits(self):
		engine = _ApiAnswerEngine(answer_cap=1)
		t, emitted = _drive_content_only_loop(engine, initial_cap=8)
		self.assertEqual(len(self._csv_prompts(emitted)), 1)

	# RC2 FIX: when the answer channel re-answers EVERY follow_up with the same CSV,
	# the loop is now BOUNDED — auto-extensions are capped, so it TERMINATES instead
	# of spinning to the worker deadline. (answer_cap huge so only the ceiling stops it.)
	def test_followup_loop_now_bounded_by_extension_ceiling(self):
		with patch("secator.tasks.ai._MAX_FOLLOWUP_EXTENSIONS", 5):
			engine = _ApiAnswerEngine(answer_cap=10_000)
			t, emitted = _drive_content_only_loop(engine, initial_cap=8)
		n = len(self._csv_prompts(emitted))
		# The run TERMINATED (this test returning proves it didn't spin forever) and the
		# CSV was served a bounded number of times ~ initial_cap + ceiling, not unbounded.
		self.assertGreaterEqual(n, 5)
		self.assertLessEqual(n, 8 + 5 + 1)


if __name__ == "__main__":
	unittest.main()

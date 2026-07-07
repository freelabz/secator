"""Interactivity backends for AI task user interaction: all prompting flows
through backend.ask_user() so callers never branch on interactive mode."""
import time

from time import sleep
from typing import Any, Dict, List, Optional

from secator.ai.tools import STOP_TOOL_SCHEMA


class InteractivityBackend:
	"""Base class for AI interactivity backends."""

	def ask_user(self, question: str, choices: List[str], session_id: str,
				 prompt_type: str = "follow_up", **context) -> Optional[Dict]:
		"""Ask the user a question; returns {"answer": str} (+ optional "extra_iters"/
		"switch_mode" for follow_up), or None on exit/timeout/deny."""
		raise NotImplementedError

	def get_excluded_tools(self) -> set:
		"""Return tool names to exclude from the LLM's available tools."""
		return set()

	def get_extra_tools(self) -> list:
		"""Return additional tool schemas (not in TOOL_SCHEMAS) to inject."""
		return []


class CLIBackend(InteractivityBackend):
	"""Local terminal interactive backend."""

	def get_excluded_tools(self) -> set:
		return {"stop"}

	def ask_user(self, question, choices, session_id, prompt_type="follow_up", **context):
		if prompt_type == "permission":
			return self._handle_permission(**context)
		return self._handle_follow_up(choices, **context)

	def _handle_permission(self, **context):
		"""Delegate permission prompts to the PermissionEngine's rich menus."""
		engine = context.get("engine")
		ptype = context.get("permission_type")
		value = context.get("value", "")
		if not engine:
			return None

		if ptype == "shell":
			decision = engine.prompt_shell(value, reason=context.get("reason", ""))
			return {"answer": decision}
		elif ptype == "target":
			decision = engine.prompt_target(value, command=context.get("command", ""))
			return {"answer": decision}
		elif ptype in ("read", "write"):
			decision = engine.prompt_path(value, access_type=ptype, command=context.get("command", ""))
			return {"answer": decision}
		return None

	def _handle_follow_up(self, choices, **context):
		"""Delegate follow-up prompts to the rich interactive menu."""
		from secator.ai.utils import prompt_user
		history = context.get("history")
		if not history:
			return None
		return prompt_user(
			history,
			encryptor=context.get("encryptor"),
			max_iterations=context.get("max_iterations", 10),
			choices=choices,
			mode=context.get("mode", "chat"),
			model=context.get("model"),
		)


class RemoteBackend(InteractivityBackend):
	"""Remote DB-polling interactive backend."""

	def __init__(self, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
		self.timeout = timeout
		self.query_engine = query_engine
		self.poll_interval = poll_interval

	def get_excluded_tools(self) -> set:
		return {"stop"}

	def build_pending_prompt(self, question, choices, session_id, prompt_type="follow_up", **context):
		"""Build a pending Ai finding for the caller to yield (persists it before
		ask_user() polls for the answer). ``prompt_uuid`` is stamped into
		``extra_data`` so the poll matches THIS prompt, not a stale one (H7)."""
		from secator.output_types import Ai
		extra_data = {
			"permission_type": context.get("permission_type", ""),
			"value": context.get("value", ""),
		}
		prompt_uuid = context.get("prompt_uuid")
		if prompt_uuid:
			extra_data["prompt_uuid"] = prompt_uuid
		# A new prompt for this session supersedes any older still-pending one
		# (e.g. a worker that died mid-poll). Expire them BEFORE this doc is
		# persisted so only the current prompt stays live (M10).
		self._expire_stale_pending(session_id)
		# The conversation id rides on `_context.session_id` (auto-stamped from the
		# runner context on persist) — the poll + restore + secator-api all key on
		# that, so this pending doc needs no top-level session_id field.
		return Ai(
			content=question,
			ai_type=prompt_type,
			status="pending",
			choices=choices,
			extra_data=extra_data,
			_timestamp=time.time(),
		)

	def ask_user(self, question, choices, session_id, prompt_type="follow_up", **context):
		answer = self._poll_for_answer(session_id, prompt_type, prompt_uuid=context.get("prompt_uuid"))
		if answer is None:
			return None

		if prompt_type == "permission":
			engine = context.get("engine")
			if answer in ("allow", "allow_all"):
				# M12: allow_all persists a session-scoped allow rule; single allow is
				# a true one-shot that adds NO rule (H9) — next match re-prompts.
				if answer == "allow_all" and engine:
					ptype = context.get("permission_type")
					value = context.get("value", "")
					self._add_permission_rules(engine, ptype, value)
				return {"answer": "allow"}
			return {"answer": "deny"}

		# follow_up: return the answer text
		return {"answer": answer}

	def poll_steers(self, session_id):
		"""Drain pending steer docs for ``session_id`` and mark them consumed.

		A "steer" is a mid-flight user message written to the channel while the
		agent runs; the worker picks it up at the next checkpoint to redirect --
		distinct from a blocking follow-up ``answer`` or a hard Stop. Returns
		content strings oldest-first, flipping each doc to ``consumed`` so it's
		injected exactly once; any backend error returns ``[]`` (a steer must
		never crash the run).
		"""
		if self.query_engine is None:
			return []
		base = {
			"_type": "ai",
			"ai_type": "steer",
			# Correlate by the runner context's session_id, auto-stamped on every
			# persisted item (item._context = self.context) — see _poll_for_answer.
			"_context.session_id": session_id,
			"status": "pending",
		}
		try:
			results = self.query_engine.search(base, limit=50)
		except Exception:  # noqa: BLE001 - a steer must never crash the run
			return []
		if not results:
			return []
		# Oldest-first so multiple queued steers are injected in send order.
		results = sorted(results, key=lambda r: r.get("_timestamp", 0))
		contents = []
		for doc in results:
			content = doc.get("content") or doc.get("answer") or ""
			if content:
				contents.append(content)
		# Mark this session's pending steers consumed so they inject exactly once.
		try:
			self.query_engine.update(
				{**base},
				{"$set": {"status": "consumed"}},
			)
		except Exception:  # noqa: BLE001 - consume failure must not crash the run
			pass
		return contents

	def _poll_for_answer(self, session_id, prompt_type, prompt_uuid=None):
		"""Poll the DB for the answer to THIS specific prompt until timeout.

		Scoped by ``prompt_uuid`` (not just session_id+status:"answered"): an
		unscoped query would match a stale previously-answered doc from an earlier
		turn, causing an infinite re-injection/respawn loop that re-runs scans and
		burns tokens. A pending steer for this session breaks the wait early and is
		returned as the answer, so the loop redirects immediately instead of stalling.
		"""
		base = {
			"_type": "ai",
			"ai_type": prompt_type,
			# session_id is auto-stamped on every persisted item (item._context)
			"_context.session_id": session_id,
		}
		if prompt_uuid:
			base["extra_data.prompt_uuid"] = prompt_uuid

		answered_query = {**base, "status": "answered"}
		elapsed = 0
		while elapsed < self.timeout:
			answer = self._resolve_answer(answered_query)
			if answer is not None:
				return answer
			# A steer breaks the wait: treat the steer as the user's answer so the
			# blocked follow-up resolves and the next turn redirects.
			steers = self.poll_steers(session_id)
			if steers:
				return "\n".join(steers)
			sleep(self.poll_interval)
			elapsed += self.poll_interval
		# One final search before giving up: the user may have answered during
		# the last sleep (or between the last search and now). Without this the
		# answer is silently stranded (M10).
		answer = self._resolve_answer(answered_query)
		if answer is not None:
			return answer
		# Timeout: atomically flip ONLY a doc that is STILL pending, so a concurrent
		# older pending doc isn't disturbed. If the answer landed in the race window
		# the doc is already 'answered' and this no-ops -- re-read rather than abandon it (M10).
		modified = self.query_engine.update(
			{**base, "status": "pending"},
			{"$set": {"status": "timed_out"}}
		)
		if not modified:
			answer = self._resolve_answer(answered_query)
			if answer is not None:
				return answer
		return None

	def _resolve_answer(self, answered_query):
		"""Return the newest answered doc's answer (by ``_timestamp``, a backstop
		against stale answers), or None if none answered."""
		results = self.query_engine.search(answered_query)
		if not results:
			return None
		newest = max(results, key=lambda r: r.get("_timestamp", 0))
		return newest.get("answer")

	def _expire_stale_pending(self, session_id):
		"""Mark any older still-pending prompt for this session as timed_out.

		Called before a new prompt persists, so stale 'pending' docs (e.g. from a
		worker that died mid-poll) don't strand the UI or collide with
		crud.answer_ai_prompt's "latest pending" (M10). FLAG: a DB-layer TTL index
		on pending Ai docs is the durable follow-up.
		"""
		if not self.query_engine:
			return
		self.query_engine.update(
			{
				"_type": "ai",
				"_context.session_id": session_id,
				"status": "pending",
			},
			{"$set": {"status": "timed_out"}},
		)

	@staticmethod
	def _add_permission_rules(engine, ptype, value):
		"""Add runtime allow rules after a remote permission approval."""
		from secator.ai.guardrails import _extract_cmd_names
		if ptype == "shell":
			cmd_names = _extract_cmd_names(value)
			if cmd_names:
				engine.add_runtime_allow([f"shell({','.join(cmd_names)})"])
			else:
				first_word = value.split()[0] if value.split() else value
				engine.add_runtime_allow([f"shell({first_word})"])
		elif ptype == "target":
			engine.add_runtime_allow([f"target({value})"])
		elif ptype in ("read", "write"):
			engine.add_runtime_allow([f"{ptype}({value})"])


class AutoBackend(InteractivityBackend):
	"""Non-interactive autonomous backend."""

	def get_excluded_tools(self) -> set:
		return {"follow_up"}

	def get_extra_tools(self) -> list:
		return [STOP_TOOL_SCHEMA]

	def ask_user(self, question, choices, session_id, prompt_type="follow_up", **context):
		return None


def create_backend(mode: str, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
	"""Factory function to create the appropriate backend."""
	if mode == "local":
		return CLIBackend()
	elif mode == "remote":
		return RemoteBackend(timeout=timeout, query_engine=query_engine, poll_interval=poll_interval)
	else:
		return AutoBackend()

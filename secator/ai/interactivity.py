"""Interactivity backends for AI task user interaction.

All user prompting (permission requests and follow-up questions) flows through
backend.ask_user().  Callers never branch on interactive mode — the backend
handles the UX differences.
"""
import time

from time import sleep
from typing import Any, Dict, List, Optional

from secator.ai.tools import STOP_TOOL_SCHEMA


class InteractivityBackend:
	"""Base class for AI interactivity backends."""

	def ask_user(self, question: str, choices: List[str], session_id: str,
				 prompt_type: str = "follow_up", **context) -> Optional[Dict]:
		"""Ask the user a question.

		Args:
			question: The question to ask.
			choices: List of choice strings.
			session_id: Session ID for correlating request/response.
			prompt_type: "follow_up" or "permission".
			**context: Backend-specific context (engine, history, etc.).

		Returns:
			dict with at least {"answer": str}, or None (exit/timeout/deny).
			For follow_up: may also include "extra_iters" and "switch_mode".
		"""
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
		"""Build a pending Ai finding for the remote user to see and answer.

		The caller must yield this item so it gets stored in the workspace
		(via runner hooks) before calling ask_user(), which will poll for the answer.
		"""
		from secator.output_types import Ai
		return Ai(
			content=question,
			ai_type=prompt_type,
			status="pending",
			choices=choices,
			session_id=session_id,
			extra_data={
				"permission_type": context.get("permission_type", ""),
				"value": context.get("value", ""),
			},
			_timestamp=time.time(),
		)

	def ask_user(self, question, choices, session_id, prompt_type="follow_up", **context):
		answer = self._poll_for_answer(session_id, prompt_type)
		if answer is None:
			return None

		if prompt_type == "permission":
			engine = context.get("engine")
			if answer in ("allow", "allow_all") and engine:
				ptype = context.get("permission_type")
				value = context.get("value", "")
				self._add_permission_rules(engine, ptype, value)
				return {"answer": "allow"}
			return {"answer": "deny"}

		# follow_up: return the answer text
		return {"answer": answer}

	def _poll_for_answer(self, session_id, prompt_type):
		"""Poll DB for user answer until timeout."""
		elapsed = 0
		while elapsed < self.timeout:
			results = self.query_engine.search({
				"_type": "ai",
				"ai_type": prompt_type,
				"session_id": session_id,
				"status": "answered"
			}, limit=1)
			if results:
				return results[0].get("answer")
			sleep(self.poll_interval)
			elapsed += self.poll_interval
		# Timeout: update finding status
		self.query_engine.update(
			{"_type": "ai", "ai_type": prompt_type, "session_id": session_id, "status": "pending"},
			{"$set": {"status": "timed_out"}}
		)
		return None

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

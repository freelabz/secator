"""Interactivity backends for AI task user interaction."""
from time import sleep
from typing import Any, List, Optional

from secator.ai.tools import STOP_TOOL_SCHEMA


class InteractivityBackend:
	"""Base class for AI interactivity backends."""

	def ask_user(self, question: str, choices: List[str], session_id: str) -> Optional[str]:
		"""Ask the user a question. Returns answer string or None (timeout/exit)."""
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

	def ask_user(self, question: str, choices: List[str], session_id: str) -> Optional[str]:
		"""Delegates to prompt_user() — called by main loop via _prompt_and_redetect."""
		raise NotImplementedError("CLIBackend.ask_user should not be called directly")


class RemoteBackend(InteractivityBackend):
	"""Remote DB-polling interactive backend."""

	def __init__(self, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
		self.timeout = timeout
		self.query_engine = query_engine
		self.poll_interval = poll_interval

	def get_excluded_tools(self) -> set:
		return {"stop"}

	def ask_user(self, question: str, choices: List[str], session_id: str) -> Optional[str]:
		"""Poll DB for user answer until timeout."""
		elapsed = 0
		while elapsed < self.timeout:
			results = self.query_engine.search({
				"_type": "ai",
				"ai_type": "follow_up",
				"session_id": session_id,
				"status": "answered"
			}, limit=1)
			if results:
				return results[0].get("answer")
			sleep(self.poll_interval)
			elapsed += self.poll_interval
		# Timeout: update finding status
		self.query_engine.update(
			{"_type": "ai", "ai_type": "follow_up", "session_id": session_id, "status": "pending"},
			{"$set": {"status": "timed_out"}}
		)
		return None


class AutoBackend(InteractivityBackend):
	"""Non-interactive autonomous backend."""

	def get_excluded_tools(self) -> set:
		return {"follow_up"}

	def get_extra_tools(self) -> list:
		return [STOP_TOOL_SCHEMA]

	def ask_user(self, question: str, choices: List[str], session_id: str) -> Optional[str]:
		"""Never called — no follow_up tool available."""
		raise NotImplementedError("AutoBackend has no user to ask")


def create_backend(mode: str, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
	"""Factory function to create the appropriate backend."""
	if mode == "local":
		return CLIBackend()
	elif mode == "remote":
		return RemoteBackend(timeout=timeout, query_engine=query_engine, poll_interval=poll_interval)
	else:
		return AutoBackend()

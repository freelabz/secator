# secator/ai/history.py
"""Chat history management for AI task - litellm format."""
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import litellm


SUMMARIZATION_PROMPT = """Summarize the following attack session history into a compact context.
Keep ONLY the essential information:
- Key findings (vulnerabilities, open ports, services, credentials)
- Action history (tasks, workflows, shell commands, queries)
- Important tool outputs (IPs, URLs, domains, versions discovered)
- Current attack progress and next steps
- Errors that affected the attack path

Discard verbose tool outputs, redundant information, and raw data dumps.
Keep the summary under {max_words} words. Use markdown formatting.

## History to summarize:

{history}

## Summary:"""


@dataclass
class ChatHistory:
	"""Manages chat history in litellm message format.

	This is a thin wrapper around a list of message dicts that can be
	passed directly to litellm.completion().

	Attributes:
		messages: List of message dicts with 'role' and 'content' keys
	"""

	messages: List[Dict[str, str]] = field(default_factory=list)
	model: Optional[str] = None

	def add_system(self, content: str) -> None:
		self.messages.append({"role": "system", "content": content})

	def set_system(self, content: str) -> None:
		"""Replace the first system message, or insert one at the start."""
		for msg in self.messages:
			if msg["role"] == "system":
				msg["content"] = content
				return
		self.messages.insert(0, {"role": "system", "content": content})

	def add_user(self, content: str) -> None:
		self.messages.append({"role": "user", "content": content})

	def add_assistant(self, content: str) -> None:
		self.messages.append({"role": "assistant", "content": content})

	def add_tool(self, content: str) -> None:
		self.messages.append({"role": "tool", "content": content})

	def to_messages(self, max_tokens_total: int = 0) -> List[Dict[str, str]]:
		"""Return a copy of the messages list, trimming if over max_tokens_total.

		Uses litellm's trim_messages which preserves system messages and recent
		context while removing oldest messages first.

		Args:
			max_tokens_total: Hard token limit. If > 0, trim messages to fit.
		"""
		if max_tokens_total > 0:
			return self.trim(max_tokens_total)
		return self.messages.copy()

	def trim(self, max_tokens: int) -> List[Dict[str, str]]:
		"""Trim messages to fit under max_tokens using litellm's trim_messages.

		Preserves system messages and recent context, removing oldest messages first.
		Also attempts to shorten individual messages before dropping them entirely.

		Args:
			max_tokens: Maximum token limit for the messages.

		Returns:
			Trimmed list of messages.
		"""
		from litellm.utils import trim_messages
		from secator.rich import console
		from secator.output_types import Warning

		original_count = len(self.messages)
		trimmed = trim_messages(self.messages, max_tokens=max_tokens)
		dropped = original_count - len(trimmed)

		if dropped:
			console.print(Warning(
				message=f'Chat history trimmed: dropped {dropped} messages to fit under {max_tokens} tokens.'
			))

		# Update internal state with trimmed messages
		self.messages = trimmed
		return trimmed

	def clear(self) -> None:
		self.messages = []

	def est_tokens(self) -> int:
		"""Estimate token count (1 token ~ 4 chars)."""
		return sum(len(m.get("content", "")) for m in self.messages) // 4

	def count_tokens(self, model: str = None) -> int:
		"""Count tokens using litellm, with per-message caching.

		Args:
			model: LLM model name (required if self.model not set)

		Returns:
			Total token count across all messages

		Raises:
			ValueError: If no model provided and self.model not set
		"""
		model = model or self.model
		if not model:
			raise ValueError("Model required for token counting")
		total = 0
		for msg in self.messages:
			cached = msg.get("_token_count")
			cached_model = msg.get("_token_model")
			if cached is not None and cached_model == model:
				total += cached
			else:
				tokens = litellm.token_counter(model=model, messages=[msg])
				msg["_token_count"] = tokens
				msg["_token_model"] = model
				total += tokens
		return total

	def maybe_summarize(self, model: str, api_base: Optional[str] = None, api_key: Optional[str] = None,
						threshold: int = 30000) -> Tuple[bool, int, int]:
		"""Summarize history if estimated token count exceeds threshold.

		Args:
			model: LLM model name
			api_base: Optional API base URL
			api_key: Optional API key
			threshold: Token threshold to trigger compaction

		Returns:
			tuple: (compacted, old_tokens, new_tokens)
		"""
		old_tokens = self.est_tokens()
		if old_tokens <= threshold:
			return False, old_tokens, old_tokens

		self._summarize_with_llm(model, api_base, api_key, threshold)
		new_tokens = self.est_tokens()
		return True, old_tokens, new_tokens

	def _summarize_with_llm(self, model: str, api_base: Optional[str] = None, api_key: Optional[str] = None,
							threshold: int = 30000) -> None:
		"""Summarize non-system messages using an LLM, keeping the initial system prompt intact."""
		if len(self.messages) <= 2:
			return

		# Preserve system prompt and first user message, summarize the rest
		system_msgs = [m for m in self.messages if m["role"] == "system"]
		non_system_msgs = [m for m in self.messages if m["role"] != "system"]
		initial_system = system_msgs[0] if system_msgs else None
		first_user = non_system_msgs[0] if non_system_msgs else None
		rest = non_system_msgs[1:] if len(non_system_msgs) > 1 else []

		if not rest:
			return

		# Import here to avoid circular import
		from secator.ai.utils import call_llm
		from secator.rich import console

		# Account for preserved messages in budget
		preserved_tokens = sum(
			len(m["content"]) // 4 for m in [initial_system, first_user] if m
		)
		remaining_budget = threshold - preserved_tokens
		max_words = (remaining_budget * 60 // 100) // 2  # rough tokens-to-words ratio

		history_text = json.dumps(rest, indent=None)
		prompt = SUMMARIZATION_PROMPT.format(history=history_text, max_words=max_words)
		from secator.utils import format_token_count
		token_str = format_token_count(self.est_tokens(), icon='arrow_up')
		with console.status(f"[bold orange3]Compacting chat history...[/] [gray42] • {token_str}[/]", spinner="dots"):
			result = call_llm([{"role": "user", "content": prompt}], model, 0.3, api_base, api_key)

		self.messages = []
		if initial_system:
			self.messages.append(initial_system)
		if first_user:
			self.messages.append(first_user)
		self.messages.append({"role": "user", "content": f"Summary of previous iterations:\n\n{result['content']}"})

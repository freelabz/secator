# secator/ai/history.py
"""Chat history management for AI task - litellm format."""
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import litellm


OUTPUT_TOKEN_RESERVATION = 8192  # Reserve for LLM response
COMPACTION_THRESHOLD_PCT = 85    # Trigger compaction at 85% of usable context
MAX_ACTION_TOKENS = 10_000       # Hard cap per action result


def get_context_window(model: str) -> int:
    """Get model's context window size from litellm.

    Args:
        model: LLM model name

    Returns:
        Context window size in tokens (default 128000 on error)
    """
    try:
        info = litellm.get_model_info(model)
        return info.get("max_input_tokens") or info.get("max_tokens", 128_000)
    except Exception:
        return 128_000  # Safe default


def truncate_to_tokens(
    content: str,
    max_tokens: int,
    model: str,
    fallback_path: Path = None,
    output_dir: Path = None,
    result_name: str = "result"
) -> str:
    """Truncate content to fit within token budget, with file fallback.

    Args:
        content: Content to truncate
        max_tokens: Maximum tokens allowed
        model: LLM model name for token counting
        fallback_path: Existing file to reference (task/workflow report.json)
        output_dir: Directory to save shell output (creates file)
        result_name: Prefix for saved filename

    Returns:
        Original content if under budget, or truncated with [TRUNCATED] marker
    """
    current = litellm.token_counter(model=model, text=content)
    if current <= max_tokens:
        return content

    # Determine file hint
    if fallback_path and fallback_path.exists():
        file_hint = f"\nFull output: {fallback_path}"
    elif output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fallback_path = output_dir / f"{result_name}_{timestamp}.txt"
        fallback_path.write_text(content)
        file_hint = f"\nFull output saved to: {fallback_path}"
    else:
        file_hint = ""

    file_hint += "\nUse shell commands to explore: grep, head, tail, jq"

    # Truncate content (ratio-based with 10% safety margin)
    ratio = max_tokens / current
    truncate_at = int(len(content) * ratio * 0.9)
    return content[:truncate_at] + f"\n\n[TRUNCATED]{file_hint}"


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
		"""Replace the first system message, or insert one at the start.

		Invalidates any cached token count for the system message.
		"""
		for msg in self.messages:
			if msg["role"] == "system":
				msg["content"] = content
				msg.pop("_token_count", None)  # Invalidate cache
				msg.pop("_token_model", None)
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

	def get_available_tokens(self, model: str) -> int:
		"""Return tokens available for new content.

		Args:
			model: LLM model name

		Returns:
			Available tokens (context - reservation - used)
		"""
		context_window = get_context_window(model)
		usable = context_window - OUTPUT_TOKEN_RESERVATION
		return usable - self.count_tokens(model)

	def should_compact(self, model: str, threshold_pct: int = COMPACTION_THRESHOLD_PCT) -> bool:
		"""Check if compaction needed based on % of context used.

		Args:
			model: LLM model name
			threshold_pct: Percentage threshold (default 85)

		Returns:
			True if compaction needed
		"""
		context_window = get_context_window(model)
		usable = context_window - OUTPUT_TOKEN_RESERVATION
		used = self.count_tokens(model)
		return used > (usable * threshold_pct / 100)

	def maybe_summarize(self, model: str, api_base: Optional[str] = None,
						api_key: Optional[str] = None) -> Tuple[bool, int, int]:
		"""Summarize history if token usage exceeds percentage threshold.

		Uses should_compact() to determine if compaction is needed based on
		percentage of usable context (default 85%).

		Args:
			model: LLM model name
			api_base: Optional API base URL
			api_key: Optional API key

		Returns:
			tuple: (compacted, old_tokens, new_tokens)
		"""
		old_tokens = self.count_tokens(model)
		if not self.should_compact(model):
			return False, old_tokens, old_tokens

		self._summarize_with_llm(model, api_base, api_key)
		new_tokens = self.count_tokens(model)
		return True, old_tokens, new_tokens

	def _summarize_with_llm(self, model: str, api_base: Optional[str] = None,
							api_key: Optional[str] = None) -> None:
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

		from secator.ai.utils import call_llm
		from secator.rich import console
		from secator.utils import format_token_count

		# Calculate target summary size based on available context
		context_window = get_context_window(model)
		usable = context_window - OUTPUT_TOKEN_RESERVATION
		target_tokens = int(usable * 0.3)  # Target 30% of usable context
		max_words = target_tokens // 2  # Rough tokens-to-words ratio

		history_text = json.dumps(rest, indent=None)
		prompt = SUMMARIZATION_PROMPT.format(history=history_text, max_words=max_words)
		token_str = format_token_count(self.count_tokens(model), icon='arrow_up')
		with console.status(f"[bold orange3]Compacting chat history...[/] [gray42] • {token_str}[/]", spinner="dots"):
			result = call_llm([{"role": "user", "content": prompt}], model, 0.3, api_base, api_key)

		self.messages = []
		if initial_system:
			self.messages.append(initial_system)
		if first_user:
			self.messages.append(first_user)
		self.messages.append({"role": "user", "content": f"Summary of previous iterations:\n\n{result['content']}"})

	def get_action_budget(self, model: str) -> int:
		"""Get max tokens allowed for a single action's combined output.

		Returns the smaller of:
		- MAX_ACTION_TOKENS (10k hard cap)
		- 50% of available context

		Args:
			model: LLM model name

		Returns:
			Token budget for action result
		"""
		available = self.get_available_tokens(model)
		return min(MAX_ACTION_TOKENS, available // 2)

# secator/ai/utils.py
"""Utility functions for AI task - LLM initialization, calling, and response parsing."""
import json
import logging
import re
from typing import Dict, List, Optional

from secator.config import CONFIG
from secator.rich import console

logger = logging.getLogger(__name__)

# Module-level state for litellm initialization
_llm_initialized = False
_llm_handler = None


def init_llm():
	"""Initialize litellm once (singleton pattern to avoid callback accumulation)."""
	global _llm_initialized, _llm_handler

	if _llm_initialized:
		return

	import litellm
	from litellm.integrations.custom_logger import CustomLogger

	# Suppress litellm's own debug logs unless 'litellm.debug' is explicitly set
	if "litellm.debug" not in CONFIG.debug:
		litellm.suppress_debug_info = True
		litellm.set_verbose = False
		litellm.json_logs = True
		logging.getLogger("LiteLLM").setLevel(logging.WARNING)
		logging.getLogger("litellm").setLevel(logging.WARNING)
		logging.getLogger("httpx").setLevel(logging.WARNING)

	class LLMCallbackHandler(CustomLogger):
		"""Custom handler for logging LLM calls."""
		_last_message_count = 0

		def log_pre_api_call(self, model, messages, kwargs):
			if "litellm" not in CONFIG.debug:
				return
			from rich.markdown import Markdown
			from rich.panel import Panel
			from rich.text import Text
			MAX_LEN = 2000
			role_styles = {"system": "blue", "user": "green", "assistant": "red"}
			message_count = len(messages)
			new_start = self._last_message_count
			self._last_message_count = message_count
			if new_start > 0:
				console.print(f"[dim]... {new_start} previous message(s) hidden ...[/]")
			for count, msg in enumerate(messages, 1):
				if count <= new_start:
					continue
				role = msg.get("role", "unknown").upper()
				content = msg.get("content", "").strip()
				style = role_styles.get(msg.get("role", ""), "white")
				if len(content) > MAX_LEN:
					content = content[:MAX_LEN] + f"\n\n... ({len(content) - MAX_LEN} chars truncated)"
				# Use Markdown for assistant responses, Text for everything else
				renderable = Markdown(content) if msg.get("role") == "assistant" else Text(content)
				console.print(Panel(
					renderable,
					title=f"[bold {style}]{role}[/] [dim]({count}/{message_count})[/]",
					border_style=style
				))

	_llm_handler = LLMCallbackHandler()
	litellm.callbacks = [_llm_handler]
	_llm_initialized = True


def call_llm(
	messages: List[Dict],
	model: str,
	temperature: float = 0.7,
	api_base: Optional[str] = None,
) -> Dict:
	"""Call litellm completion and return response with usage."""
	import litellm

	# Initialize litellm once (avoids callback accumulation)
	init_llm()

	response = litellm.completion(
		model=model,
		messages=messages,
		temperature=temperature,
		api_base=api_base,
	)

	content = response.choices[0].message.content
	usage = None

	if hasattr(response, 'usage') and response.usage:
		try:
			cost = litellm.completion_cost(completion_response=response)
		except Exception:
			cost = None

		usage = {
			"tokens": response.usage.total_tokens,
			"cost": cost,
		}

	return {"content": content, "usage": usage}


def parse_actions(response: str) -> List[Dict]:
	"""Extract JSON action array from LLM response."""
	# Try code block first (```json ... ```)
	match = re.search(r'```(?:json)?\s*(\[[\s\S]*?\])\s*```', response)
	if match:
		try:
			return json.loads(match.group(1))
		except json.JSONDecodeError:
			pass

	# Try raw JSON array with "action" key
	match = re.search(r'\[[\s\S]*?"action"[\s\S]*?\]', response)
	if match:
		try:
			# Find matching brackets
			text = response[match.start():]
			depth = 0
			end = 0
			for i, c in enumerate(text):
				if c == '[':
					depth += 1
				elif c == ']':
					depth -= 1
					if depth == 0:
						end = i + 1
						break
			return json.loads(text[:end])
		except json.JSONDecodeError:
			pass

	# Try single JSON object with "action" key
	match = re.search(r'\{[\s\S]*?"action"[\s\S]*?\}', response)
	if match:
		try:
			text = response[match.start():]
			depth = 0
			end = 0
			for i, c in enumerate(text):
				if c == '{':
					depth += 1
				elif c == '}':
					depth -= 1
					if depth == 0:
						end = i + 1
						break
			obj = json.loads(text[:end])
			if isinstance(obj, dict):
				return [obj]
		except json.JSONDecodeError:
			pass

	return []


def strip_json_from_response(text: str) -> str:
	"""Remove JSON action blocks, keep only text/reasoning."""
	if not text:
		return ""

	# Remove code blocks
	text = re.sub(r'```(?:json)?\s*\[[\s\S]*?\]\s*```', '', text)

	# Remove raw JSON arrays that contain "action"
	result = []
	i = 0
	while i < len(text):
		if text[i] == '[':
			# Find matching bracket first
			depth = 0
			end = i
			for j in range(i, len(text)):
				if text[j] == '[':
					depth += 1
				elif text[j] == ']':
					depth -= 1
					if depth == 0:
						end = j + 1
						break

			# Extract the bracketed content
			bracketed = text[i:end]

			# Only skip if it looks like a JSON action array
			if '"action"' in bracketed and bracketed.startswith('[{'):
				i = end
			else:
				result.append(text[i])
				i += 1
		else:
			result.append(text[i])
			i += 1

	return ''.join(result).strip()


def prompt_user(history, encryptor=None, mode="chat"):
	"""Prompt user for follow-up input.

	Returns:
		tuple: (action, value) where action is 'continue', 'follow_up', or 'summarize'.
		None: to exit.
	"""
	from secator.rich import InteractiveMenu

	try:
		other_mode = "chat" if mode == "attack" else "attack"
		switch_label = f"Switch to {other_mode} mode"
		if mode == "attack":
			options = [
				{"label": "Continue attacking", "description": "Continue for N more iterations"},
				{"label": "Summarize", "description": "Get a summary of findings so far"},
				{"label": "Show raw", "description": "Print last response as copyable text"},
				{"label": switch_label, "description": "Change mode with a new prompt", "input": True},
				{"label": "Something else", "description": "Send custom instructions", "input": True},
				{"label": "Exit"},
			]
			result = InteractiveMenu("What's next?", options).show()
			if result is None:
				return None
			idx, value = result
			if idx == 0:  # Continue attacking
				from rich.prompt import IntPrompt
				n = IntPrompt.ask("[bold cyan]Number of iterations[/]", default=5)
				return ("continue", n)
			if idx == 1:  # Summarize
				return ("summarize", None)
			if idx == 2:  # Show raw
				return ("show_raw", None)
			if idx == 3:  # Switch mode
				return ("switch_mode", value)
			if idx == 4:  # Something else
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
			if idx == 5:  # Exit
				return None
		else:
			options = [
				{"label": "Show raw", "description": "Print last response as copyable text"},
				{"label": switch_label, "description": "Change mode with a new prompt", "input": True},
				{"label": "Something else", "description": "Send custom instructions", "input": True},
				{"label": "Exit"},
			]
			result = InteractiveMenu("What's next?", options).show()
			if result is None:
				return None
			idx, value = result
			if idx == 0:  # Show raw
				return ("show_raw", None)
			if idx == 1:  # Switch mode
				return ("switch_mode", value)
			if idx == 2:  # Something else
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
			if idx == 3:  # Exit
				return None
	except (KeyboardInterrupt, EOFError):
		return None

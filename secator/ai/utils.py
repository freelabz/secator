# secator/ai/utils.py
"""Utility functions for AI task - LLM initialization, calling, and response parsing."""
import json
import logging
import re
from typing import Dict, List, Optional

from secator.config import CONFIG
from secator.output_types import Warning
from secator.rich import console

# Module-level state for litellm initialization
_llm_initialized = False


def _find_matching_bracket(text: str, start: int, open_char: str, close_char: str) -> int:
	"""Find position after the matching closing bracket, starting from `start`."""
	depth = 0
	for i in range(start, len(text)):
		if text[i] == open_char:
			depth += 1
		elif text[i] == close_char:
			depth -= 1
			if depth == 0:
				return i + 1
	return start


def init_llm(api_key: Optional[str] = None):
	"""Initialize litellm once (singleton pattern to avoid callback accumulation)."""
	global _llm_initialized

	import litellm

	# Set API key if provided (can be called multiple times)
	if api_key:
		litellm.api_key = api_key

	if _llm_initialized:
		return

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

	litellm.callbacks = [LLMCallbackHandler()]
	_llm_initialized = True


def call_llm(
	messages: List[Dict],
	model: str,
	temperature: float = 0.7,
	api_base: Optional[str] = None,
	api_key: Optional[str] = None,
	max_retries: int = 3,
) -> Dict:
	"""Call litellm completion and return response with usage."""
	import time
	import litellm

	# Initialize litellm once (avoids callback accumulation)
	init_llm(api_key=api_key)

	retryable = (
		litellm.InternalServerError, litellm.RateLimitError,
		litellm.ServiceUnavailableError, litellm.APIConnectionError,
	)
	for attempt in range(1, max_retries + 1):
		try:
			response = litellm.completion(
				model=model,
				messages=messages,
				temperature=temperature,
				api_base=api_base,
			)
			break
		except retryable as e:
			if attempt < max_retries:
				wait = 2 ** attempt
				console.print(Warning(
					message=f"LLM call failed (attempt {attempt}/{max_retries}): {e}. Retrying in {wait}s..."))
				time.sleep(wait)
			else:
				raise

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


def _is_action_list(obj) -> bool:
	"""Check if parsed JSON is a list of action dicts."""
	return isinstance(obj, list) and all(isinstance(a, dict) and "action" in a for a in obj)


def parse_actions(response: str) -> List[Dict]:
	"""Extract JSON action array from LLM response."""
	# Try code block first (```json ... ```)
	match = re.search(r'```(?:json)?\s*(\[[\s\S]*?\])\s*```', response)
	if match:
		try:
			result = json.loads(match.group(1))
			if _is_action_list(result):
				return result
		except json.JSONDecodeError:
			pass

	# Try raw JSON array with "action" key
	match = re.search(r'\[[\s\S]*?"action"[\s\S]*?\]', response)
	if match:
		try:
			text = response[match.start():]
			end = _find_matching_bracket(text, 0, '[', ']')
			result = json.loads(text[:end])
			if _is_action_list(result):
				return result
		except json.JSONDecodeError:
			pass

	# Try collecting individual JSON objects with "action" key
	actions = []
	for match in re.finditer(r'\{"action"', response):
		try:
			text = response[match.start():]
			end = _find_matching_bracket(text, 0, '{', '}')
			obj = json.loads(text[:end])
			if isinstance(obj, dict) and "action" in obj:
				actions.append(obj)
		except json.JSONDecodeError:
			pass
	if actions:
		return actions

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
			end = _find_matching_bracket(text, i, '[', ']')

			# Extract the bracketed content
			bracketed = text[i:end]

			# Only skip if it looks like a JSON action array
			if '"action"' in bracketed and re.match(r'^\[\s*\{', bracketed):
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
	from secator.definitions import IN_WORKER
	if IN_WORKER:
		return ("exit", None)
	from secator.rich import InteractiveMenu

	try:
		other_mode = "chat" if mode == "attack" else "attack"
		switch_label = f"Switch to {other_mode} mode"
		if mode == "attack":
			options = [
				{"label": "Continue attacking", "description": "Continue for N more iterations", "action": "continue"},
				{"label": "Summarize", "description": "Get a summary of findings so far", "action": "summarize"},
				{"label": "Show raw", "description": "Print last response as copyable text", "action": "show_raw"},
				{"label": switch_label, "description": "Change mode with a new prompt", "input": True, "action": "switch_mode"},
				{"label": "Something else", "description": "Send custom instructions", "input": True, "action": "follow_up"},
				{"label": "Exit", "action": "exit"},
			]
			result = InteractiveMenu("What's next?", options).show()
			if result is None:
				return None
			idx, value = result
			action = options[idx].get("action")
			if action == "continue":
				from rich.prompt import IntPrompt
				n = IntPrompt.ask("[bold cyan]Number of iterations[/]", default=5)
				return ("continue", n)
			if action == "summarize":
				return ("summarize", None)
			if action == "show_raw":
				return ("show_raw", None)
			if action == "switch_mode":
				return ("switch_mode", value)
			if action == "follow_up":
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
			if action == "exit":
				return None
		else:
			options = [
				{"label": "Show raw", "description": "Print last response as copyable text", "action": "show_raw"},
				{"label": switch_label, "description": "Change mode with a new prompt", "input": True, "action": "switch_mode"},
				{"label": "Something else", "description": "Send custom instructions", "input": True, "action": "follow_up"},
				{"label": "Exit", "action": "exit"},
			]
			result = InteractiveMenu("What's next?", options).show()
			if result is None:
				return None
			idx, value = result
			action = options[idx].get("action")
			if action == "show_raw":
				return ("show_raw", None)
			if action == "switch_mode":
				return ("switch_mode", value)
			if action == "follow_up":
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
			if action == "exit":
				return None
	except (KeyboardInterrupt, EOFError):
		return None

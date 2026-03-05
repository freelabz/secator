# secator/ai/utils.py
"""Utility functions for AI task - LLM initialization, calling, and response parsing."""
import json
import logging
import re
from typing import Dict, List, Optional

from secator.config import CONFIG
from secator.output_types import Warning, Error
from secator.rich import console, maybe_status

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
			new_start = self._last_message_count - 1
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
		except litellm.AuthenticationError as e:
			console.print(Error(message=e))
			console.print(Error(
				message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`'
			))
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


MODEL_COLORS = [
	'cyan', 'green', 'yellow', 'magenta', 'red', 'blue',
	'bright_cyan', 'bright_green', 'bright_yellow', 'bright_magenta',
	'bright_red', 'bright_blue', 'orange3', 'deep_pink2', 'dark_olive_green3',
	'medium_purple3', 'dodger_blue2', 'gold3', 'spring_green3', 'hot_pink',
]


def setup_ai():
	"""Interactive search-filter-select flow for configuring AI model and API key."""
	import litellm
	from rich.prompt import Prompt

	# Load all models, sort, build color map
	all_models = sorted(litellm.model_list)
	all_parts = set()
	for m in all_models:
		parts = m.split('/')
		for p in parts[:-1]:
			all_parts.add(p)
	part_colors = {p: MODEL_COLORS[i % len(MODEL_COLORS)] for i, p in enumerate(sorted(all_parts))}

	def _format_model(m, idx=None):
		parts = m.split('/')
		if len(parts) > 1:
			segments = [f"[bold {part_colors[p]}]{p}[/]" for p in parts[:-1]]
			colored = '/'.join(segments) + f"/[bold white]{parts[-1]}[/]"
		else:
			colored = f"[bold white]{m}[/]"
		prefix = f"[dim]{idx:>4}[/] " if idx is not None else "  "
		return prefix + colored

	# Show current config
	current_model = CONFIG.addons.ai.default_model
	current_intent = CONFIG.addons.ai.intent_model
	current_key = CONFIG.addons.ai.api_key
	masked_key = f"{current_key[:8]}...{current_key[-4:]}" if current_key and len(current_key) > 12 else current_key or ""
	console.print()
	console.print("[bold]  Current config:[/]")
	console.print(f"    Model:        [bold white]{current_model or 'not set'}[/]")
	console.print(f"    Intent model: [bold white]{current_intent or 'not set'}[/]")
	console.print(f"    API key:      [bold white]{masked_key or 'not set'}[/]")
	console.print()

	# Display all models numbered
	displayed = all_models
	suffix = ''
	console.print(f"[bold]  Found {len(displayed)} models{suffix}:[/]")
	for i, m in enumerate(displayed, 1):
		console.print(_format_model(m, idx=i), highlight=False)

	# Enter prompt loop
	while True:
		console.print()
		choice = Prompt.ask("[bold cyan]  Filter or select (number/name, q to quit)[/]")

		if not choice:
			# Empty input: re-show current list
			console.print(f"\n[bold]  Found {len(displayed)} models{suffix}:[/]")
			for i, m in enumerate(displayed, 1):
				console.print(_format_model(m, idx=i), highlight=False)
			continue

		if choice.lower() in ('q', 'quit', 'exit'):
			return None

		# Number → select from current display
		if choice.isdigit():
			idx = int(choice)
			if 1 <= idx <= len(displayed):
				selected = displayed[idx - 1]
			else:
				console.print(f"[bold red]  Invalid number: {idx} (valid: 1-{len(displayed)})[/]")
				continue
		else:
			# Check exact match first
			exact = [m for m in all_models if m.lower() == choice.lower()]
			if exact:
				selected = exact[0]
			else:
				# Text → filter models, re-display
				query_lower = choice.lower()
				filtered = [m for m in all_models if query_lower in m.lower()]
				if not filtered:
					console.print(f'[bold yellow]  No models matching "{choice}".[/]')
					continue
				if len(filtered) == 1:
					selected = filtered[0]
				else:
					displayed = filtered
					suffix = f' matching "{choice}"'
					console.print(f"\n[bold]  Found {len(displayed)} models{suffix}:[/]")
					for i, m in enumerate(displayed, 1):
						console.print(_format_model(m, idx=i), highlight=False)
					continue

		# Model selected - save config
		console.print(f"\n[bold green]  Selected: [white]{selected}[/][/]")
		CONFIG.set('addons.ai.default_model', selected)
		CONFIG.set('addons.ai.intent_model', selected)

		# Prompt for API key if model changed or key unset
		api_key = Prompt.ask(
			"  [bold cyan]API key[/] [dim](leave empty to keep current)[/]",
			default=masked_key,
			show_default=bool(masked_key),
		)
		if api_key and api_key != masked_key:
			CONFIG.set('addons.ai.api_key', api_key)

		config = CONFIG.validate()
		if config:
			CONFIG.save()
			console.print(f"[bold green]  Default model set to [white]{selected}[/][/]")
			console.print(f"[bold green]  Intent model set to [white]{selected}[/][/]")
		else:
			console.print(f"[bold yellow]  Model selected: {selected} (config validation failed, not saved)[/]")

		# Verify with a simple LLM call
		api_key = CONFIG.addons.ai.api_key
		api_base = CONFIG.addons.ai.api_base
		console.print()
		try:
			with maybe_status("[bold orange3]Verifying model connection...[/]", spinner="dots"):
				result = call_llm(
					[{"role": "user", "content": "Reply with only: OK"}],
					selected, temperature=0, api_base=api_base, api_key=api_key,
				)
			console.print(f"[bold green]  Connection verified! Response: {result['content'].strip()}[/]")
		except Exception as e:
			console.print(f"[bold red]  Connection failed: {e}[/]")
			console.print("[dim]  Check your API key and model name.[/]")

		return selected


def prompt_user(history, encryptor=None, max_iterations=10, choices=None, mode="chat"):
	"""Prompt user for follow-up input via interactive menu.

	Builds a unified menu with optional LLM-provided choices, plus Continue,
	Summarize, and Exit. Mutates history in-place before returning.

	Args:
		history: ChatHistory instance to mutate with user's choice.
		encryptor: Optional SensitiveDataEncryptor for encrypting user input.
		max_iterations: Current max iterations (used for continue message).
		choices: Optional list of choice strings from LLM follow_up action.

	Returns:
		tuple: (action, extra_iters) where action is 'continue', 'summarize',
			or 'follow_up', and extra_iters is iterations to add.
		None: to exit.
	"""
	from secator.definitions import IN_WORKER
	if IN_WORKER:
		return None
	from secator.rich import InteractiveMenu
	from secator.ai.prompts import format_continue
	from secator.ai.prompts import get_system_prompt

	try:
		options = []

		# Insert LLM-provided choices first
		if choices:
			for choice in choices:
				options.append({
					"label": choice,
					"description": "",
					"input": True,
					"action": "follow_up",
				})

			# Add "All of the above" when 2+ choices
			if len(choices) >= 2:
				options.append({
					"label": "All of the above",
					"description": "Run all suggested actions",
					"input": True,
					"action": "all_choices",
				})

		# Default options (always present)
		continue_label = f"Continue to {mode}"
		options.extend([
			{
				"label": continue_label, "description": "Continue with optional instructions",
				"input": True, "action": "continue",
			},
			{
				"label": "Summarize", "description": "Get a summary of findings",
				"input": True, "action": "summarize", "default": "Summarize all findings so far",
			},
			{"label": "Exit", "action": "exit"},
		])

		result = InteractiveMenu("What's next?", options).show()
		if result is None:
			return None

		idx, value = result
		action = options[idx].get("action")

		if action == "continue":
			if value:
				user_msg = _maybe_encrypt(value, encryptor)
				history.add_user(user_msg)
			else:
				continue_msg = format_continue(0, max_iterations)
				history.add_user(_maybe_encrypt(continue_msg, encryptor))
			return (value or continue_label, max_iterations)

		if action == "summarize":
			history.set_system(get_system_prompt("chat"))
			summary_msg = "Summarize all findings so far and provide a final report."
			if value:
				summary_msg += f" {value}"
			history.add_user(_maybe_encrypt(summary_msg, encryptor))
			return (summary_msg, 1)

		if action == "follow_up":
			choice_label = options[idx].get("label", "")
			msg = choice_label
			if value:
				msg = f"{choice_label}: {value}"
			history.add_user(_maybe_encrypt(msg, encryptor))
			return (msg, 1)

		if action == "all_choices":
			numbered = [f"{i}) {c}" for i, c in enumerate(choices, 1)]
			msg = f"Do all of the following: {', '.join(numbered)}"
			if value:
				msg += f". Additional instructions: {value}"
			history.add_user(_maybe_encrypt(msg, encryptor))
			return (msg, max_iterations)

		# exit
		return None
	except (KeyboardInterrupt, EOFError):
		return None


def _maybe_encrypt(text, encryptor):
	"""Encrypt text if encryptor is available, otherwise return as-is."""
	return encryptor.encrypt(text) if encryptor else text

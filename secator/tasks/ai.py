# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import json
import logging
import re
from typing import Dict, Generator, List, Optional

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Ai, Stat, Progress, Error, Info, Warning, State, Vulnerability, FINDING_TYPES, OutputType
from secator.runners import PythonRunner
from secator.rich import console
from secator.utils import format_object
from secator.tasks.ai_actions import ActionContext, dispatch_action
from secator.tasks.ai_encryption import SensitiveDataEncryptor
from secator.tasks.ai_history import ChatHistory
from secator.tasks.ai_prompts import (
	get_system_prompt, format_user_initial, format_tool_result, format_continue)

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


def _interactive_menu(options, title="Select an option"):
	"""Display an interactive menu with arrow-key navigation and inline typing.

	Args:
		options: List of dicts with keys:
			- label: Display text
			- description: Optional dim description below the label
			- input: If True, this option accepts typed input (shown inline)
		title: Menu title

	Returns:
		tuple: (index, value) where value is typed text for input options, or None.
		None: if user pressed Escape or Ctrl+C.
	"""
	import sys
	import tty
	import termios
	from io import StringIO

	fd = sys.stdin.fileno()
	old_settings = termios.tcgetattr(fd)
	selected = 0
	typed = ""
	in_input_mode = False

	def _read_key():
		"""Read a single keypress, handling escape sequences."""
		ch = sys.stdin.read(1)
		if ch == '\x1b':
			ch2 = sys.stdin.read(1)
			if ch2 == '[':
				ch3 = sys.stdin.read(1)
				if ch3 == 'A':
					return 'up'
				elif ch3 == 'B':
					return 'down'
			return 'escape'
		elif ch == '\r' or ch == '\n':
			return 'enter'
		elif ch == '\x03':
			return 'ctrl_c'
		elif ch == '\x04':
			return 'ctrl_d'
		elif ch == '\x7f' or ch == '\x08':
			return 'backspace'
		else:
			return ch

	def _render():
		"""Render the menu to a string using Rich."""
		from rich.console import Console as RichConsole
		buf = StringIO()
		render_console = RichConsole(file=buf, force_terminal=True, width=console.width)
		w = console.width
		render_console.print(f"[dim]{'─' * w}[/]")
		render_console.print(f"[bold]{title}[/]\n")
		for i, opt in enumerate(options):
			is_selected = i == selected
			prefix = "[bold cyan]❯[/]" if is_selected else " "
			num = f"[bold]{i + 1}.[/]"
			if opt.get("input"):
				if is_selected and in_input_mode:
					label = f"{prefix} {num} [bold]{typed}[/][dim]▎[/]"
				elif is_selected:
					label = f"{prefix} {num} [bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} [dim]{opt['label']}[/]"
			else:
				if is_selected:
					label = f"{prefix} {num} [bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} [dim]{opt['label']}[/]"
			render_console.print(label)
			if opt.get("description") and not (opt.get("input") and in_input_mode):
				render_console.print(f"     [gray35]{opt['description']}[/]")
		render_console.print(f"\n[dim]{'─' * w}[/]")
		return buf.getvalue()

	# Count total lines for clearing
	def _line_count(text):
		return text.count('\n')

	output = ""
	try:
		tty.setraw(fd)
		# Initial render
		output = _render().replace('\n', '\r\n')
		sys.stderr.write(output)
		sys.stderr.flush()

		while True:
			key = _read_key()
			prev_output = output

			if key == 'ctrl_c' or key == 'escape':
				# Clear menu
				lines = _line_count(prev_output)
				sys.stderr.write(f"\033[{lines}A\033[J")
				sys.stderr.flush()
				return None

			elif key == 'up' and not in_input_mode:
				selected = (selected - 1) % len(options)

			elif key == 'down' and not in_input_mode:
				selected = (selected + 1) % len(options)

			elif key == 'enter':
				opt = options[selected]
				if opt.get("input") and not in_input_mode:
					in_input_mode = True
					typed = ""
				elif opt.get("input") and in_input_mode:
					lines = _line_count(prev_output)
					sys.stderr.write(f"\033[{lines}A\033[J")
					sys.stderr.flush()
					if typed.strip():
						return (selected, typed.strip())
					return None
				else:
					lines = _line_count(prev_output)
					sys.stderr.write(f"\033[{lines}A\033[J")
					sys.stderr.flush()
					return (selected, None)

			elif key == 'backspace' and in_input_mode:
				typed = typed[:-1]

			elif in_input_mode and len(key) == 1 and key.isprintable():
				typed += key

			elif not in_input_mode and key.isdigit():
				idx = int(key) - 1
				if 0 <= idx < len(options):
					selected = idx

			# Re-render
			lines = _line_count(prev_output)
			sys.stderr.write(f"\033[{lines}A\033[J")
			output = _render().replace('\n', '\r\n')
			sys.stderr.write(output)
			sys.stderr.flush()

	except (KeyboardInterrupt, EOFError):
		lines = _line_count(output) if output else 0
		if lines:
			sys.stderr.write(f"\033[{lines}A\033[J")
			sys.stderr.flush()
		return None
	finally:
		termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def _prompt_user(history, encryptor=None, mode="chat"):
	"""Prompt user for follow-up input.

	Returns:
		tuple: (action, value) where action is 'continue', 'follow_up', or 'summarize'.
		None: to exit.
	"""
	try:
		if mode == "attack":
			options = [
				{"label": "Continue attacking", "description": "Continue for N more iterations"},
				{"label": "Summarize", "description": "Get a summary of findings so far"},
				{"label": "Something else", "description": "Send custom instructions", "input": True},
				{"label": "Exit"},
			]
			result = _interactive_menu(options, title="What's next?")
			if result is None:
				return None
			idx, value = result
			if idx == 0:  # Continue attacking
				from rich.prompt import IntPrompt
				n = IntPrompt.ask("[bold cyan]Number of iterations[/]", default=5)
				return ("continue", n)
			if idx == 1:  # Summarize
				return ("summarize", None)
			if idx == 2:  # Something else
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
			if idx == 3:  # Exit
				return None
		else:
			options = [
				{"label": "Exit"},
				{"label": "Something else", "description": "Send custom instructions", "input": True},
			]
			result = _interactive_menu(options, title="What's next?")
			if result is None:
				return None
			idx, value = result
			if idx == 0:  # Exit
				return None
			if idx == 1:  # Something else
				user_msg = encryptor.encrypt(value) if encryptor else value
				history.add_user(user_msg)
				return ("follow_up", value)
	except (KeyboardInterrupt, EOFError):
		return None


@task()
class ai(PythonRunner):
	"""AI-powered penetration testing assistant (attack or chat mode)."""
	output_types = FINDING_TYPES
	tags = ["ai", "analysis", "pentest"]
	install_cmd = "pip install litellm"
	default_inputs = ''
	opts = {
		"prompt": {"type": str, "default": "", "short": "p", "help": "Prompt"},
		"mode": {"type": str, "default": "", "help": "Mode: attack or chat"},
		"model": {"type": str, "default": CONFIG.ai.default_model, "help": "LLM model"},
		"api_base": {"type": str, "default": CONFIG.ai.api_base, "help": "API base URL"},
		"sensitive": {"is_flag": True, "default": True, "help": "Encrypt sensitive data"},
		"max_iterations": {"type": int, "default": 10, "help": "Max iterations"},
		"temperature": {"type": float, "default": 0.7, "help": "LLM temperature"},
		"dry_run": {"is_flag": True, "default": False, "help": "Show without executing"},
		"yes": {"is_flag": True, "default": False, "short": "y", "help": "Auto-accept"},
	}

	def yielder(self) -> Generator:
		"""Execute AI task."""
		try:
			import litellm  # noqa
		except ImportError:
			yield Error(message="litellm required. Install: pip install litellm")
			return

		prompt = self.run_opts.get("prompt", "")
		mode = self.run_opts.get("mode", "") or self._detect_mode(prompt)
		model = self.run_opts.get("model")
		targets = self.inputs

		yield Info(message=f"Using model: {model}, mode: {mode}")

		# Initialize encryptor
		encryptor = None
		if self.run_opts.get("sensitive", True):
			encryptor = SensitiveDataEncryptor()

		# Run unified loop for both modes
		yield from self._run_loop(mode, prompt, targets, model, encryptor)

	def _detect_mode(self, prompt: str) -> str:
		"""Detect mode from prompt keywords."""
		keywords = ["attack", "exploit", "scan", "test", "pentest", "hack", "fuzz", "enumerate"]
		return "attack" if any(kw in prompt.lower() for kw in keywords) else "chat"

	def _run_loop(self, mode: str, prompt: str, targets: List[str], model: str,
				  encryptor: Optional[SensitiveDataEncryptor]) -> Generator:
		"""Run unified loop for both attack and chat modes."""
		max_iter = int(self.run_opts.get("max_iterations", 10))
		temp = float(self.run_opts.get("temperature", 0.7))
		api_base = self.run_opts.get("api_base")
		dry_run = self.run_opts.get("dry_run", False)
		verbose = self.run_opts.get("verbose", False)

		# Initialize chat history with appropriate system prompt
		history = ChatHistory()
		history.add_system(get_system_prompt(mode))
		user_msg = format_user_initial(targets, prompt)
		history.add_user(encryptor.encrypt(user_msg) if encryptor else user_msg)
		yield Ai(content=prompt or f"Starting {mode}...", ai_type="prompt")

		# Create action context
		ctx = ActionContext(
			targets=targets, model=model, encryptor=encryptor, dry_run=dry_run,
			auto_yes=self.run_opts.get("yes", False),
			verbose=verbose,
			workspace_id=self.context.get("workspace_id") if self.context else None)

		iteration = 0
		done = False
		while iteration < max_iter:
			iteration += 1
			yield Info(message=f"Iteration {iteration}/{max_iter}")

			try:
				# Call LLM
				result = call_llm(history.to_messages(), model, temp, api_base)
				response = result["content"]
				usage = result.get("usage", {})

				# Handle empty response
				if not response:
					yield Warning(message="LLM returned empty response")
					iteration += 1
					continue

				# Decrypt response
				if encryptor:
					response = encryptor.decrypt(response)

				# Parse actions
				actions = parse_actions(response)

				# Show response (strip JSON for display unless verbose)
				display_text = response if verbose else strip_json_from_response(response)
				if display_text:
					yield Ai(
						content=display_text,
						ai_type="response",
						mode=mode,
						model=model,
						extra_data={
							"iteration": iteration,
							"max_iterations": max_iter,
							"tokens": usage.get("tokens") if usage else None,
							"cost": usage.get("cost") if usage else None,
						},
					)

				# Add to history
				history.add_assistant(response)

				# Execute actions
				yield Info(message=f"Executing {len(actions)} actions ...")
				for action in actions:
					action_type = action.get("action", "")
					yield Info(message=f"Running action {format_object(action, 'yellow')}")
					action_results = []
					for item in dispatch_action(action, ctx):
						if isinstance(item, (Stat, Progress, State, Info)):
							continue
						if isinstance(item, OutputType):
							self.add_result(item, print=False)  # only for Secator findings
							item = item.toDict()
							item.pop('_context', None)
							item.pop('_uuid', None)
							item.pop('_related', None)
						action_results.append(item)

					# Build tool result for history (compact JSON)
					yield Info(f"Adding {len(action_results)} action results to next iteration ...")
					tool_result = format_tool_result(
						action.get("name", action_type),
						"success",
						len(action_results),
						action_results
					)
					if encryptor:
						tool_result = encryptor.encrypt(tool_result)
					history.add_user(tool_result)

					# Done action: prompt user for continuation
					if action_type == "done":
						done = True

				# Prompt user for continuation
				if done or (iteration == max_iter):
					if (iteration == max_iter):
						yield Info(message=f"Reached max iterations ({max_iter}). Following up with user.")
					elif done:
						yield Info(message=f"Following up with user.")
					result = _prompt_user(history, encryptor, mode)
					if result is None:
						return
					action, value = result
					if action == "continue":
						max_iter += value
						done = False
						continue_msg = format_continue(iteration, max_iter)
						history.add_user(encryptor.encrypt(continue_msg) if encryptor else continue_msg)
					elif action == "summarize":
						max_iter += 1
						summary_msg = "Summarize all findings so far and provide a final report."
						history.add_user(encryptor.encrypt(summary_msg) if encryptor else summary_msg)
						yield Ai(content=summary_msg, ai_type="prompt")
					elif action == "follow_up":
						max_iter += 1
						done = False
						yield Ai(content=value, ai_type="prompt")
					elif action == "exit":
						return
					continue

				# Continue action
				continue_msg = format_continue(iteration, max_iter)
				history.add_user(encryptor.encrypt(continue_msg) if encryptor else continue_msg)

			except Exception as e:
				import litellm
				if isinstance(e, litellm.RateLimitError):
					yield Warning(message="Rate limit exceeded - will retry in the next iteration")
					continue
				yield Error.from_exception(e)
				if isinstance(e, litellm.exceptions.APIError):
					yield Error(message="API error occurred. Stopping.")
					return

		yield Info(message=f"Reached max iterations ({max_iter})")

# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import json
import logging
import re
from typing import Dict, Generator, List, Optional

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Ai, Error, Info, Warning, Vulnerability, FINDING_TYPES
from secator.runners import PythonRunner
from secator.rich import console
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

	# Suppress debug output unless 'litellm' is in CONFIG.debug
	if "litellm.debug" not in CONFIG.debug:
		litellm.suppress_debug_info = True
		litellm.set_verbose = False
		litellm.json_logs = True
		logging.getLogger("LiteLLM").setLevel(logging.WARNING)
		logging.getLogger("litellm").setLevel(logging.WARNING)
		logging.getLogger("httpx").setLevel(logging.WARNING)

	class LLMCallbackHandler(CustomLogger):
		"""Custom handler for logging LLM calls."""

		def log_pre_api_call(self, model, messages, kwargs):
			if "litellm" not in CONFIG.debug:
				return
			from rich.markdown import Markdown
			from rich.panel import Panel
			MAX_LEN = 2000
			role_styles = {"system": "blue", "user": "green", "assistant": "red"}
			message_count = len(messages)
			for count, msg in enumerate(messages, 1):
				role = msg.get("role", "unknown").upper()
				content = msg.get("content", "")
				style = role_styles.get(msg.get("role", ""), "white")
				if len(content) > MAX_LEN:
					content = content[:MAX_LEN] + f"\n\n... ({len(content) - MAX_LEN} chars truncated)"
				console.print(Panel(
					Markdown(content),
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


@task()
class ai(PythonRunner):
	"""AI-powered penetration testing assistant (attack or chat mode)."""
	output_types = FINDING_TYPES + [Info, Warning, Error]
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
		"verbose": {"is_flag": True, "default": False, "short": "v", "help": "Verbose"},
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

		# Route to mode
		if mode == "attack":
			yield from self._run_attack(prompt, targets, model, encryptor)
		else:
			yield from self._run_chat(prompt, targets, model, encryptor)

	def _detect_mode(self, prompt: str) -> str:
		"""Detect mode from prompt keywords."""
		keywords = ["attack", "exploit", "scan", "test", "pentest", "hack", "fuzz", "enumerate"]
		return "attack" if any(kw in prompt.lower() for kw in keywords) else "chat"

	def _run_attack(self, prompt: str, targets: List[str], model: str,
					encryptor: Optional[SensitiveDataEncryptor]) -> Generator:
		"""Run attack loop."""
		max_iter = int(self.run_opts.get("max_iterations", 10))
		temp, api_base = float(self.run_opts.get("temperature", 0.7)), self.run_opts.get("api_base")
		dry_run, verbose = self.run_opts.get("dry_run", False), self.run_opts.get("verbose", False)

		history = ChatHistory()
		history.add_system(get_system_prompt("attack"))
		user_msg = format_user_initial(targets, prompt)
		history.add_user(encryptor.encrypt(user_msg) if encryptor else user_msg)
		yield Ai(content=prompt or "Starting attack...", ai_type="prompt")

		ctx = ActionContext(
			targets=targets, model=model, encryptor=encryptor, dry_run=dry_run,
			auto_yes=self.run_opts.get("yes", False),
			workspace_id=self.context.get("workspace_id") if self.context else None)

		for iteration in range(max_iter):
			yield Info(message=f"Iteration {iteration + 1}/{max_iter}")

			try:
				# Call LLM
				result = call_llm(history.to_messages(), model, temp, api_base)

				response = result["content"]
				usage = result.get("usage", {})

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
						mode="attack",
						model=model,
						extra_data={
							"iteration": iteration + 1,
							"tokens": usage.get("tokens") if usage else None,
							"cost": usage.get("cost") if usage else None,
						},
					)

				# Add to history
				history.add_assistant(response)

				if not actions:
					yield Warning(message="Could not parse actions")
					history.add_user("Could not parse your actions")
					continue

				# Execute actions
				for action in actions:
					action_type = action.get("action", "")
					action_results = []
					for item in dispatch_action(action, ctx):
						action_results.append(item)
						if action_type != "query":
							yield item

					# Build tool result for history (compact JSON)
					tool_result = format_tool_result(
						action.get("name", action_type),
						"success",
						len(action_results),
						action_results
					)
					if encryptor:
						tool_result = encryptor.encrypt(tool_result)
					history.add_user(tool_result)

					# Check for done
					if action_type == "done":
						return

				continue_msg = format_continue(iteration + 1, max_iter)
				history.add_user(encryptor.encrypt(continue_msg) if encryptor else continue_msg)

			except Exception as e:
				yield Error(message=f"Iteration failed: {e}")
				logger.exception("Attack iteration error")

		yield Info(message=f"Reached max iterations ({max_iter})")

	def _run_chat(self, prompt: str, targets: List[str], model: str,
				  encryptor: Optional[SensitiveDataEncryptor]) -> Generator:
		"""Run chat mode for Q&A."""
		temp, api_base = float(self.run_opts.get("temperature", 0.7)), self.run_opts.get("api_base")
		history = ChatHistory()
		history.add_system(get_system_prompt("chat"))
		user_msg = format_user_initial(targets, prompt)
		history.add_user(encryptor.encrypt(user_msg) if encryptor else user_msg)
		yield Ai(content=prompt, ai_type="prompt")

		try:
			result = call_llm(history.to_messages(), model, temp, api_base)

			response = result["content"]
			usage = result.get("usage", {})

			if encryptor:
				response = encryptor.decrypt(response)

			yield Ai(
				content=response,
				ai_type="response",
				mode="chat",
				model=model,
				extra_data={
					"tokens": usage.get("tokens") if usage else None,
					"cost": usage.get("cost") if usage else None,
				},
			)

		except Exception as e:
			yield Error(message=f"Chat failed: {e}")

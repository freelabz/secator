# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import json
import os
import random
from pathlib import Path
from typing import Generator, List, Optional

from time import sleep

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import ADDONS_ENABLED, LLM_SPINNER_MESSAGES
from secator.output_types import (
	Ai, Stat, Progress, Error, Info, Warning, State, FINDING_TYPES, OutputType, INTERNAL_FIELDS
)
from secator.runners import PythonRunner
from secator.rich import console, maybe_status
from secator.utils import format_token_count
from secator.ai.actions import ActionContext, dispatch_action
from secator.ai.encryption import SensitiveDataEncryptor
from secator.ai.history import ChatHistory
from secator.ai.prompts import get_system_prompt, format_user_initial, format_tool_result, format_continue
from secator.ai.utils import call_llm, setup_ai, parse_actions, strip_json_from_response, prompt_user


def _maybe_encrypt(text, encryptor):
	"""Encrypt text if encryptor is available, otherwise return as-is."""
	return encryptor.encrypt(text) if encryptor else text


DEFAULT_API_KEY = CONFIG.addons.ai.api_key or os.environ.get('ANTHROPIC_API_KEY', '')


@task()
class ai(PythonRunner):
	"""AI-powered penetration testing assistant (attack or chat mode)."""
	output_types = FINDING_TYPES
	tags = ["ai", "analysis", "pentest"]
	default_inputs = ''
	opts = {
		"prompt": {"type": str, "default": "", "short": "p", "help": "Prompt"},
		"mode": {"type": str, "default": "", "help": "Mode: attack or chat"},
		"model": {"type": str, "default": CONFIG.addons.ai.default_model, "help": "LLM model"},
		"api_key": {"type": str, "default": DEFAULT_API_KEY, "help": "API key for LLM provider"},
		"api_base": {"type": str, "default": CONFIG.addons.ai.api_base, "help": "API base URL"},
		"sensitive": {"is_flag": True, "default": True, "help": "Encrypt sensitive data"},
		"max_iterations": {"type": int, "default": 10, "help": "Max iterations"},
		"temperature": {"type": float, "default": 0.7, "help": "LLM temperature"},
		"dry_run": {"is_flag": True, "default": False, "help": "Show without executing"},
		"yes": {"is_flag": True, "default": False, "short": "y", "help": "Auto-accept"},
		"intent_model": {"type": str, "default": CONFIG.addons.ai.intent_model, "help": "Model for intent detection"},
		"max_tokens": {"type": int, "default": CONFIG.addons.ai.max_tokens, "help": "Max tokens before compacting history"},
		"max_tokens_total": {
			"type": int, "default": CONFIG.addons.ai.max_tokens_total,
			"help": "Hard token limit - truncate oldest messages beyond this",
		},
		"interactive": {"is_flag": True, "default": True, "help": "Prompt user for follow-up after completion"},
	}

	@classmethod
	def get_mock_context(cls, fixture):
		"""Return a context manager that mocks LLM calls with fixture data."""
		from secator.utils_test import mock_litellm_completion
		return mock_litellm_completion(fixture)

	def yielder(self) -> Generator:
		"""Execute AI task."""
		# Handle 'setup' input (before addon check so it works without full AI deps)
		if self.inputs == ['setup']:
			if not ADDONS_ENABLED['ai']:
				yield Error(message='Missing ai addon: please run "secator install addons ai".')
				return
			setup_ai()
			return

		if not ADDONS_ENABLED['ai']:
			yield Error(message='Missing ai addon: please run "secator install addons ai".')
			return

		prompt = self.run_opts.get("prompt", "")
		if prompt and Path(prompt).is_file():
			prompt = Path(prompt).read_text().strip()
		model = self.run_opts.get("model")
		intent_model = self.run_opts.get("intent_model")
		api_base = self.run_opts.get("api_base")
		api_key = self.run_opts.get("api_key")
		targets = self.inputs
		mode = self.run_opts.get("mode", "") or self._detect_mode(prompt, intent_model, api_base, api_key)

		yield Info(message=f"Using model: {model}, mode: {mode}")

		# Initialize encryptor
		encryptor = None
		if self.run_opts.get("sensitive", True):
			encryptor = SensitiveDataEncryptor()

		# Convert upstream results to JSON dicts for context
		previous_results = []
		for r in self.results:
			if not isinstance(r, tuple(FINDING_TYPES)):
				continue
			if hasattr(r, 'toDict'):
				d = r.toDict()
				for f in INTERNAL_FIELDS:
					d.pop(f, None)
				previous_results.append(d)

		# Run unified loop for both modes
		yield from self._run_loop(mode, prompt, targets, model, encryptor, previous_results)

	def _detect_mode(self, prompt: str, intent_model: str, api_base: str = None, api_key: str = None) -> str:
		"""Detect mode using a fast LLM call for intent analysis."""
		if not prompt:
			return "chat"
		try:
			messages = [{"role": "user", "content": (
				"Classify the following user prompt as either 'attack' or 'chat'.\n"
				"'attack' = the user wants to actively scan, test, exploit, enumerate, or pentest targets.\n"
				"'chat' = the user wants to ask questions, get summaries, or discuss findings.\n"
				"Respond with ONLY the single word 'attack' or 'chat'.\n\n"
				f"Prompt: {prompt}"
			)}]
			with maybe_status("[bold orange3]Detecting intent...[/]", spinner="dots"):
				result = call_llm(messages, intent_model, temperature=0.3, api_base=api_base, api_key=api_key)
			mode = result["content"].strip().lower()
			if mode in ("attack", "chat"):
				console.print(rf"[bold green]\[INF][/] Detected intent: [bold]{mode}[/]")
				return mode
		except Exception as e:
			console.print(Warning(message=f'Could not detect mode automatically: {e}. Falling back to "chat" mode.'))
		return "chat"

	def _prompt_and_redetect(self, history, encryptor, max_iter, choices, mode, api_base, api_key):
		"""Show interactive menu and re-detect intent. Returns (mode, max_iter, items) or None."""
		result = prompt_user(history, encryptor, max_iterations=max_iter, choices=choices, mode=mode)
		if result is None:
			return None
		menu_action, extra_iters = result
		max_iter += extra_iters

		items = []
		intent_model = self.run_opts.get("intent_model")
		new_mode = self._detect_mode(menu_action, intent_model, api_base, api_key)
		if new_mode != mode:
			mode = new_mode
			history.set_system(get_system_prompt(mode))
			items.append(Info(message=f"Switched to {mode} mode"))

		items.append(Ai(content=menu_action, ai_type="prompt"))
		return mode, max_iter, items

	def _run_loop(self, mode: str, prompt: str, targets: List[str], model: str,
				  encryptor: Optional[SensitiveDataEncryptor], previous_results: List = None) -> Generator:
		"""Run unified loop for both attack and chat modes."""
		max_iter = int(self.run_opts.get("max_iterations", 10))
		temp = float(self.run_opts.get("temperature", 0.7))
		api_key = self.run_opts.get("api_key")
		api_base = self.run_opts.get("api_base")
		max_tokens = int(self.run_opts.get("max_tokens", CONFIG.addons.ai.max_tokens))
		max_tokens_total = int(self.run_opts.get("max_tokens_total", CONFIG.addons.ai.max_tokens_total))
		dry_run = self.run_opts.get("dry_run", False)
		verbose = self.run_opts.get("verbose", False)
		interactive = self.run_opts.get("interactive", True)
		import litellm

		# Initialize chat history with appropriate system prompt
		history = ChatHistory()
		history.add_system(get_system_prompt(mode))
		user_msg = format_user_initial(targets, prompt, previous_results=previous_results or [])
		history.add_user(_maybe_encrypt(user_msg, encryptor))
		yield Ai(content=prompt or f"Starting {mode}...", ai_type="prompt")

		# Create action context
		scope = "current" if previous_results else "workspace"
		ctx = ActionContext(
			targets=targets, model=model, encryptor=encryptor,
			dry_run=dry_run, verbose=verbose,
			context=self.context or {},
			scope=scope, results=previous_results or [])
		# yield Info(message=repr(ctx))

		iteration = 0
		query_extensions = 0
		max_query_extensions = 3
		while iteration < max_iter:
			iteration += 1

			try:
				# Auto-summarize if token count exceeds threshold
				summarized, old_tokens, new_tokens = history.maybe_summarize(
					model, api_base=api_base, api_key=api_key, threshold=max_tokens)
				if summarized:
					yield Ai(
						content=f"Chat history compacted: {old_tokens} -> {new_tokens} estimated tokens",
						ai_type="chat_compacted",
					)

				# Call LLM
				messages = history.to_messages(max_tokens_total=max_tokens_total)
				token_str = format_token_count(history.est_tokens(), icon='arrow_up')
				msg = f"[bold orange3]{random.choice(LLM_SPINNER_MESSAGES)}[/] [gray42] • {token_str}[/]"
				with maybe_status(msg, spinner="dots"):
					result = call_llm(messages, model, temp, api_base, api_key)
				response = result["content"]
				usage = result.get("usage", {})

				# Handle empty response
				if not response:
					yield Warning(message="LLM returned empty response")
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

				# Execute actions and capture follow_up
				if len(actions) > 0:
					yield Info(message=f"Executing {len(actions)} actions ...")
					self.debug(json.dumps(actions, indent=4))
				follow_up_choices = None
				for action in actions:
					action_type = action.get("action", "")
					is_secator = action_type in ['task', 'workflow']
					action_results = []
					has_errors = False
					for item in dispatch_action(action, ctx):
						if isinstance(item, (Stat, Progress, State, Info)):
							# Skip stats, progress, state, and info
							continue
						if isinstance(item, Error):
							has_errors = True
						if isinstance(item, Ai):
							self.add_result(item)
							# Capture choices from follow_up action
							if item.ai_type == "follow_up":
								follow_up_choices = (item.extra_data or {}).get("choices", [])
							# Feed shell output back to the LLM
							if item.ai_type == "shell_output":
								action_results.append({"output": item.content})
							continue
						if isinstance(item, OutputType):
							self.add_result(item, print=not is_secator)  # only print non-Secator findings
							item = item.toDict(exclude=list(INTERNAL_FIELDS))  # TODO: verify if yielding raw output would be better
						action_results.append(item)  # TODO: verify if yielding raw output would be better

						# Keep ctx.results in sync for scope='current' queries
						if ctx.scope == "current":
							ctx.results.append(item)

					# Build tool result for history (compact JSON)
					tool_result = format_tool_result(
						action.get("name", action_type),
						"error" if has_errors else "success",
						len(action_results),
						action_results
					)
					tool_result = _maybe_encrypt(tool_result, encryptor)
					history.add_user(tool_result)

				# If the last action was a query, allow one more iteration (capped to prevent infinite loops)
				if actions and actions[-1].get("action") == "query" and query_extensions < max_query_extensions:
					max_iter += 1
					query_extensions += 1

				# Show menu if follow_up, no actions, or max_iter reached
				if follow_up_choices is not None or not actions or iteration == max_iter:
					if not interactive:
						return
					if not follow_up_choices:
						if iteration == max_iter:
							yield Ai(content="Max iterations reached. What should I do next?", ai_type="follow_up")
						elif not actions:
							yield Ai(content="No actions to execute. What should I do next?", ai_type="follow_up")
					result = self._prompt_and_redetect(
						history, encryptor, max_iter, follow_up_choices or [], mode, api_base, api_key)
					if result is None:
						return
					mode, max_iter, items = result
					yield from items
					continue

				# Normal continue
				continue_msg = format_continue(iteration, max_iter)
				history.add_user(_maybe_encrypt(continue_msg, encryptor))

			except KeyboardInterrupt:
				if not interactive:
					return
				yield Warning(message="Interrupted by user.")
				result = self._prompt_and_redetect(
					history, encryptor, max_iter, [], mode, api_base, api_key)
				if result is None:
					return
				mode, max_iter, items = result
				yield from items
				continue

			except Exception as e:
				if isinstance(e, litellm.RateLimitError):
					yield Warning(message="Rate limit exceeded - waiting 5s and retry in the next iteration")
					iteration -= 1
					sleep(5)
					continue
				yield Error.from_exception(e)
				if isinstance(e, litellm.exceptions.APIError):
					yield Error(message="API error occurred. Stopping.")
					return

		yield Info(message=f"Reached max iterations ({max_iter})")

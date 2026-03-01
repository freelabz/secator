# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import os
import random
from pathlib import Path
from typing import Generator, List, Optional

from time import sleep

from pydantic.functional_validators import InstanceOf

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import ADDONS_ENABLED, LLM_SPINNER_MESSAGES
from secator.output_types import (
	Ai, Stat, Progress, Error, Info, Warning, State, FINDING_TYPES, OutputType
)
from secator.runners import PythonRunner
from secator.rich import console, maybe_status
from secator.utils import format_token_count
from secator.ai.actions import ActionContext, dispatch_action
from secator.ai.encryption import SensitiveDataEncryptor
from secator.ai.history import ChatHistory
from secator.ai.prompts import get_system_prompt, format_user_initial, format_tool_result, format_continue
from secator.ai.utils import call_llm, parse_actions, strip_json_from_response, prompt_user


DEFAULT_API_KEY = CONFIG.addons.ai.api_key or os.environ.get('ANTHROPIC_API_KEY', '')


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
		"model": {"type": str, "default": CONFIG.addons.ai.default_model, "help": "LLM model", "choices": ["claude-sonnet-4-6", "claude-haiku-4-5"]},
		"api_key": {"type": str, "default": DEFAULT_API_KEY, "help": "API key for LLM provider"},
		"api_base": {"type": str, "default": CONFIG.addons.ai.api_base, "help": "API base URL"},
		"sensitive": {"is_flag": True, "default": True, "help": "Encrypt sensitive data"},
		"max_iterations": {"type": int, "default": 10, "help": "Max iterations"},
		"temperature": {"type": float, "default": 0.7, "help": "LLM temperature"},
		"dry_run": {"is_flag": True, "default": False, "help": "Show without executing"},
		"yes": {"is_flag": True, "default": False, "short": "y", "help": "Auto-accept"},
		"intent_model": {"type": str, "default": CONFIG.addons.ai.intent_model, "help": "Model for intent detection"},
		"max_tokens": {"type": int, "default": CONFIG.addons.ai.max_tokens, "help": "Max tokens before compacting history"},
		"interactive": {"is_flag": True, "default": True, "help": "Prompt user for follow-up after completion"},
	}

	def yielder(self) -> Generator:
		"""Execute AI task."""
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
				d.pop('_context', None)
				d.pop('_uuid', None)
				d.pop('_related', None)
				d.pop('_duplicate', None)
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
		except Exception:
			pass
		return "chat"

	def _run_loop(self, mode: str, prompt: str, targets: List[str], model: str,
				  encryptor: Optional[SensitiveDataEncryptor], previous_results: List = None) -> Generator:
		"""Run unified loop for both attack and chat modes."""
		max_iter = int(self.run_opts.get("max_iterations", 10))
		temp = float(self.run_opts.get("temperature", 0.7))
		api_key = self.run_opts.get("api_key")
		api_base = self.run_opts.get("api_base")
		max_tokens = int(self.run_opts.get("max_tokens", CONFIG.addons.ai.max_tokens))
		dry_run = self.run_opts.get("dry_run", False)
		verbose = self.run_opts.get("verbose", False)
		interactive = self.run_opts.get("interactive", True)

		# Initialize chat history with appropriate system prompt
		history = ChatHistory()
		history.add_system(get_system_prompt(mode))
		user_msg = format_user_initial(targets, prompt, previous_results=previous_results or [])
		history.add_user(encryptor.encrypt(user_msg) if encryptor else user_msg)
		yield Ai(content=prompt or f"Starting {mode}...", ai_type="prompt")

		# Create action context
		scope = "current" if previous_results else "workspace"
		ctx = ActionContext(
			targets=targets, model=model, encryptor=encryptor, dry_run=dry_run,
			verbose=verbose,
			drivers=self.context.get("drivers") if self.context else [],
			workspace_id=self.context.get("workspace_id") if self.context else None,
			scan_id=self.context.get("scan_id") if self.context else None,
			workflow_id=self.context.get("workflow_id") if self.context else None,
			task_id=self.context.get("task_id") if self.context else None,
			scope=scope,
			results=previous_results or [])
		yield Info(message=repr(ctx))

		iteration = 0
		done = False
		while iteration < max_iter:
			iteration += 1
			# yield Info(message=f"Iteration {iteration}/{max_iter}")

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
				messages = history.to_messages()
				token_str = format_token_count(history.est_tokens(), icon='arrow_up')
				msg = f"[bold orange3]{random.choice(LLM_SPINNER_MESSAGES)}[/] [gray42] • {token_str}[/]"
				with maybe_status(msg, spinner="dots"):
					result = call_llm(messages, model, temp, api_base, api_key)
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
					# yield Info(message=f"Running action {format_object(action, 'yellow')}")
					action_results = []
					for item in dispatch_action(action, ctx):
						if isinstance(item, (Stat, Progress, State, Info)):
							continue
						if isinstance(item, Ai):
							self.add_result(item)
							# Feed shell output back to the LLM
							if item.ai_type == "shell_output":
								action_results.append({"output": item.content})
							continue
						if isinstance(item, OutputType):
							self.add_result(item, print=False)  # only for Secator findings
							item = item.toDict(exclude=['_context', '_uuid', '_related'])
						action_results.append(item)
						# Keep ctx.results in sync for scope='current' queries
						if ctx.scope == "current":
							ctx.results.append(item)

					# Build tool result for history (compact JSON)
					# yield Info(f"Action returned {len(action_results)} results")
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

				# If the last action was a query (and not in a query-only loop), allow one more iteration
				if actions and actions[-1].get("action") == "query":
					max_iter += 1

				# Prompt user for continuation
				if done or (iteration == max_iter):
					if not interactive:
						if done:
							return
						yield Info(message=f"Reached max iterations ({max_iter}).")
						return
					if (iteration == max_iter):
						yield Info(message=f"Reached max iterations ({max_iter}). Following up with user.")
					elif done:
						yield Info(message="Following up with user.")
					while True:
						result = prompt_user(history, encryptor, mode)
						if result is None:
							return
						action, value = result
						if action == "show_raw":
							console.print(f"\n{response}\n")
							continue
						break
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
						done = True
						yield Ai(content=value, ai_type="prompt")
					elif action == "switch_mode":
						other_mode = "chat" if mode == "attack" else "attack"
						mode = other_mode
						history.add_system(get_system_prompt(mode))
						user_msg = encryptor.encrypt(value) if encryptor else value
						history.add_user(user_msg)
						max_iter += 1
						done = False
						yield Info(message=f"Switched to {mode} mode")
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
					yield Warning(message="Rate limit exceeded - waiting 5s and retry in the next iteration")
					iteration -= 1
					sleep(5)
					continue
				yield Error.from_exception(e)
				if isinstance(e, litellm.exceptions.APIError):
					yield Error(message="API error occurred. Stopping.")
					return

		yield Info(message=f"Reached max iterations ({max_iter})")

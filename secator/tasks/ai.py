# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import json
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
from secator.ai.actions import ActionContext, dispatch_action, _run_batch, _decrypt_dict
from secator.ai.encryption import SensitiveDataEncryptor, maybe_encrypt
from secator.ai.history import ChatHistory, truncate_to_tokens
from secator.ai.prompts import (
	get_system_prompt, get_mode_config, format_user_initial, format_tool_result, format_continue
)
from secator.ai.tools import build_tool_schemas, tool_call_to_action
from secator.ai.utils import call_llm, setup_ai, prompt_user


DEFAULT_API_KEY = CONFIG.addons.ai.api_key


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
		"max_tokens_total": {
			"type": int, "default": CONFIG.addons.ai.max_tokens_total,
			"help": "Hard token limit - truncate oldest messages beyond this",
		},
		"interactive": {"is_flag": True, "default": True, "help": "Prompt user for follow-up after completion"},
		"context": {
			"type": dict,
			"default": None,
			"internal": True,
			"help": "Context to pass to AI (findings, scope, objective)"
		},
		"internal": {
			"is_flag": True,
			"default": False,
			"internal": True,
			"help": "Mark as internal subagent (suppresses interactive prompts)"
		},
		"max_workers": {
			"type": int,
			"default": 3,
			"internal": True,
			"help": "Max concurrent tasks for batch execution"
		},
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

		# If no prompt provided, show full-screen prompt input
		is_internal = self.run_opts.get("internal", False)
		if not prompt and not is_internal:
			from secator.definitions import IN_WORKER
			if not IN_WORKER:
				from secator.rich import FullScreenPrompt
				targets_str = ', '.join(self.inputs) if self.inputs else 'no target'
				prompt = FullScreenPrompt(
					title=f"What do you want to do? ({targets_str})",
					placeholder="e.g. Scan for vulnerabilities on this target..."
				).show()
				if not prompt:
					yield Info(message="No prompt provided. Exiting.")
					return

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
		except Exception:
			console.print(Warning(message='Could not detect mode using LLM. Falling back to "chat" mode.'))
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
		# Get mode config
		mode_config = get_mode_config(mode)
		mode_max_iter = mode_config.get("max_iterations")
		max_iter = mode_max_iter if mode_max_iter else int(self.run_opts.get("max_iterations", 10))

		temp = float(self.run_opts.get("temperature", 0.7))
		api_key = self.run_opts.get("api_key")
		api_base = self.run_opts.get("api_base")
		max_tokens_total = int(self.run_opts.get("max_tokens_total", CONFIG.addons.ai.max_tokens_total))
		dry_run = self.run_opts.get("dry_run", False)
		verbose = self.run_opts.get("verbose", False)
		interactive = self.run_opts.get("interactive", True)

		# Check if internal subagent
		is_internal = self.run_opts.get("internal", False)
		passed_context = self.run_opts.get("context") or {}

		# Suppress interactive prompts for internal subagents
		if is_internal:
			interactive = False

		import litellm

		# Initialize chat history with appropriate system prompt
		history = ChatHistory()
		history.model = model
		system_prompt = get_system_prompt(mode)

		# Inject context for subagents
		if is_internal and passed_context:
			system_prompt += "\n\n### SUBAGENT CONTEXT\n"
			system_prompt += json.dumps(passed_context, indent=2)

		history.add_system(system_prompt)
		user_msg = format_user_initial(targets, prompt, previous_results=previous_results or [])
		history.add_user(maybe_encrypt(user_msg, encryptor))
		yield Ai(content=prompt or f"Starting {mode}...", ai_type="prompt")

		# Create action context
		scope = "current" if previous_results else "workspace"
		max_workers = int(self.run_opts.get("max_workers", 3))
		ctx = ActionContext(
			targets=targets, model=model, encryptor=encryptor,
			dry_run=dry_run, verbose=verbose,
			context=self.context or {},
			scope=scope, results=previous_results or [],
			max_workers=max_workers)

		# Build tool schemas for native tool calling
		tool_schemas = build_tool_schemas(mode)

		iteration = 0
		query_extensions = 0
		max_query_extensions = 3
		while iteration < max_iter:
			iteration += 1

			try:
				# Auto-summarize if token count exceeds threshold
				self.debug(f'[context] iteration {iteration}/{max_iter}, checking compaction...')
				summarized, old_tokens, new_tokens = history.maybe_summarize(
					model, api_base=api_base, api_key=api_key)
				if summarized:
					self.debug(f'[context] compacted: {old_tokens} -> {new_tokens} tokens')
					yield Ai(
						content=f"Chat history compacted: {old_tokens} -> {new_tokens} estimated tokens",
						ai_type="chat_compacted",
					)

				# Call LLM with tool schemas
				messages = history.to_messages(max_tokens_total=max_tokens_total)
				token_count = history.count_tokens(model)
				self.debug(f'[context] sending {token_count} tokens to LLM ({len(messages)} messages)')
				token_str = format_token_count(token_count, icon='arrow_up')
				msg = f"[bold orange3]{random.choice(LLM_SPINNER_MESSAGES)}[/] [gray42] • {token_str}[/]"
				with maybe_status(msg, spinner="dots"):
					result = call_llm(messages, model, temp, api_base, api_key, tools=tool_schemas)
				response_content = result["content"]
				tool_calls = result.get("tool_calls", [])
				usage = result.get("usage", {})

				# Handle empty response (no content and no tool calls)
				if not response_content and not tool_calls:
					yield Warning(message="LLM returned empty response")
					continue

				# Decrypt response content
				if encryptor and response_content:
					response_content = encryptor.decrypt(response_content)

				# Convert tool_calls to actions
				actions = []
				tc_action_pairs = []  # list of (tool_call_dict, action_dict) tuples
				for tc in tool_calls:
					args = tc["arguments"]
					if encryptor:
						args = _decrypt_dict(args, encryptor)
					action = tool_call_to_action(tc["name"], args)
					if action is not None:
						actions.append(action)
						tc_action_pairs.append((tc, action))
					else:
						self.debug(f'[tool_call] skipping unknown tool: {tc["name"]}')

				# Display response content as-is
				if response_content:
					yield Ai(
						content=response_content,
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
				if tool_calls:
					# Build litellm-format tool_calls for history
					litellm_tool_calls = []
					for tc in tool_calls:
						litellm_tool_calls.append({
							"id": tc["id"],
							"type": "function",
							"function": {
								"name": tc["name"],
								"arguments": json.dumps(tc["arguments"]),
							},
						})
					history.add_assistant_with_tool_calls(response_content or None, litellm_tool_calls)
				else:
					history.add_assistant(response_content)

				# Execute actions and capture follow_up
				if len(actions) > 0:
					action_str = 'actions' if len(actions) > 1 else None
					if action_str:
						yield Info(message=f"Executing {len(actions)} {action_str} ...")
					self.debug(json.dumps(actions, indent=4))

				# Dispatch actions: batch if multiple, single otherwise
				follow_up_choices = None
				if len(tc_action_pairs) > 1:
					# Batch execution
					action_list = [action for _, action in tc_action_pairs]
					action_iter = _run_batch(action_list, ctx)
					action_results = []
					has_errors = False

					for result in action_iter:
						if isinstance(result, (Stat, Progress, State, Info)):
							continue
						if isinstance(result, Error):
							has_errors = True
						if isinstance(result, Ai):
							self.add_result(result)
							if result.ai_type == "follow_up":
								follow_up_choices = (result.extra_data or {}).get("choices", [])
							if result.ai_type == "shell_output":
								action_results.append({"output": result.content})
							continue
						if isinstance(result, OutputType):
							self.add_result(result, print=False)
							result = result.toDict(exclude=list(INTERNAL_FIELDS))
						action_results.append(result)
						if ctx.scope == "current":
							ctx.results.append(result)

					# Build a single tool result and assign to first tool_call ID
					action_name = f"batch({len(action_list)})"
					tool_result_str = format_tool_result(
						action_name,
						"error" if has_errors else "success",
						len(action_results),
						action_results
					)

					# Apply token budget and truncation
					budget = history.get_action_budget(model)
					original_len = len(tool_result_str)
					self.debug(
						f'[context] action "batch" result: {len(action_results)} items, budget={budget} tokens')
					fallback_path = Path(self.reports_folder) / "report.json" if self.reports_folder else None
					tool_result_str = truncate_to_tokens(
						tool_result_str, budget, model, fallback_path=fallback_path)
					if "[TRUNCATED]" in tool_result_str:
						self.debug(f'[context] truncated: {original_len} -> {len(tool_result_str)} chars')

					tool_result_str = maybe_encrypt(tool_result_str, encryptor)

					# Add tool result for each tool call ID
					for tc, _ in tc_action_pairs:
						history.add_tool_result(tc["id"], tool_result_str)

				elif len(tc_action_pairs) == 1:
					# Single action dispatch
					tc, action = tc_action_pairs[0]
					action_type = action.get("action", "")
					action_iter = dispatch_action(action, ctx)
					action_results = []
					has_errors = False

					for result in action_iter:
						if isinstance(result, (Stat, Progress, State, Info)):
							continue
						if isinstance(result, Error):
							has_errors = True
						if isinstance(result, Ai):
							self.add_result(result)
							if result.ai_type == "follow_up":
								follow_up_choices = (result.extra_data or {}).get("choices", [])
							if result.ai_type == "shell_output":
								action_results.append({"output": result.content})
							continue
						if isinstance(result, OutputType):
							self.add_result(result, print=False)
							result = result.toDict(exclude=list(INTERNAL_FIELDS))
						action_results.append(result)
						if ctx.scope == "current":
							ctx.results.append(result)

					# Build tool result for history
					action_name = action.get("name", action_type)
					tool_result_str = format_tool_result(
						action_name,
						"error" if has_errors else "success",
						len(action_results),
						action_results
					)

					# Apply token budget and truncation
					budget = history.get_action_budget(model)
					original_len = len(tool_result_str)
					self.debug(
						f'[context] action "{action_type}" result: '
						f'{len(action_results)} items, budget={budget} tokens')
					if action_type in ("task", "workflow"):
						fallback_path = (
							Path(self.reports_folder) / "report.json" if self.reports_folder else None)
						tool_result_str = truncate_to_tokens(
							tool_result_str, budget, model, fallback_path=fallback_path)
					elif action_type == "shell":
						output_dir = (
							Path(self.reports_folder) / ".outputs" if self.reports_folder else None)
						tool_result_str = truncate_to_tokens(
							tool_result_str, budget, model,
							output_dir=output_dir,
							result_name="shell"
						)
					else:
						tool_result_str = truncate_to_tokens(tool_result_str, budget, model)

					if "[TRUNCATED]" in tool_result_str:
						self.debug(f'[context] truncated: {original_len} -> {len(tool_result_str)} chars')

					tool_result_str = maybe_encrypt(tool_result_str, encryptor)
					history.add_tool_result(tc["id"], tool_result_str)

				if len(actions) > 0:
					action_str = 'actions' if len(actions) > 1 else None
					if action_str:
						yield Info(message=f"Executed {len(actions)} {action_str}.")

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
					# Rebuild tool schemas if mode changed
					tool_schemas = build_tool_schemas(mode)
					yield from items
					continue

				# STOP or CONTINUE
				stop_or_continue = "STOP or CONTINUE based on whether the initial user request has been fulfilled"
				continue_msg = format_continue(iteration, max_iter, stop_or_continue)
				history.add_user(maybe_encrypt(continue_msg, encryptor))

			except KeyboardInterrupt:
				if not interactive:
					return
				yield Warning(message="Interrupted by user.")
				result = self._prompt_and_redetect(
					history, encryptor, max_iter, [], mode, api_base, api_key)
				if result is None:
					return
				mode, max_iter, items = result
				# Rebuild tool schemas if mode changed
				tool_schemas = build_tool_schemas(mode)
				yield from items
				continue

			except Exception as e:
				if isinstance(e, litellm.RateLimitError):
					yield Warning(message="Rate limit exceeded - waiting 5s and retry in the next iteration")
					iteration -= 1
					sleep(5)
					continue
				elif isinstance(e, litellm.AuthenticationError):
					yield Error(message=str(e))
					yield Error(
						message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`'
					)
					return
				yield Error.from_exception(e)
				return

		yield Info(message=f"Reached max iterations ({max_iter})")

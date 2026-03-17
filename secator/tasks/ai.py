# secator/tasks/ai.py
"""AI-powered penetration testing task - simplified implementation."""
import json
from pathlib import Path
from typing import Generator

from time import sleep

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import ADDONS_ENABLED
from secator.output_types import (
	Ai, Stat, Progress, Error, Info, Warning, State, FINDING_TYPES, OutputType, INTERNAL_FIELDS
)
from secator.runners import PythonRunner
from secator.rich import console, maybe_status
from secator.ai.actions import (
	ActionContext, check_guardrails, dispatch_action, _run_batch, _decrypt_dict, _build_action_display
)
from secator.ai.guardrails import PermissionEngine
from secator.ai.encryption import SensitiveDataEncryptor, maybe_encrypt
from secator.ai.history import ChatHistory, truncate_to_tokens, get_context_window
from secator.ai.prompts import (
	load_prompt, get_system_prompt, get_mode_config, format_tool_result, format_continue
)
from secator.ai.tools import build_tool_schemas, tool_call_to_action, TOOL_SCHEMAS
from secator.ai.session import save_history, show_session_picker, replay_session
from secator.ai.utils import call_llm, init_llm, setup_ai, prompt_user, format_llm_status
from secator.ai.interactivity import create_backend, RemoteBackend


DEFAULT_API_KEY = CONFIG.addons.ai.api_key


@task()
class ai(PythonRunner):
	"""AI-powered penetration testing assistant (attack or chat mode)."""
	output_types = FINDING_TYPES
	tags = ["ai", "analysis", "pentest"]
	default_inputs = ''
	opts = {
		"name": {"type": str, "default": "", "short": "n", "internal_name": "session_name", "help": "Name for the AI session or subagent"},  # noqa: E501
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
		"subagent": {
			"is_flag": True,
			"default": False,
			"internal": True,
			"help": "Mark as subagent (suppresses interactive prompts and progress display)"
		},
		"max_workers": {
			"type": int,
			"default": 3,
			"internal": True,
			"help": "Max concurrent tasks for batch execution"
		},
		"resume": {
			"is_flag": True,
			"default": False,
			"help": "Resume a previous AI session"
		},
		"context_warnings": {
			"is_flag": True,
			"default": True,
			"help": "Show context window usage warnings at 50%/75%"
		},
		"async_tasks": {
			"is_flag": True,
			"default": False,
			"help": "Run tasks/workflows asynchronously (via Celery worker)"
		},
		"show_prompt": {
			"is_flag": True,
			"default": False,
			"help": "Render and display the system prompt, then exit"
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

		# Set run opts as instance attributes
		self.resume = self.get_opt_value("resume")
		self.is_subagent = self.get_opt_value("subagent")
		self.model = self.get_opt_value("model")
		self.intent_model = self.get_opt_value("intent_model")
		self.api_base = self.get_opt_value("api_base")
		self.api_key = self.get_opt_value("api_key")
		self.sensitive = self.get_opt_value("sensitive")
		self.mode = self.get_opt_value("mode")
		self.max_tokens_total = self.get_opt_value("max_tokens_total")
		self.max_workers = self.get_opt_value("max_workers")
		self.max_iterations = self.get_opt_value("max_iterations")
		self.temp = self.get_opt_value("temperature")
		self.dry_run = self.run_opts.get("dry_run", False)
		self.verbose = self.run_opts.get("verbose", False)
		interactive = self.get_opt_value("interactive")
		if interactive is True:
			self.interactive = "local"
		elif interactive is False:
			self.interactive = "auto"
		elif interactive is None:
			self.interactive = "local" if self.sync else "auto"
		else:
			self.interactive = interactive
		if self.is_subagent:
			self.interactive = "auto"
		self.context_warnings = self.get_opt_value("context_warnings")
		self.session_name = self.run_opts.get("session_name")
		self.passed_context = self.run_opts.get("context") or {}
		self.async_tasks = self.get_opt_value("async_tasks")
		self._sync = False if self.async_tasks else self.sync
		self.history = ChatHistory()
		self.encryptor = SensitiveDataEncryptor() if self.sensitive else None
		self.has_previous_results = len(self.results) > 0
		self.scope = "current" if self.has_previous_results > 0 else "workspace"  # TODO: rework
		self.permission_engine = PermissionEngine(
			CONFIG.addons.ai.permissions,
			targets=self.inputs,
			workspace=self.reports_folder or ""
		)

		# Create interactivity backend
		self.session_id = self.session_name or str(self.id)
		self.backend = create_backend(self.interactive, timeout=CONFIG.addons.ai.user_response_timeout)

		# Suppress interactive prompts and noisy output for subagents
		if self.is_subagent:
			self.print_info = False
			self.print_warning = False
			self.print_error = False

		# Handle --show-prompt: render and display the system prompt, then exit
		if self.run_opts.get("show_prompt", False):
			show_mode = self.mode or "attack"
			system_prompt = get_system_prompt(show_mode, workspace_path=str(self.reports_folder), backend=self.backend)
			console.print(f"[bold orange3]System prompt ({show_mode})[/]\n")
			console.print(system_prompt, highlight=False, soft_wrap=True)
			return

		# Session resume and replay
		if self.resume and not self.is_subagent:
			session = show_session_picker()
			if session is None:
				return
			self.session_name = session["name"]
			self.history = replay_session(session)
			if self.history is None:
				yield Error(message="Failed to restore session.")
				return
			self.history.model = self.model # update to new model if different
			self._reports_folder = session['folder'] # restore the original session folder
			if self.interactive != "auto":
				result = self._prompt_and_redetect([])
				if result is None:
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				yield from result

		# Get prompt from file
		self.prompt = self.run_opts.get("prompt", "")
		if self.prompt and Path(self.prompt).is_file():
			self.prompt = Path(self.prompt).read_text().strip()

		# If no prompt provided, show full-screen prompt input
		if not self.prompt and not self.is_subagent:
			from secator.definitions import IN_WORKER
			if not IN_WORKER:
				from secator.rich import FullScreenPrompt
				targets_str = ', '.join(self.inputs) if self.inputs else 'no target'
				self.prompt = FullScreenPrompt(
					title=f"What do you want to do? ({targets_str})",
					placeholder="e.g. Scan for vulnerabilities on this target..."
				).show()
				if not self.prompt:
					yield Info(message="No prompt provided. Exiting.")
					return

		# Set session name
		prompt_label = (self.prompt[:80] + '...') if self.prompt and len(self.prompt) > 80 else (self.prompt or self.mode)
		if not self.session_name:
			self.session_name = prompt_label

		# Encrypt session name
		if self.encryptor:
			self.session_name = self.encryptor.decrypt(self.session_name)

		# Tag session name / subagent in runner context
		self.context["session_name"] = self.session_name
		if self.is_subagent:
			self.context["subagent"] = self.session_name

		# Detect mode + set system prompt
		self._detect_mode()
		self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
		self.history.set_system(maybe_encrypt(self.system_prompt, self.encryptor))
		self.history.add_user(maybe_encrypt(self.prompt, self.encryptor))
		yield Info(message=f"Using model: {self.model}, mode: {self.mode}")

		# Run unified loop
		yield from self._run_loop()

	def _detect_mode(self):
		"""Detect mode using a fast LLM call for intent analysis."""
		old_mode = self.mode
		if not self.prompt:
			self.mode = old_mode or "chat"
			return
		try:
			selection_prompt = load_prompt("modes/_selection.txt")
			messages = [{"role": "user", "content": f"{selection_prompt}\n{self.prompt}"}]
			with maybe_status("[bold orange3]Detecting intent...[/]", spinner="dots"):
				result = call_llm(messages, self.intent_model, temperature=0.3, api_base=self.api_base, api_key=self.api_key)
			mode = result["content"].strip().lower()
			if mode in ("attack", "chat"):
				console.print(rf"[bold green]\[INF][/] Detected intent: [bold]{mode}[/]")
				self.mode = mode
			else:
				self.mode = old_mode or "chat"
		except Exception:
			console.print(Warning(message='Could not detect mode using LLM. Falling back to "chat" mode.'))
			self.mode = "chat"
		if not self.mode:
			self.mode = "chat"
		self.max_iterations = get_mode_config(self.mode).get("max_iterations", self.max_iterations)
		self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
		if not old_mode or old_mode != self.mode:
			self.tool_schemas = build_tool_schemas(
				self.mode,
				backend=self.backend)

	def _prompt_and_redetect(self, choices):
		"""Show interactive menu and re-detect intent. Returns (mode, max_iter, items) or None."""

		# Prompt user with choices
		result = prompt_user(
			self.history,
			self.encryptor,
			max_iterations=self.max_iterations,
			choices=choices,
			mode=self.mode,
			model=self.model)
		if result is None:
			return None
		menu_action, extra_iters = result
		self.prompt = menu_action
		items = []

		# Increase max iters
		# Re-detect mode (before adding extra iters, since _detect_mode resets max_iterations)
		previous_mode = self.mode
		self._detect_mode()

		# Increase max iters after _detect_mode (which resets to mode default)
		self.max_iterations += extra_iters
		if self.mode != previous_mode:
			self.history.set_system(maybe_encrypt(self.system_prompt, self.encryptor))
			items.append(Info(message=f"Switched to {self.mode} mode"))

		# Build token breakdown for prompt display
		extra_data = {}
		by_role = self.history.count_tokens_by_role(self.model)
		from secator.ai.history import get_context_window
		extra_data = {"tokens": by_role["total"], "context_window": get_context_window(self.model), "by_role": by_role}

		items.append(Ai(content=menu_action, ai_type="prompt", extra_data=extra_data))
		return items

	def _prompt_context_fill(self, token_count, ctx_window):
		"""Prompt user when context window is filling up. Returns (compacted, items)."""
		from secator.ai.history import OUTPUT_TOKEN_RESERVATION
		items = []
		usable = ctx_window - OUTPUT_TOKEN_RESERVATION
		pct_used = (token_count / usable * 100) if usable > 0 else 0
		for threshold in (50, 75):
			if pct_used >= threshold and threshold not in self._context_warnings_shown:
				self._context_warnings_shown.add(threshold)
				from secator.rich import InteractiveMenu
				ctx_result = InteractiveMenu(
					f"Context window {threshold}% full ({token_count}/{usable} tokens).",
					[{"label": "Continue"}, {"label": "Compact"}]
				).show()
				if ctx_result is not None:
					idx, _ = ctx_result
					if idx == 1:  # Compact
						self.history.compact(self.model, self.api_base, self.api_key)
						new_tokens = self.history.count_tokens(self.model)
						items.append(Ai(
							content=f"Chat history compacted: {token_count} -> {new_tokens} tokens",
							ai_type="chat_compacted",
						))
						return True, items
				break
		return False, items

	def _run_loop(self) -> Generator:
		"""Run unified loop for both attack and chat modes."""

		# Lazy litellm import + init
		import litellm
		init_llm(api_key=self.api_key)

		# TODO: Check if this was needed
		# if not resumed_history:
		# 	# Build token breakdown for initial prompt display
		# 	by_role = history.count_tokens_by_role(model)
		# 	from secator.ai.history import get_context_window
		# 	initial_extra = {"tokens": by_role["total"], "context_window": get_context_window(model), "by_role": by_role}
		# 	yield Ai(content=prompt or f"Starting {mode}...", ai_type="prompt", extra_data=initial_extra)

		# Create action context
		ctx = ActionContext(
			targets=self.inputs,
			model=self.model,
			encryptor=self.encryptor,
			dry_run=self.dry_run,
			verbose=self.verbose,
			context=self.context or {},
			scope=self.scope,
			results=self.results,
			max_workers=self.max_workers,
			subagent=self.is_subagent,
			sync=self._sync,
			permission_engine=self.permission_engine)

		# Wire query_engine to remote backend if needed
		if isinstance(self.backend, RemoteBackend):
			self.backend.query_engine = ctx.get_query_engine()

		# Enter loop
		iteration = 0
		query_extensions = 0
		max_query_extensions = 3
		self._context_warnings_shown = set()
		while iteration < self.max_iterations:
			iteration += 1

			try:
				# Auto-summarize if token count exceeds threshold
				self.debug(f'iteration {iteration}/{self.max_iterations}, checking compaction...', sub='context')
				summarized, old_tokens, new_tokens = self.history.maybe_summarize(
					self.model, api_base=self.api_base, api_key=self.api_key)
				if summarized:
					self.debug(f'compacted: {old_tokens} -> {new_tokens} tokens', sub='context')
					yield Ai(
						content=f"Chat history compacted: {old_tokens} -> {new_tokens} estimated tokens",
						ai_type="chat_compacted",
					)

				# Call LLM with tool schemas
				messages = self.history.to_messages(max_tokens_total=self.max_tokens_total)
				by_role = self.history.count_tokens_by_role(self.model)
				token_count = by_role["total"]
				ctx_window = get_context_window(self.model)
				self.debug(f'sending {token_count} tokens to LLM ({len(messages)} messages)', sub='context')

				# Prompt user when context is filling up
				if self.interactive == "local" and self.context_warnings and ctx_window > 0:
					compacted, items = self._prompt_context_fill(token_count, ctx_window)
					yield from items
					if compacted:
						messages = self.history.to_messages(max_tokens_total=self.max_tokens_total)
						by_role = self.history.count_tokens_by_role(self.model)
						token_count = by_role["total"]

				# Yield subagent token usage for batch progress tracking
				if self.is_subagent:
					yield Ai(
						content='',
						ai_type="token_usage",
						extra_data={
							"tokens": token_count,
							"context_window": ctx_window,
						})

				# Call LLM with rich console status + token info
				msg = format_llm_status(token_count, ctx_window, by_role)
				with maybe_status(msg, spinner="dots"):
					result = call_llm(messages, self.model, self.temp, self.api_base, self.api_key, tools=self.tool_schemas)
				response_content = result["content"]
				tool_calls = result.get("tool_calls", [])
				usage = result.get("usage", {})

				# Debug: log raw LLM response
				self.debug(f'content: {response_content[:200] if response_content else "(empty)"}', sub='llm')

				# Handle empty response (no content and no tool calls)
				if not response_content and not tool_calls:
					yield Warning(message="LLM returned empty response")
					continue

				# Add assistant message to history (must happen before tool results)
				if tool_calls:
					litellm_tool_calls = [{
						"id": tc.id,
						"type": "function",
						"function": {
							"name": tc.function.name,
							"arguments": tc.function.arguments if isinstance(tc.function.arguments, str) else json.dumps(tc.function.arguments),
						},
					} for tc in tool_calls]
					self.history.add_assistant_with_tool_calls(response_content or None, litellm_tool_calls)
				else:
					self.history.add_assistant(response_content)

				# Display response content as-is
				if response_content:

					# Decrypt response
					if self.encryptor and response_content:
						response_content = self.encryptor.decrypt(response_content)

					# Mark as summary when LLM returns text with no tool calls (final answer)
					is_summary = not tool_calls
					yield Ai(
						content=response_content,
						ai_type="response",
						mode=self.mode,
						model=self.intent_model,
						summary=is_summary,
						extra_data={
							"iteration": iteration,
							"max_iterations": self.max_iterations,
							"tokens": usage.get("tokens") if usage else None,
							"cost": usage.get("cost") if usage else None,
						},
					)

				# Validate tool calls and convert to actions
				actions = []
				for tc in tool_calls:
					name = tc.function.name
					id = tc.id
					args = tc.function.arguments

					# Convert args to JSON if needed (some LLMs send a string here)
					if isinstance(args, str):
						args = json.loads(tc.function.arguments)

					# Decrypt args
					if self.encryptor:
						args = _decrypt_dict(args, self.encryptor)

					# Validate action parsing
					action = tool_call_to_action(name, args)
					if not action:
						reason = "empty arguments" if not args else f"unknown tool '{name}'"
						self.debug(f'[tool_call] skipping {name}: {reason}', sub='llm')
						schema = TOOL_SCHEMAS.get(name, {}).get("function", {})
						required = schema.get("parameters", {}).get("required", [])
						error_msg = json.dumps({
							"error": f"Tool call '{id}' rejected: {reason}",
							"required_fields": required,
							"hint": f"You must provide all required fields: {required}. Retry with a complete arguments object.",
						}, separators=(',', ':'))
						self.history.add_tool_result(name, id, error_msg)
						continue

					# Set tool call id in action
					action["tool_call_id"] = id
					action["tool_call_name"] = name

					# Guardrails pre-check: validate all actions on main thread before dispatch
					# This ensures interactive prompts happen before batch/progress panels
					denial, warnings = check_guardrails(action, ctx)
					denial_str = "denied" if denial else "ok"
					act_desc = args.get("command", None) or args.get("name", None) or args.get("query", None)
					self.debug(f'[guardrails] {name}({act_desc}) => {denial_str}', sub='guardrail')
					for w in warnings:
						yield Warning(message=w)
					if denial:
						cmd_display = _build_action_display(action)
						denial_display = denial
						if cmd_display:
							denial_display = f"{denial}\n[gray42]{cmd_display}[/gray42]"
						yield Warning(message=denial_display)
						error_msg = json.dumps({"error": denial}, separators=(',', ':'))
						self.history.add_tool_result(name, id, error_msg)
						continue
					actions.append(action)
				self.debug(f'actions (parsed): {json.dumps(actions, indent=2)}', sub='llm')

				# Dispatch actions: batch if multiple, single otherwise
				follow_up_choices = None
				stop_reason = None
				follow_up_ai = None
				if actions:
					is_batch = len(actions) > 1
					action_iter = _run_batch(actions, ctx) if is_batch else dispatch_action(actions[0], ctx)

					# Collect results
					collected = []
					for result in action_iter:
						# Skip adding execution types to this runner results
						if isinstance(result, (Stat, Progress, State, Info)):
							continue

						# Check if result is from a subagent
						is_from_subagent = isinstance(result, OutputType) and bool(result._context.get('subagent'))
						if isinstance(result, Ai):
							# Do not print subagent Ai-type results to not bloat main window, but still add them
							self.add_result(result, print=not is_from_subagent)

							# For Ai follow ups, grab proposed choices if any
							if result.ai_type == "follow_up":
								follow_up_ai = result
								follow_up_choices = result.choices
							elif result.ai_type == "stopped":
								stop_reason = result.content

							# TODO: Check if needed (probably not)
							# # If it's from an Ai-summary from a subagent, add it to action results
							# # so the main thread can read it
							# if result.summary and is_from_subagent and not self.is_subagent:
							# 	action_results.append({"summary": result.content})

							# # Add shell outputs to main thread
							# elif result.ai_type == "shell_output":
							# 	action_results.append({"output": result.content})
							continue

						# If it's output type, always add it, but don't print if it's from a subagent
						if isinstance(result, OutputType):
							self.add_result(result, print=not is_from_subagent)

						result = result.toDict() if isinstance(result, OutputType) else result
						# console.print(result)
						collected.append(result)
						ctx.results.append(result)

					# Group results by tool_call_id and add to history
					from itertools import groupby
					budget = self.history.get_action_budget(self.model)
					fallback_path = Path(self.reports_folder) / "report.json" if self.reports_folder else None
					for tc_id, group in groupby(collected, key=lambda r: r["_context"]['tool_call_id']):
						group_results = list(group)
						tc_name = group_results[0]["_context"]['tool_call_name']
						has_errors = any(r["_type"] == "error" for r in group_results)
						serialized = [
							r.toDict(exclude=list(INTERNAL_FIELDS)) if isinstance(r, OutputType) else r
							for r in group_results
						]
						tool_result_str = format_tool_result(
							tc_name, "error" if has_errors else "success",
							len(serialized), serialized)
						tool_result_str = truncate_to_tokens(
							tool_result_str, budget, self.model, fallback_path=fallback_path)
						tool_result_str = maybe_encrypt(tool_result_str, self.encryptor)
						self.history.add_tool_result(tc_name, tc_id, tool_result_str)

				if len(actions) > 0:
					action_str = 'actions' if len(actions) > 1 else None
					if action_str:
						yield Info(message=f"Executed {len(actions)} {action_str}.")

				# If the last action was a query, allow one more iteration (capped to prevent infinite loops)
				if actions and actions[-1].get("action") == "query" and query_extensions < max_query_extensions:
					self.max_iterations += 1
					query_extensions += 1

				# Stop tool: save and exit
				if stop_reason is not None:
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return

				# Show menu if follow_up, no actions, or max_iter reached
				if follow_up_choices is not None or not actions or iteration == self.max_iterations:
					if self.interactive == "auto":
						save_history(self.history, self.reports_folder, debug_fn=self.debug)
						return
					elif isinstance(self.backend, RemoteBackend) and follow_up_ai:
						follow_up_ai.status = "pending"
						follow_up_ai.session_id = self.session_id
						yield follow_up_ai
						answer = self.backend.ask_user(
							question=follow_up_ai.content,
							choices=follow_up_ai.choices,
							session_id=self.session_id
						)
						if answer is None:
							save_history(self.history, self.reports_folder, debug_fn=self.debug)
							return
						self.history.add_user(maybe_encrypt(answer, self.encryptor))
						continue
					else:
						result = self._prompt_and_redetect(follow_up_choices or [])
						if result is None:
							save_history(self.history, self.reports_folder, debug_fn=self.debug)
							return
						yield from result
						continue

				# STOP or CONTINUE
				stop_or_continue = (
					"Analyze the tool results, then STOP or CONTINUE based on whether the initial user request has been fulfilled"
					" (no need to explain why you stopped or continued, or comment on the initial user request)"
				)
				continue_msg = format_continue(iteration, self.max_iterations, stop_or_continue)
				self.history.add_user(maybe_encrypt(continue_msg, self.encryptor))

			except KeyboardInterrupt:
				if self.interactive == "auto":
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				yield Warning(message="Interrupted by user.")
				result = self._prompt_and_redetect([])
				if result is None:
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				mode, self.max_iterations, items = result
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
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				yield Error.from_exception(e)
				save_history(self.history, self.reports_folder, debug_fn=self.debug)
				return

		save_history(self.history, self.reports_folder, debug_fn=self.debug)
		yield Info(message=f"Reached max iterations ({iteration}/{self.max_iterations})")

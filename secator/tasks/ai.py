# secator/tasks/ai.py
"""AI-powered penetration testing task."""
import json
from itertools import groupby
from pathlib import Path
from time import sleep
from typing import Generator

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import ADDONS_ENABLED
from secator.output_types import (
	Ai, Stat, Progress, Error, Info, Warning, State, Target, FINDING_TYPES, OutputType, INTERNAL_FIELDS
)
from secator.runners import PythonRunner
from secator.rich import console, maybe_status
from secator.ai.actions import (
	ActionContext, check_guardrails, dispatch_action, _run_batch, _decrypt_dict, _build_action_display
)
from secator.ai.guardrails import PermissionEngine
from secator.ai.interactivity import create_backend, RemoteBackend
from secator.ai.encryption import SensitiveDataEncryptor, maybe_encrypt
from secator.ai.history import ChatHistory, truncate_to_tokens, get_context_window
from secator.ai.prompts import (
	load_prompt, get_system_prompt, get_mode_config, format_tool_result, format_continue
)
from secator.ai.tools import build_tool_schemas, tool_call_to_action, TOOL_SCHEMAS
from secator.ai.session import save_history, show_session_picker, replay_session
from secator.ai.utils import call_llm, init_llm, setup_ai, format_llm_status


DEFAULT_API_KEY = CONFIG.addons.ai.api_key


@task()
class ai(PythonRunner):
	"""AI-powered penetration testing assistant (attack or chat mode)."""
	output_types = FINDING_TYPES + [Target]
	tags = ["ai", "analysis", "pentest"]
	default_inputs = ''
	install_cmd = 'pipx install shfmt-py'
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
		"interactive": {"type": str, "default": "local", "help": "Interactivity mode: local, remote, or auto"},
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
		"dangerous": {
			"is_flag": True,
			"default": False,
			"help": "Skip all permission engine checks (dangerous!)"
		},
	}

	@classmethod
	def get_mock_context(cls, fixture):
		"""Return a context manager that mocks LLM calls with fixture data."""
		from secator.utils_test import mock_litellm_completion
		return mock_litellm_completion(fixture)

	# -------------------------------------------------------------------------
	# yielder: flat init sequence
	# -------------------------------------------------------------------------

	def yielder(self) -> Generator:
		"""Execute AI task."""
		# Addon / setup check
		if self.inputs == ['setup']:
			if not ADDONS_ENABLED['ai']:
				yield Error(message='Missing ai addon: please run "secator install addons ai".')
				return
			setup_ai()
			return
		if not ADDONS_ENABLED['ai']:
			yield Error(message='Missing ai addon: please run "secator install addons ai".')
			return

		# Init all options
		self._init_options()

		# Show prompt mode (diagnostic)
		if self.run_opts.get("show_prompt", False):
			show_mode = self.mode or "attack"
			prompt = get_system_prompt(show_mode, workspace_path=str(self.reports_folder), backend=self.backend)
			console.print(f"[bold orange3]System prompt ({show_mode})[/]\n")
			console.print(prompt, highlight=False, soft_wrap=True)
			return

		# Resume session
		if self.resume and not self.is_subagent:
			session = show_session_picker()
			if session is None:
				return
			self.session_name = session["name"]
			self.history = replay_session(session)
			if self.history is None:
				yield Error(message="Failed to restore session.")
				return
			self.history.model = self.model
			self._reports_folder = session['folder']
			result = self._prompt_and_redetect([])
			if result is None:
				save_history(self.history, self.reports_folder, debug_fn=self.debug)
				return
			self.context["session_name"] = self.session_name
			yield from result
			yield Info(message=f"Using model: {self.model}, mode: {self.mode}")
			yield from self._run_loop()
			return

		# Get user prompt
		self.prompt = self.run_opts.get("prompt", "")
		if self.prompt and Path(self.prompt).is_file():
			self.prompt = Path(self.prompt).read_text().strip()
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

		# Setup session metadata
		prompt_label = (self.prompt[:80] + '...') if self.prompt and len(self.prompt) > 80 else (self.prompt or self.mode)
		if not self.session_name:
			self.session_name = prompt_label
		if self.encryptor:
			self.session_name = self.encryptor.decrypt(self.session_name)
		self.context["session_name"] = self.session_name
		if self.is_subagent:
			self.context["subagent"] = self.session_name

		# Detect mode
		self._detect_mode()

		# Build system prompt + start history
		self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
		self.history.set_system(maybe_encrypt(self.system_prompt, self.encryptor))
		self.history.add_user(maybe_encrypt(self.prompt, self.encryptor))
		yield Ai(content=self.prompt, ai_type="prompt")
		yield Info(message=f"Using model: {self.model}, mode: {self.mode}")

		# Run loop
		yield from self._run_loop()

	# -------------------------------------------------------------------------
	# _run_loop: main LLM interaction loop
	# -------------------------------------------------------------------------

	def _run_loop(self) -> Generator:
		"""Main LLM interaction loop."""
		import litellm
		init_llm(api_key=self.api_key)

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
			interactive=self.interactive,
			backend=self.backend,
			session_id=self.session_id,
			permission_engine=self.permission_engine,
		)

		# Wire query_engine to remote backend if needed
		if isinstance(self.backend, RemoteBackend):
			self.backend.query_engine = ctx.get_query_engine()

		iteration = 0
		query_extensions = 0
		empty_streak = 0
		self._context_warnings_shown = set()

		while iteration < self.max_iterations:
			iteration += 1

			try:
				# Auto-summarize when context > 85% threshold
				yield from self._summarize_auto()

				# Prompt user when context is filling up (local only)
				yield from self._summarize_user()

				# Subagent token usage (for batch progress tracking)
				if self.is_subagent:
					by_role = self.history.count_tokens_by_role(self.model)
					yield Ai(content='', ai_type="token_usage", extra_data={
						"tokens": by_role["total"],
						"context_window": get_context_window(self.model),
					})

				# Call LLM
				messages = self.history.to_messages(max_tokens_total=self.max_tokens_total)
				by_role = self.history.count_tokens_by_role(self.model)
				token_count = by_role["total"]
				ctx_window = get_context_window(self.model)
				self.debug(f'iter {iteration}/{self.max_iterations}, {token_count} tokens', sub='context')

				msg = format_llm_status(token_count, ctx_window, by_role)
				with maybe_status(msg, spinner="dots"):
					result = call_llm(messages, self.model, self.temp, self.api_base, self.api_key, tools=self.tool_schemas)

				content = result["content"]
				tool_calls = result.get("tool_calls", [])
				usage = result.get("usage", {})

				self.debug(f'content: {content[:200] if content else "(empty)"}', sub='llm')

				# Empty response
				if not content and not tool_calls:
					empty_streak += 1
					yield Warning(message="LLM returned empty response")
					if empty_streak >= 3:
						yield Error(message="3 consecutive empty responses - the model may not support tool calling. Stopping.")
						save_history(self.history, self.reports_folder, debug_fn=self.debug)
						return
					continue

				empty_streak = 0

				# Add assistant message to history
				self._add_assistant_to_history(content, tool_calls)

				# Yield response content
				if content:
					display_content = self.encryptor.decrypt(content) if self.encryptor else content
					yield Ai(
						content=display_content,
						ai_type="response",
						mode=self.mode,
						model=self.intent_model,
						summary=not tool_calls,
						extra_data={
							"iteration": iteration,
							"max_iterations": self.max_iterations,
							"tokens": usage.get("tokens") if usage else None,
							"cost": usage.get("cost") if usage else None,
						},
					)

				# Process tool calls → validated actions
				follow_up_choices = None
				stop_reason = None
				follow_up_ai = None

				if tool_calls:
					actions = yield from self._process_tool_calls(tool_calls, ctx)

					if not actions:
						# All denied or failed → retry
						retry_msg = format_continue(iteration, self.max_iterations,
							"Some actions were denied by guardrails. Try alternative approaches that stay within allowed permissions.")
						self.history.add_user(maybe_encrypt(retry_msg, self.encryptor))
						continue

					# Dispatch actions, collect results, add to history
					dispatch_result = yield from self._dispatch_and_collect(actions, ctx)
					follow_up_choices = dispatch_result.get("follow_up_choices")
					stop_reason = dispatch_result.get("stop_reason")
					follow_up_ai = dispatch_result.get("follow_up_ai")

					if len(actions) > 1:
						yield Info(message=f"Executed {len(actions)} actions.")

				# Query extension (allow extra iterations for data exploration)
				if tool_calls and actions and actions[-1].get("action") == "query" and query_extensions < 3:
					self.max_iterations += 1
					query_extensions += 1

				# Stop tool → save and exit
				if stop_reason is not None:
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return

				# Follow-up / content-only / max_iter → prompt user
				if follow_up_choices is not None or not tool_calls or iteration == self.max_iterations:
					# For remote follow-up, yield the pending Ai so frontend can show it
					if follow_up_ai and isinstance(self.backend, RemoteBackend):
						follow_up_ai.status = "pending"
						follow_up_ai.session_id = self.session_id
						yield follow_up_ai

					result = self._prompt_and_redetect(follow_up_choices or [])
					if result is None:
						save_history(self.history, self.reports_folder, debug_fn=self.debug)
						return
					yield from result
					continue

				# Continue prompt (tool results analysed, keep going)
				stop_or_continue = load_prompt("constraints/tool_result_analysis.txt")
				continue_msg = format_continue(iteration, self.max_iterations, stop_or_continue)
				self.history.add_user(maybe_encrypt(continue_msg, self.encryptor))

			except KeyboardInterrupt:
				yield Warning(message="Interrupted by user.")
				result = self._prompt_and_redetect([])
				if result is None:
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				yield from result
				continue

			except Exception as e:
				if isinstance(e, litellm.RateLimitError):
					yield Warning(message="Rate limit exceeded - waiting 5s and retry in the next iteration")
					iteration -= 1
					sleep(5)
					continue
				elif isinstance(e, litellm.AuthenticationError):
					yield Error(message=str(e))
					yield Error(message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`')
					save_history(self.history, self.reports_folder, debug_fn=self.debug)
					return
				yield Error.from_exception(e)
				save_history(self.history, self.reports_folder, debug_fn=self.debug)
				return

		save_history(self.history, self.reports_folder, debug_fn=self.debug)
		yield Info(message=f"Reached max iterations ({iteration}/{self.max_iterations})")

	# -------------------------------------------------------------------------
	# Init
	# -------------------------------------------------------------------------

	def _init_options(self):
		"""Initialize all run options as instance attributes."""
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
		self.context_warnings = self.get_opt_value("context_warnings")
		self.session_name = self.run_opts.get("session_name")
		self.passed_context = self.run_opts.get("context") or {}
		self.async_tasks = self.get_opt_value("async_tasks")
		self.dangerous = self.get_opt_value("dangerous")

		# Interactive mode: "local" / "remote" / "auto"
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

		# Derived state
		self._sync = False if self.async_tasks else self.sync
		self.history = ChatHistory()
		self.encryptor = SensitiveDataEncryptor() if self.sensitive else None
		self.has_previous_results = len(self.results) > 0
		self.scope = "current" if self.has_previous_results > 0 else "workspace"
		self.permission_engine = PermissionEngine(
			CONFIG.addons.ai.permissions,
			targets=self.inputs,
			workspace=self.reports_folder or ""
		)

		# Create interactivity backend
		self.session_id = self.session_name or str(self.id)
		self.backend = create_backend(self.interactive, timeout=CONFIG.addons.ai.user_response_timeout)

		# Auto-approve workspace targets
		self._auto_approve_workspace_targets()

		# Suppress noisy output for subagents
		if self.is_subagent:
			self.print_info = False
			self.print_warning = False
			self.print_error = False

	# -------------------------------------------------------------------------
	# Mode detection
	# -------------------------------------------------------------------------

	def _detect_mode(self, force=False):
		"""Detect mode using a fast LLM call for intent analysis.
		Skips detection if mode was explicitly set (e.g. by subagent or CLI option),
		unless force=True (used for follow-up re-detection)."""
		old_mode = self.mode
		if old_mode and not force:
			if not hasattr(self, 'tool_schemas'):
				self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
				self.tool_schemas = build_tool_schemas(self.mode, is_subagent=self.is_subagent, backend=self.backend)
			return
		if not self.prompt:
			self.mode = "chat"
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
		mode_max = get_mode_config(self.mode).get("max_iterations", self.max_iterations)
		self.max_iterations = max(self.max_iterations, mode_max)
		self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
		if not hasattr(self, 'tool_schemas') or not old_mode or old_mode != self.mode:
			self.tool_schemas = build_tool_schemas(self.mode, is_subagent=self.is_subagent, backend=self.backend)

	# -------------------------------------------------------------------------
	# Workspace helpers
	# -------------------------------------------------------------------------

	def _auto_approve_workspace_targets(self):
		"""Auto-approve all targets found in the workspace."""
		workspace_id = self.context.get("workspace_id", "")
		if not workspace_id:
			return
		try:
			from secator.query import QueryEngine
			engine = QueryEngine(workspace_id, context=dict(self.context))
			results = engine.search({"_type": "target"}, limit=1000)
			target_names = {r.get("name") or r.get("_name", "") for r in results if r}
			target_names.discard("")
			self.debug(f'[workspace] found {len(results)} target(s): {list(target_names)[:20]}', sub='guardrail')
			if target_names:
				rule = f"target({','.join(target_names)})"
				self.debug(f'[workspace] auto-approve: {rule}', sub='guardrail')
				self.permission_engine.add_runtime_allow([rule])
		except Exception as e:
			self.debug(f'[workspace] failed to query targets: {e}', sub='guardrail')

	# -------------------------------------------------------------------------
	# Summarization / compaction
	# -------------------------------------------------------------------------

	def _summarize_auto(self):
		"""Auto-compact history when context exceeds 85% threshold."""
		self.debug('checking auto-compaction...', sub='context')
		summarized, old_tokens, new_tokens = self.history.maybe_summarize(
			self.model, api_base=self.api_base, api_key=self.api_key)
		if summarized:
			self.debug(f'compacted: {old_tokens} -> {new_tokens} tokens', sub='context')
			yield Ai(
				content=f"Chat history compacted: {old_tokens} -> {new_tokens} estimated tokens",
				ai_type="chat_compacted",
			)

	def _summarize_user(self):
		"""Prompt user when context is filling up (local interactive only)."""
		if self.interactive != "local" or not self.context_warnings:
			return
		ctx_window = get_context_window(self.model)
		if ctx_window <= 0:
			return
		from secator.ai.history import OUTPUT_TOKEN_RESERVATION
		by_role = self.history.count_tokens_by_role(self.model)
		token_count = by_role["total"]
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
						yield Ai(
							content=f"Chat history compacted: {token_count} -> {new_tokens} tokens",
							ai_type="chat_compacted",
						)
				break

	# -------------------------------------------------------------------------
	# Tool call processing
	# -------------------------------------------------------------------------

	def _process_tool_calls(self, tool_calls, ctx):
		"""Parse, validate, and guardrails-check tool calls from LLM response.

		Generator: yields Warning items and pending Ai prompts (for remote).
		Returns list of validated action dicts via generator return.
		Use: actions = yield from self._process_tool_calls(tool_calls, ctx)
		"""
		actions = []

		for tc in tool_calls:
			name = tc.function.name
			tc_id = tc.id
			args = tc.function.arguments

			# Parse JSON arguments
			if isinstance(args, str):
				try:
					args = json.loads(tc.function.arguments)
				except (json.JSONDecodeError, TypeError) as e:
					self.debug(f'[tool_call] {name}: failed to parse: {tc.function.arguments[:200]}', sub='llm')
					schema = TOOL_SCHEMAS.get(name, {}).get("function", {})
					properties = schema.get("parameters", {}).get("properties", {})
					error_msg = json.dumps({
						"error": f"Tool call '{tc_id}' rejected: malformed JSON arguments ({e})",
						"raw_arguments": tc.function.arguments[:200],
						"expected_schema": {k: v.get("type", "any") for k, v in properties.items()},
						"hint": "Retry with properly formatted JSON arguments.",
					}, separators=(',', ':'))
					self.history.add_tool_result(name, tc_id, maybe_encrypt(error_msg, self.encryptor))
					continue

			# Decrypt args
			if self.encryptor:
				args = _decrypt_dict(args, self.encryptor)

			# Convert to action
			self.debug(f'[tool_call] {name} id={tc_id} args={args}', sub='llm')
			action = tool_call_to_action(name, args)
			if not action:
				reason = "empty arguments" if not args else f"unknown tool '{name}'"
				self.debug(f'[tool_call] skipping {name}: {reason}', sub='llm')
				schema = TOOL_SCHEMAS.get(name, {}).get("function", {})
				params = schema.get("parameters", {})
				error_msg = json.dumps({
					"error": f"Tool call '{tc_id}' rejected: {reason}",
					"required_fields": params.get("required", []),
					"schema": {k: v.get("type", "any") for k, v in params.get("properties", {}).items()},
					"hint": "Provide all required fields. Retry with a complete arguments object.",
				}, separators=(',', ':'))
				self.history.add_tool_result(name, tc_id, maybe_encrypt(error_msg, self.encryptor))
				continue

			action["tool_call_id"] = tc_id
			action["tool_call_name"] = name

			# Guardrails check (generator: yields warnings + pending Ai prompts)
			if self.dangerous:
				denial = None
			else:
				denial = yield from check_guardrails(action, ctx)

			act_desc = args.get("command") or args.get("name") or args.get("query")
			self.debug(f'[guardrails] {name}({act_desc}) => {"denied" if denial else "ok"}', sub='guardrail')

			if denial:
				cmd_display = _build_action_display(action)
				denial_display = f"{denial}\n[gray42]{cmd_display}[/gray42]" if cmd_display else denial
				yield Warning(message=denial_display)
				error_msg = json.dumps({"error": denial}, separators=(',', ':'))
				self.history.add_tool_result(name, tc_id, maybe_encrypt(error_msg, self.encryptor))
				continue

			actions.append(action)

		self.debug(f'actions (parsed): {json.dumps(actions, indent=2)}', sub='llm')
		return actions

	# -------------------------------------------------------------------------
	# Dispatch and collect results
	# -------------------------------------------------------------------------

	def _dispatch_and_collect(self, actions, ctx):
		"""Dispatch actions, yield results, add to history.

		Yields OutputType items. Returns dict with follow_up_choices, stop_reason, follow_up_ai.
		Use: result = yield from self._dispatch_and_collect(actions, ctx)
		"""
		follow_up_choices = None
		stop_reason = None
		follow_up_ai = None

		is_batch = len(actions) > 1
		action_iter = _run_batch(actions, ctx) if is_batch else dispatch_action(actions[0], ctx)

		collected = []
		for result in action_iter:
			# Skip execution-only types
			if isinstance(result, (Stat, Progress, State, Info)):
				continue

			is_from_subagent = isinstance(result, OutputType) and bool(result._context.get('subagent'))

			if isinstance(result, Ai):
				self.add_result(result, print=not is_from_subagent)
				if result.ai_type == "follow_up":
					follow_up_ai = result
					follow_up_choices = result.choices or (result.extra_data or {}).get("choices", [])
					continue
				elif result.ai_type == "stopped":
					stop_reason = result.content
					continue
				if result.ai_type not in ("shell_output", "response"):
					continue
			elif isinstance(result, OutputType):
				self.add_result(result, print=not is_from_subagent)

			# Yield live to caller
			yield result

			result = result.toDict() if isinstance(result, OutputType) else result
			collected.append(result)
			ctx.results.append(result)

		# Group results by tool_call_id and add to history
		budget = self.history.get_action_budget(self.model)
		fallback_path = Path(self.reports_folder) / "report.json" if self.reports_folder else None
		for tc_id, group in groupby(collected, key=lambda r: r["_context"]['tool_call_id']):
			group_results = list(group)
			tc_name = group_results[0]["_context"]['tool_call_name']
			has_errors = any(r["_type"] == "error" for r in group_results)
			serialized = [
				{k: v for k, v in r.items() if k not in INTERNAL_FIELDS}
				for r in group_results
			]
			tool_result_str = format_tool_result(
				tc_name, "error" if has_errors else "success",
				len(serialized), serialized)
			tool_result_str = truncate_to_tokens(
				tool_result_str, budget, self.model, fallback_path=fallback_path)
			tool_result_str = maybe_encrypt(tool_result_str, self.encryptor)
			self.history.add_tool_result(tc_name, tc_id, tool_result_str)

		return {"follow_up_choices": follow_up_choices, "stop_reason": stop_reason, "follow_up_ai": follow_up_ai}

	# -------------------------------------------------------------------------
	# History helpers
	# -------------------------------------------------------------------------

	def _add_assistant_to_history(self, content, tool_calls):
		"""Add assistant message (with optional tool calls) to chat history."""
		if tool_calls:
			litellm_tool_calls = [{
				"id": tc.id,
				"type": "function",
				"function": {
					"name": tc.function.name,
					"arguments": (tc.function.arguments if isinstance(tc.function.arguments, str)
					else json.dumps(tc.function.arguments)),
				},
			} for tc in tool_calls]
			self.history.add_assistant_with_tool_calls(
				maybe_encrypt(content, self.encryptor) if content else None,
				litellm_tool_calls)
		else:
			self.history.add_assistant(maybe_encrypt(content, self.encryptor))

	# -------------------------------------------------------------------------
	# Follow-up / prompt
	# -------------------------------------------------------------------------

	def _prompt_and_redetect(self, choices):
		"""Prompt user via backend and re-detect intent.

		Works for all backends: CLIBackend shows rich menus, RemoteBackend
		polls DB, AutoBackend returns None (exits).

		Returns list of items to yield, or None to exit.
		"""
		response = self.backend.ask_user(
			question="What's next?",
			choices=choices,
			session_id=self.session_id,
			prompt_type="follow_up",
			history=self.history,
			encryptor=self.encryptor,
			max_iterations=self.max_iterations,
			mode=self.mode,
			model=self.model,
		)
		if response is None:
			return None

		answer = response["answer"]
		extra_iters = response.get("extra_iters", 1)
		self.prompt = answer
		items = []

		# Add to history
		self.history.add_user(maybe_encrypt(answer, self.encryptor))

		# Handle explicit mode switch (e.g. summarize → chat)
		if response.get("switch_mode"):
			self.mode = response["switch_mode"]
			self.system_prompt = get_system_prompt(self.mode, workspace_path=str(self.reports_folder), backend=self.backend)
			self.tool_schemas = build_tool_schemas(self.mode, is_subagent=self.is_subagent, backend=self.backend)
			self.history.set_system(maybe_encrypt(self.system_prompt, self.encryptor))
			self.max_iterations += extra_iters
			items.append(Info(message=f"Switched to {self.mode} mode"))
		else:
			# Re-detect mode (user may switch from chat to attack, etc.)
			previous_mode = self.mode
			self._detect_mode(force=True)
			self.max_iterations += extra_iters
			if self.mode != previous_mode:
				self.history.set_system(maybe_encrypt(self.system_prompt, self.encryptor))
				items.append(Info(message=f"Switched to {self.mode} mode"))

		# Token breakdown for prompt display
		by_role = self.history.count_tokens_by_role(self.model)
		extra_data = {"tokens": by_role["total"], "context_window": get_context_window(self.model), "by_role": by_role}
		items.append(Ai(content=answer, ai_type="prompt", extra_data=extra_data))
		return items

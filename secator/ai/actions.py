"""Action handlers for AI task."""
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, fields
from typing import Any, Dict, Generator, List, Optional, Tuple

from secator.runners import Task, Workflow
from secator.runners.task import TaskNotFoundError
from secator.output_types import Ai, Error, Info, Warning, OutputType, FINDING_TYPES
from secator.template import TemplateLoader
from secator.utils import format_token_count
from secator.ai.utils import (
	_sanitized_env, _build_action_display, _is_approved, _truncate, _format_action_error,
	_is_heavy_runner, _sanitize_child_opts, build_subagent_prompt, _union_live_results,
	_coerce_finding_fields, _get_action_label, _decrypt_dict,
)
from secator.ai.utils import _MAX_CHILD_ITERATIONS  # noqa: F401 - re-exported for tests importing it from actions


# Bound recursive AI-subagent fan-out so injected output can't drive an
# exponential subagent/token blow-up. Depth caps recursion (child inherits +1 via
# context); breadth caps how many subagents one parent turn may spawn.
_MAX_SUBAGENT_DEPTH = 3
_MAX_SUBAGENTS_PER_TURN = 5
_SUBAGENT_TURN_LOCK = threading.Lock()

# Cap shell stdout before it enters AI history so a huge command can't blow up
# the next prompt's token budget; head+tail keeps both the start and the result.
_MAX_SHELL_OUTPUT_CHARS = 4000

# Cap on ad-hoc AI shell commands (dispatched as the `command` task). Applied as an
# instance attribute post-construction (see _handle_shell) since max_timeout is not a
# run_opts-settable field.
_SHELL_TIMEOUT = 60


@dataclass
class ActionContext:
	"""Shared context for action execution.

	Attributes:
		targets: List of target hosts/URLs
		model: LLM model name
		encryptor: Optional SensitiveDataEncryptor instance
		dry_run: If True, show actions without executing
		context: Runner context dict (drivers, workspace_id, scan_id, etc.)
	"""
	targets: List[str]
	model: str
	api_key: str = ""
	api_base: str = ""
	encryptor: Any = None
	dry_run: bool = False
	verbose: bool = False
	context: Dict = field(default_factory=dict)
	scope: str = "workspace"
	results: Optional[List[Dict]] = None
	max_workers: int = 3
	in_batch: bool = False  # set on the per-batch ctx so the per-turn fan-out cap applies
	subagent: bool = False
	silent: bool = False
	sync: bool = True
	interactive: Any = "local"  # "local", "remote", "auto", or bool (legacy)
	backend: Any = field(default=None, repr=False)
	session_id: str = ""
	_query_engine: Any = field(default=None, repr=False)
	permission_engine: Any = field(default=None, repr=False)

	def get_query_engine(self):
		"""Get or create a QueryEngine (cached for reuse across queries)."""
		if self._query_engine is None:
			from secator.query import QueryEngine
			if self.scope == "current":
				query_context = {"results": self.results or []}
			else:
				query_context = dict(self.context)
			self._query_engine = QueryEngine(self.context.get("workspace_id", ""), context=query_context)
		return self._query_engine


def _build_hooks_from_context(context: Dict) -> Dict:
	"""Build the runner hooks dict from ``context['drivers']``.

	Sub-runners dispatched by the ai task are constructed in-process and run
	synchronously, so the framework's pickle path (``__setstate__``, which
	re-registers driver hooks from ``context['drivers']``) never runs for them.
	Without this, a sub-runner inherits the ai task's ``workspace_id`` /
	``drivers`` in its context but registers *no* driver hooks — so its
	``mongodb``/``api`` ``update_runner``/``update_finding`` hooks never fire and
	its runner doc + findings are never persisted to the workspace. The result:
	sub-runs are absent from the workspace History.

	This mirrors the normal CLI entrypoint (``cli_helper._run``): import each
	driver's ``secator.hooks.<driver>.HOOKS`` and ``deep_merge_dicts`` them into a
	single class-keyed dict (keyed by ``Scan``/``Workflow``/``Task``). The dict is
	returned raw (not flattened) because ``Task``/``Workflow`` forward
	``self._hooks.get(Task, {})`` down to their command/task signatures.

	Args:
		context: Runner context dict (expects ``drivers`` list).

	Returns:
		dict: Merged hooks dict suitable for ``runner_cls(..., hooks=hooks)``.
	"""
	from secator.loader import discover_external_drivers, get_available_drivers, order_drivers
	from secator.utils import import_dynamic, deep_merge_dicts

	drivers = list(context.get('drivers', []))
	if not drivers:
		return {}
	discover_external_drivers()
	# Order by canonical priority so authoritative backends (e.g. mongodb) register
	# their hooks before relay drivers (e.g. api) — same ordering as __setstate__.
	drivers = order_drivers(drivers)
	supported = set(get_available_drivers())
	hooks_list = []
	for driver in drivers:
		if driver not in supported:
			continue
		driver_hooks = import_dynamic(f'secator.hooks.{driver}', 'HOOKS')
		if driver_hooks:
			hooks_list.append(driver_hooks)
	if not hooks_list:
		return {}
	return deep_merge_dicts(*hooks_list)


def _build_child_hooks_or_denial(context: Dict) -> Tuple[Dict, Optional["Warning"]]:
	"""Rebuild the child's persistence hooks, refusing a persistence-less child.

	``context`` carries the parent's ``drivers`` (copied via ``_get_result_context``),
	so an empty/failed rebuild while the parent HAS drivers means the child would run
	to completion and silently persist nothing (lost findings/docs). In that case
	return a denial ``Warning`` (same shape other denials use) so the caller yields it
	and skips the spawn. When the parent itself has no drivers (pure local/no-persistence
	run) an empty-hooks child is expected and allowed.

	Returns ``(hooks, denial)``; if ``denial`` is non-None the caller must not spawn.
	"""
	parent_has_drivers = bool(context.get('drivers'))
	try:
		hooks = _build_hooks_from_context(context)
	except Exception as e:  # narrow to the rebuild — surface, don't degrade to hooks={}
		if parent_has_drivers:
			return {}, Warning(
				message=f"Subagent spawn denied: persistence hook rebuild failed — {type(e).__name__}: {e}",
				_context=context,
			)
		return {}, None
	if parent_has_drivers and not hooks:
		return {}, Warning(
			message="Subagent spawn denied: parent has persistence drivers but child hook rebuild "
				"was empty (would silently drop findings/docs)",  # noqa: E131
			_context=context,
		)
	return hooks, None


def check_guardrails_sync(action: Dict, ctx: ActionContext) -> Tuple[Optional[str], List]:
	"""Non-generator wrapper for check_guardrails.

	Collects yielded items (warnings, pending prompts) and returns (denial, items).
	Use from non-generator callers (tests, simple scripts).
	"""
	gen = check_guardrails(action, ctx)
	items = []
	try:
		while True:
			items.append(next(gen))
	except StopIteration as e:
		return e.value, items


def check_guardrails(action: Dict, ctx: ActionContext):
	"""Check action against guardrails before dispatching.

	Generator that yields Warning and pending Ai items (for remote backends).
	Returns denial_reason (str or None) via generator return.

	Use from generators: denial = yield from check_guardrails(action, ctx)
	Use from regular code: denial, items = check_guardrails_sync(action, ctx)
	"""
	from secator.ai.interactivity import RemoteBackend
	from secator.output_types import Warning as Warn

	if ctx.permission_engine is None:
		return None

	# Check for non-existent file paths (warn but don't block)
	from secator.ai.guardrails import detect_paths, detect_paths_with_access, classify_command
	from pathlib import Path
	action_type = action.get("action", "")
	if action_type == "shell":
		cmd = action.get("command", "")
		cmd_name = cmd.split()[0] if cmd.split() else ""
		cmd_class = classify_command(cmd_name)
		if cmd_class == "read":
			for path in detect_paths(cmd):
				if any(c in path for c in ('*', '?', '[', ']')):
					continue
				try:
					expanded = Path(path).expanduser()
					if not expanded.exists():
						yield Warn(message=f"Path does not exist: {path}")
				except (OSError, ValueError):
					pass

	result = ctx.permission_engine.check_action(action)
	if result.decision == "deny":
		return f"Action denied by guardrails: {result.reason}"

	is_remote = isinstance(ctx.backend, RemoteBackend)

	# Prompt loop: check_action returns the first unresolved "ask" layer (shell, then
	# targets, then paths); prompt via ctx.backend.ask_user() and re-check until resolved.
	max_rounds = 5
	rounds = 0
	while result.decision == "ask" and rounds < max_rounds:
		rounds += 1
		cmd_display = _build_action_display(action)

		# Handle shell command prompts (unknown commands or parse failures)
		if result.shell_command:
			parse_failed = "Could not parse" in (result.reason or "")
			ask_kwargs = dict(
				question=result.reason or "Shell command requires approval",
				choices=["allow", "allow_all", "deny"],
				session_id=ctx.session_id,
				prompt_type="permission",
				permission_type="shell",
				value=result.shell_command,
				reason=result.reason,
				engine=ctx.permission_engine,
				# unique id per prompt so its remote poll matches only its own answer
				prompt_uuid=str(uuid.uuid4()),
			)
			if is_remote:
				yield ctx.backend.build_pending_prompt(**ask_kwargs)
			response = ctx.backend.ask_user(**ask_kwargs) if ctx.backend else None
			if not _is_approved(response):
				return "Action denied: shell command not approved"
			if parse_failed:
				return None

		# Handle target prompts
		for target in result.targets:
			recheck = ctx.permission_engine._check_value("target", target)
			if recheck.decision == "allow":
				continue
			ask_kwargs = dict(
				question=f"Target {target} requires approval",
				choices=["allow", "allow_all", "deny"],
				session_id=ctx.session_id,
				prompt_type="permission",
				permission_type="target",
				value=target,
				command=cmd_display,
				engine=ctx.permission_engine,
				prompt_uuid=str(uuid.uuid4()),
			)
			if is_remote:
				yield ctx.backend.build_pending_prompt(**ask_kwargs)
			response = ctx.backend.ask_user(**ask_kwargs) if ctx.backend else None
			if not _is_approved(response):
				return f"Action denied: target {target} not approved"

		# Handle path prompts
		if result.paths:
			cmd = action.get("command", "")
			path_access_map = {p: a for p, a in detect_paths_with_access(cmd)}
			for path in result.paths:
				access_type = path_access_map.get(path, "read")
				ask_kwargs = dict(
					question=f"{access_type.capitalize()} access to {path} requires approval",
					choices=["allow", "allow_all", "deny"],
					session_id=ctx.session_id,
					prompt_type="permission",
					permission_type=access_type,
					value=path,
					command=cmd_display,
					engine=ctx.permission_engine,
					prompt_uuid=str(uuid.uuid4()),
				)
				if is_remote:
					yield ctx.backend.build_pending_prompt(**ask_kwargs)
				response = ctx.backend.ask_user(**ask_kwargs) if ctx.backend else None
				if not _is_approved(response):
					return f"Action denied: {access_type} access to {path} not approved"

		# Re-check to see if more layers need prompting
		result = ctx.permission_engine.check_action(action)
		if result.decision == "deny":
			return f"Action denied after prompt: {result.reason}"

	# fail closed: prompts exhausted with the decision still unresolved -> block
	if result.decision == "ask":
		return f"Action denied: guardrail check unresolved after {max_rounds} prompts"

	return None


def dispatch_action(action: Dict, ctx: ActionContext) -> Generator:
	"""Route action to appropriate handler.

	Args:
		action: Action dict with 'action' key and parameters
		ctx: Shared action context

	Yields:
		OutputType instances (Info, Warning, Error, Ai)
	"""
	action_type = action.get("action", "")

	handlers = {
		"task": _handle_task,
		"workflow": _handle_workflow,
		"shell": _handle_shell,
		"query": _handle_query,
		"follow_up": _handle_follow_up,
		"add_finding": _handle_add_finding,
		"stop": _handle_stop,
	}

	handler = handlers.get(action_type)
	if handler:
		yield from handler(action, ctx)
	else:
		context = _get_result_context(action, ctx)
		yield Warning(message=f"Unknown action: {action_type}", _context=context)


def safe_dispatch_action(action: Dict, ctx: ActionContext) -> Generator:
	"""Dispatch a single action, converting any raised ``Exception`` into an
	``Error`` output item instead of letting it abort the AI loop.

	A Python error during a handler (e.g. ``TypeError: 'str' object is not a
	mapping`` from a malformed LLM action/opts) must NOT kill the main loop. We
	wrap the per-action generator so the failure becomes an ``Error`` carrying
	the action's ``tool_call_id``/``tool_call_name`` in ``_context`` — that lets
	the caller group it into a tool result and feed the error back to the LLM so
	it can correct itself on the next turn.

	Only ``Exception`` is caught: ``KeyboardInterrupt`` / ``SystemExit`` /
	``GeneratorExit`` (all ``BaseException`` subclasses) propagate so legitimate
	control-flow and generator close are never swallowed.
	"""
	import traceback as _traceback
	try:
		yield from dispatch_action(action, ctx)
	except Exception as e:  # noqa: BLE001 - per-action resilience: feed error back to LLM, never abort the loop
		context = _get_result_context(action, ctx)
		yield Error(
			message=_format_action_error(e),
			traceback=_traceback.format_exc(),
			_context=context,
		)


def _guard_subagent_fanout(ctx: "ActionContext", context: Dict) -> Optional["Warning"]:
	"""Cap AI-subagent recursion depth + per-turn fan-out.

	Returns a denial ``Warning`` if a cap is hit (caller yields it and skips the
	spawn); otherwise stamps the child's depth (+1) into ``context`` and bumps the
	per-turn counter. Breadth is only counted within a batch (one LLM turn); a
	lone spawn is inherently breadth-1.
	"""
	depth = int(ctx.context.get("ai_subagent_depth", 0) or 0)
	if depth >= _MAX_SUBAGENT_DEPTH:
		return Warning(
			message=f"Subagent spawn denied: recursion depth cap ({_MAX_SUBAGENT_DEPTH}) reached",
			_context=context,
		)
	if ctx.in_batch:  # per-turn breadth only bites within a batch
		with _SUBAGENT_TURN_LOCK:
			turn = int(ctx.context.get("ai_subagent_turn_count", 0) or 0)
			over_breadth = turn >= _MAX_SUBAGENTS_PER_TURN
			if not over_breadth:
				ctx.context["ai_subagent_turn_count"] = turn + 1
		if over_breadth:
			return Warning(
				message=f"Subagent spawn denied: per-turn fan-out cap ({_MAX_SUBAGENTS_PER_TURN}) reached",
				_context=context,
			)
	context["ai_subagent_depth"] = depth + 1  # child inherits depth+1
	return None


def _gather_subagent_evidence(ctx: "ActionContext", targets: list, limit: int = 40) -> str:
	"""Auto-assemble prior findings for the subagent's targets so it doesn't redo work.

	Queries the workspace (the single source of truth — incl. this run's live findings)
	for findings whose host/ip/url match any target, capped at `limit`. Best-effort:
	any failure returns "" (evidence is a nicety, never a blocker).
	"""
	targets = [t for t in (targets or []) if t]
	if not targets:
		return ""
	query = {"$or": [{"host": {"$in": targets}}, {"ip": {"$in": targets}}, {"url": {"$in": targets}}]}
	try:
		results = ctx.get_query_engine().search(query, limit=limit) or []
	except Exception:  # noqa: BLE001 - evidence is best-effort; never break the spawn
		return ""
	lines = []
	for r in results[:limit]:
		d = r.toDict() if hasattr(r, "toDict") else r
		t = d.get("_type", "finding")
		key = d.get("url") or d.get("matched_at") or f"{d.get('ip', '') or d.get('host', '')}"
		extra = f":{d.get('port')}" if d.get("port") else ""
		name = f" {d.get('name')}" if d.get("name") else ""
		lines.append(f"- {t} {key}{extra}{name}".rstrip())
	return "\n".join(lines)


def _run_runner(action: Dict, ctx: ActionContext, runner_type: str) -> Generator:
	"""Execute a secator task or workflow.

	Args:
		action: Action dict with name, targets, opts
		ctx: Action context
		runner_type: Either "task" or "workflow"
	"""
	name = action.get("name", "")
	targets = action.get("targets", ctx.targets)
	# drop LLM-set control keys (notably `dangerous`) before they reach the child
	opts = _sanitize_child_opts(action.get("opts", {}))
	context = _get_result_context(action, ctx)

	# Force subagent flags when spawning an AI task from a parent AI task
	if runner_type == "task" and name.lower() == "ai":
		# Bound recursive fan-out before constructing/running the child
		denial = _guard_subagent_fanout(ctx, context)
		if denial is not None:
			yield denial
			return
		opts["subagent"] = True
		opts["interactive"] = False
		# Inherit the parent's resolved LLM config (else it falls back to the default
		# model/provider with no key set -> AuthenticationError). setdefault so an
		# explicit LLM-supplied model/key still wins.
		opts.setdefault("model", ctx.model)
		if ctx.api_key:
			opts.setdefault("api_key", ctx.api_key)
		if ctx.api_base:
			opts.setdefault("api_base", ctx.api_base)
		# 1.b/1.c: structure the subagent's prompt and inject prior findings for its
		# scope so it doesn't re-run work already done.
		_objective = opts.get("prompt", "")
		opts["prompt"] = build_subagent_prompt(_objective, targets, _gather_subagent_evidence(ctx, targets))

	# defense in depth: a spawned runner is never dangerous (CLI --dangerous unaffected)
	opts["dangerous"] = False

	if runner_type == "task":
		tpl = TemplateLoader(input={'type': 'task', 'name': name})
		runner_cls = Task
	else:
		tpl = TemplateLoader(name=f'workflows/{name}')
		runner_cls = Workflow

	# Decrypt targets
	if ctx.encryptor:
		targets = [ctx.encryptor.decrypt(str(t)) for t in targets]

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run {runner_type}: {name} on {targets}", _context=context)
		return

	run_opts = {
		"print_item": not ctx.silent,
		"print_line": ctx.verbose and not ctx.silent,
		"print_cmd": not ctx.silent and not ctx.subagent,
		"print_cmd_icon": "└",
		"print_progress": False,
		"print_reports_message": False,
		"enable_reports": True,
		"exporters": [],
		"sync": ctx.sync,
		"tty": not ctx.subagent and ctx.sync,
		**opts,
	}
	if runner_type == "workflow":
		run_opts["print_start"] = not ctx.silent and not ctx.subagent
		run_opts["print_end"] = not ctx.silent and not ctx.subagent

	# A heavy sub-task (e.g. nuclei) must not run sync in the ai task's small worker
	# pool (OOM risk) — dispatch it async to its own profile's queue when in a worker.
	if run_opts.get("sync") and _is_heavy_runner(runner_type, name, opts):
		from secator.celery import IN_WORKER
		if IN_WORKER:
			run_opts["sync"] = False
			run_opts["tty"] = False

	context["task_chunk_id"] = str(uuid.uuid4())
	if ctx.subagent:
		context["subagent"] = ctx.context.get("subagent", True)

	# Propagate driver hooks (mongodb/api): a sync sub-runner skips the pickle path
	# that normally re-registers them, so without this its results never persist.
	# Don't silently spawn a persistence-less child when the parent has drivers
	hooks, denial = _build_child_hooks_or_denial(context)
	if denial is not None:
		yield denial
		return
	try:
		runner = runner_cls(tpl, targets, run_opts=run_opts, hooks=hooks, context=context)
	except TaskNotFoundError as e:
		yield Error(message=str(e), _context=context)
		return

	# Emit the action Ai item now the runner exists (on_init stamped the runner id) so
	# the UI can render a RunnerCard; always emitted, even when silent. Prefer context
	# `{type}_id` (the persisted doc's `_id`) over `runner.id` (internal, doesn't match).
	runner_id = context.get(f"{runner_type}_id", "") or runner.id
	yield Ai(
		content=name,
		ai_type=runner_type,
		extra_data={
			"targets": targets,
			"opts": opts,
			"runner_id": runner_id,
			"runner_type": runner_type,
		},
		_context=context,
	)

	yield from runner

	# Auto-allow reading from the spawned runner's reports folder
	if ctx.permission_engine and hasattr(runner, 'reports_folder') and runner.reports_folder:
		reports_path = str(runner.reports_folder)
		ctx.permission_engine.add_runtime_allow([f"read({reports_path}/*)", f"read({reports_path})"])


def _get_result_context(action, ctx):
	"""Build the CHILD runner's context.

	Stamps the conversation ``session_id`` (parenting link — see the runner-parenting
	design) and marks the child ``has_parent``. Critically, it STRIPS the parent's
	runner-identity keys (`task_id`/`workflow_id`/`scan_id`): a child that inherited
	them would make `update_runner`/`runner_id` target the PARENT's doc instead of
	minting its own. The child keeps drivers/workspace so it persists into the same
	workspace, linked to the conversation by ``session_id``.
	"""
	new_ctx = ctx.context.copy()
	for identity_key in ("task_id", "workflow_id", "scan_id", "task_chunk_id"):
		new_ctx.pop(identity_key, None)
	if ctx.session_id and not new_ctx.get("session_id"):
		new_ctx["session_id"] = ctx.session_id
	new_ctx["has_parent"] = True
	action_context = {}
	tool_call_id = action.get("tool_call_id")
	tool_call_name = action.get("tool_call_name")
	if tool_call_id:
		action_context["tool_call_id"] = tool_call_id
		action_context["tool_call_name"] = tool_call_name
	return {**new_ctx, **action_context}


def _handle_task(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator task."""
	yield from _run_runner(action, ctx, "task")


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator workflow."""
	yield from _run_runner(action, ctx, "workflow")


def _handle_shell(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a shell command as a `command` task runner.

	Dispatches the built-in `command` task (a Command subclass that runs an arbitrary
	shell command line verbatim) through the normal runner lifecycle, instead of a raw
	`subprocess.run`. This makes the shell invocation persist as a runner doc (via the
	driver hooks rebuilt from `context['drivers']`) and appear in history, parented
	under the conversation via `context['session_id']` — exactly like `_run_runner`
	does for AI-spawned tasks/workflows.

	Args:
		action: Action dict with command
		ctx: Action context
	"""
	command = action.get("command", "")
	context = _get_result_context(action, ctx)

	if ctx.encryptor:
		command = ctx.encryptor.decrypt(command)

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run: {command}", _context=context)
		return

	try:
		context["task_chunk_id"] = str(uuid.uuid4())
		if ctx.subagent:
			context["subagent"] = ctx.context.get("subagent", True)

		# Don't silently run a persistence-less child when the parent has drivers
		# (same guard _run_runner uses for spawned tasks/workflows).
		hooks, denial = _build_child_hooks_or_denial(context)
		if denial is not None:
			yield denial
			return

		# hooks is CLASS-keyed ({Task: {...}}); we bypass the Task wrapper with a direct
		# `command(...)` instantiation, so extract hooks[Task] ourselves — else register_hooks
		# finds no match and the runner doc is silently never persisted (no error, no doc).
		hooks = hooks.get(Task, {})

		# Mirrors _run_runner's wiring: quiet, reports enabled, never dangerous (defense
		# in depth). `env` is the sanitized process env so `env`/`printenv` can't leak secrets.
		run_opts = {
			"print_item": not ctx.silent,
			"print_line": ctx.verbose and not ctx.silent,
			"print_cmd": False,
			"print_progress": False,
			"print_reports_message": False,
			"enable_reports": True,
			"exporters": [],
			"sync": ctx.sync,
			"dangerous": False,
			"env": _sanitized_env(),
		}

		# Instantiate `command` directly (bypasses the Task wrapper, which discards `.output`)
		# so stdout survives while persist hooks still fire. Spread **run_opts, not `run_opts=`
		# (would nest and drop `env`); import locally to avoid a circular import.
		from secator.tasks.command import command as CommandTask
		runner = CommandTask([command], hooks=hooks, context=context, **run_opts)

		# 60s cap on ad-hoc AI shell commands. max_timeout is NOT run_opts-settable
		# (Command.__init__ resolves it from CONFIG.tasks.overrides); setting the
		# instance attribute here is honored by get_max_timeout().
		runner.max_timeout = _SHELL_TIMEOUT

		# Emit the command Ai now that the runner exists: its on_init hook has
		# stamped the runner id into context, so the UI can link this item to the
		# persisted runner doc (mirrors _run_runner:688-699).
		yield Ai(
			content=command,
			ai_type="shell",
			extra_data={
				"runner_id": context.get("task_id", "") or runner.id,
				"runner_type": "task",
			},
			_context=context,
		)

		# Run to completion in-process (fires persist hooks like a normal task/workflow).
		# Do NOT `yield from runner` — raw stdout lines aren't separate transcript items;
		# the single shell_output below is the contract.
		runner.run()

		output = _truncate(runner.output or "(no output)", _MAX_SHELL_OUTPUT_CHARS)  # cap so it can't blow up history
		yield Ai(content=output, ai_type="shell_output", _context=context)

	except Exception as e:
		yield Error(message=f"Shell command failed: {e}", _context=context)


def _handle_query(action: Dict, ctx: ActionContext) -> Generator:
	"""Query workspace or current results for findings.

	Args:
		action: Action dict with query (MongoDB query dict)
		ctx: Action context (scope='current' passes results to QueryEngine in-memory)
	"""
	context = _get_result_context(action, ctx)
	query_filter = action.get("query", {})
	# The schema declares `limit` an integer, but some models send it as a string
	# ("10"); a str limit reaches the backend and raises `'>=' not supported between
	# int and str`. Coerce to int (bad/None values fall back to the default).
	limit = action.get("limit", 100)
	try:
		limit = int(limit)
	except (TypeError, ValueError):
		limit = 100

	# Some providers serialize `query` as a JSON string despite the object schema
	# (known tool-calling quirk); coerce it back, else fail with a clear LLM error.
	if isinstance(query_filter, str):
		try:
			query_filter = json.loads(query_filter)
		except (json.JSONDecodeError, TypeError):
			yield Error(
				message='query must be a JSON object (e.g. {"_type": "vulnerability"}); '
				f'got an unparseable string: {query_filter[:120]!r}',
				_context=context,
			)
			return
	if not isinstance(query_filter, dict):
		yield Error(
			message=f'query must be a JSON object; got {type(query_filter).__name__}.',
			_context=context,
		)
		return

	# Decrypt query values
	if ctx.encryptor:
		query_filter = _decrypt_dict(query_filter, ctx.encryptor)

	engine = ctx.get_query_engine()
	is_local = getattr(engine.backend, "name", "") == "json"

	# A non-local backend (mongodb/api) needs a workspace to query. The local (json)
	# driver can always answer from this run's in-memory findings (unioned below), so
	# it is exempt from the workspace_id requirement.
	if not is_local and ctx.scope != "current" and not ctx.context.get("workspace_id"):
		yield Warning(message="No workspace available for query", _context=context)
		return

	try:
		query_str = json.dumps(query_filter, separators=(',', ':'))
		results = engine.search(query_filter, limit=limit)
		# Local driver only writes to disk at end-of-run, so union in-memory live results
		# to make query_workspace the source of truth (mongodb/api persist live already).
		if is_local and ctx.scope != "current":
			results = _union_live_results(results, ctx.results or [], query_filter, limit)
		yield Ai(
			content=query_str,
			ai_type="query",
			extra_data={"results": len(results), "limit": limit},
			_context=context
		)
		for result in results:
			if isinstance(result, OutputType):
				result = result.toDict()
			result["_context"].update(context)
			# Query results are existing workspace findings surfaced for the AI's
			# observation only — mark them so the runner doesn't re-yield/re-report
			# them (which would duplicate them back into the workspace).
			result.setdefault("_context", {})["ai_query_result"] = True
			yield result

	except Exception as e:
		yield Ai(
			content=str(query_filter),
			ai_type="query",
			extra_data={"results": "failed", "limit": limit},
			_context=context
		)
		yield Error.from_exception(e, _context=context)


def _handle_follow_up(action: Dict, ctx: ActionContext) -> Generator:
	"""Handle follow-up with user.

	Args:
		action: Action dict with reason and optional choices
		ctx: Action context
	"""
	context = _get_result_context(action, ctx)
	reason = action.get("reason", "completed")
	choices = action.get("choices", [])
	# Store choices on the top-level `choices` field (what the web UI reads) AND in
	# extra_data (back-compat). Without the top-level field, the persisted follow-up
	# doc has `choices: []` and the UI renders no choice buttons.
	yield Ai(content=reason, ai_type="follow_up", choices=choices, extra_data={"choices": choices}, _context=context)


def _handle_stop(action: Dict, ctx: ActionContext) -> Generator:
	"""Handle stop action - signals session completion."""
	context = _get_result_context(action, ctx)
	reason = action.get("reason", "completed")
	yield Ai(content=reason, ai_type="stopped", _context=context)


def _handle_add_finding(action: Dict, ctx: ActionContext) -> Generator:
	"""Create a secator finding from LLM-provided data.

	Args:
		action: Action dict with _type and finding fields
		ctx: Action context
	"""
	context = _get_result_context(action, ctx)

	finding_type = action.get("_type", "")
	finding_data = {k: v for k, v in action.items() if k not in ("action", "_type", "tool_call_id", "tool_call_name")}
	finding_data["_context"] = context

	# Decrypt field values
	if ctx.encryptor:
		finding_data = _decrypt_dict(finding_data, ctx.encryptor)

	# Resolve _type string to OutputType class
	type_map = {cls.get_name(): cls for cls in FINDING_TYPES}
	cls = type_map.get(finding_type)
	if not cls:
		yield Warning(message=f"Unknown finding type: {finding_type}", _context=context)
		return

	# Deserialize JSON strings that should be dicts/lists
	# (LLMs often send structured fields as JSON strings)
	for f in fields(cls):
		if f.name not in finding_data:
			continue
		val = finding_data[f.name]
		if not isinstance(val, str):
			continue
		expected = f.type if isinstance(f.type, type) else getattr(f.type, '__origin__', None)
		if expected in (dict, list):
			try:
				finding_data[f.name] = json.loads(val)
			except (json.JSONDecodeError, TypeError):
				pass

	# Strip unknown fields: move them into extra_data so no data is lost
	known_fields = {f.name for f in fields(cls)}
	unknown = {k: v for k, v in finding_data.items() if k not in known_fields and not k.startswith('_')}
	if unknown:
		finding_data = {k: v for k, v in finding_data.items() if k in known_fields or k.startswith('_')}
		extra = finding_data.get('extra_data', {})
		if isinstance(extra, str):
			try:
				extra = json.loads(extra)
			except (json.JSONDecodeError, TypeError):
				extra = {}
		extra.update(unknown)
		finding_data['extra_data'] = extra

	# Coerce AI-provided scalars to declared field types (LLMs send wrong-typed
	# scalars, e.g. a bool field as the string "true") before validating.
	finding_data = _coerce_finding_fields(cls, finding_data)

	# Validate field types before instantiation
	errors = cls.validate_fields(finding_data)
	if errors:
		error_msg = f"Invalid {finding_type} fields: {'; '.join(errors)}.\nExpected schema:\n{cls.schema()}"
		yield Error(message=error_msg, _context=context)
		return

	try:
		finding = cls(**finding_data)
		yield Ai(
			content=f'{str(finding)}',
			ai_type="add_finding",
			# Carry the created finding so the web UI can render its FindingCard
			# (VulnerabilityCard/SubdomainCard/…) — it routes on `_type`.
			extra_data={"finding": finding.toDict()},
			_context=context
		)
		yield finding
	except Exception as e:
		yield Error(message=f"Failed to create {finding_type}: {e}\nExpected schema:\n{cls.schema()}", _context=context)


def _run_batch(actions: List[Dict], ctx: ActionContext) -> Generator:
	"""Execute multiple actions in parallel with Rich progress display.

	Shows a live panel with task status while running, prints results
	grouped by task as each completes.

	Args:
		actions: List of action dicts to execute concurrently
		ctx: Action context with max_workers setting

	Yields:
		Results from all actions as they complete, grouped by task
	"""
	from dataclasses import replace
	from rich.padding import Padding
	from rich.panel import Panel
	from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
	from secator.rich import console

	if not actions:
		yield Warning(message="Batch has no actions to execute")
		return

	max_workers = ctx.max_workers or 3

	# Fresh per-turn subagent fan-out budget for this batch (one LLM turn)
	ctx.context["ai_subagent_turn_count"] = 0

	# Silence console output for parallel tasks to avoid interleaved printing
	batch_ctx = replace(ctx, silent=True, in_batch=True)

	# Skip Rich progress panel when we are a subagent, or when the batch
	# contains an AI subagent task (its output conflicts with the Live display)
	has_ai_subagent = any(
		a.get("action") == "task" and a.get("name", "").lower() == "ai"
		for a in actions
	)
	use_progress = not ctx.subagent and not has_ai_subagent

	# Print all task start messages before any task begins
	if use_progress:
		for act in actions:
			name = act.get("description")
			action = act.get("action", "")
			targets = act.get("targets", ctx.targets)
			ai_start = Ai(content=name, ai_type=action, extra_data={"targets": targets, "opts": act.get("opts", {})})
			console.print(ai_start)

	progress = None
	progress_ids = {}

	def run_single(act: Dict, idx: int) -> Dict:
		# safe_dispatch_action so one action raising doesn't abort the batch — the
		# error becomes an Error item (tagged with tool_call_id) fed back to the LLM.
		results = []
		for item in safe_dispatch_action(act, batch_ctx):
			if isinstance(item, Ai) and item.ai_type == "token_usage":
				if progress:
					extra = item.extra_data or {}
					tokens = extra.get("tokens", 0)
					ctx_win = extra.get("context_window", 0)
					tokens_str = (
						f'[gray42]{format_token_count(tokens, compact=True)}'
						f'/[dim red]{format_token_count(ctx_win, compact=True)}[/][/]'
					)
					progress.update(progress_ids[idx], tokens=tokens_str)
					progress.refresh()
				continue  # Don't include token_usage items in results
			results.append(item)
		return {"action": act, "results": results}

	if use_progress:
		class BatchProgress(RichProgress):
			def get_renderables(self):
				yield Padding(Panel(
					self.make_tasks_table(self.tasks),
					title='[bold]Batch execution[/]',
					title_align='left',
					border_style='bold gold3',
					expand=True,
					highlight=True), pad=(1, 0, 0, 0))

		progress = BatchProgress(
			SpinnerColumn('dots'),
			TextColumn('[bold cyan]{task.fields[label]}[/]'),
			TextColumn('{task.fields[state]:<12}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('{task.fields[tokens]}'),
			auto_refresh=True,
			transient=True,
			console=console,
		)
		ctx_mgr = progress
	else:
		from contextlib import nullcontext
		ctx_mgr = nullcontext()

	all_results = []
	with ctx_mgr:
		if use_progress:
			for i, act in enumerate(actions):
				label = _get_action_label(act)
				progress_ids[i] = progress.add_task('', label=label, state='[bold cyan]RUNNING[/]', count='', tokens='')

		with ThreadPoolExecutor(max_workers=max_workers) as executor:
			futures = {executor.submit(run_single, a, i): i for i, a in enumerate(actions)}
			for future in as_completed(futures):
				idx = futures[future]
				result = future.result()
				items = result["results"]

				if use_progress:
					finding_count = sum(1 for r in items if isinstance(r, OutputType))
					has_errors = any(isinstance(r, Error) for r in items)
					state = '[red]FAILURE[/]' if has_errors else '[green]SUCCESS[/]'
					progress.update(
						progress_ids[idx],
						state=state,
						count=f'{finding_count} results',
					)
					progress.refresh()

				all_results.append((idx, result))

	for idx, result in sorted(all_results, key=lambda x: x[0]):
		for item in result["results"]:
			yield item

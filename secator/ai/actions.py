"""Action handlers for AI task."""
import json
import os
import re
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
	_denied_secret_read, _scrub_secrets, loads_lenient,
)


# Bound recursive AI-subagent fan-out so injected output can't drive an
# exponential subagent/token blow-up. Depth caps recursion (child inherits +1 via
# context); breadth caps how many subagents one parent turn may spawn.
_MAX_SUBAGENT_DEPTH = 3
_MAX_SUBAGENTS_PER_TURN = 5
_SUBAGENT_TURN_LOCK = threading.Lock()

# Serializes isolation-container creation within a process: shells in the same run
# share one container, and two racing to create it would collide on the name (125).
_SANDBOX_CREATE_LOCK = threading.Lock()

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
	# Parent's RESOLVED agent-loop cap, handed down so a spawned AI subagent gets the
	# SAME turn budget as the parent (else the mode floor of 5 starves it). Trusted
	# (operator/config-resolved, not LLM-set), so it bypasses the _MAX_CHILD_ITERATIONS clamp.
	max_iterations: int = 0
	in_batch: bool = False  # set on the per-batch ctx so the per-turn fan-out cap applies
	subagent: bool = False
	# Parent's resolved mode (chat/attack/exploit) + whether it is auto. Handed to a
	# spawned AI subagent so run_subagent can enforce its mode policy: a pinned read-only
	# `chat` parent forces a chat subagent; an auto/attack parent may pick the subagent's
	# mode.
	mode: str = ""
	mode_is_auto: bool = True
	silent: bool = False
	sync: bool = True
	interactive: Any = "local"  # "local", "remote", "auto", or bool (legacy)
	backend: Any = field(default=None, repr=False)
	session_id: str = ""
	# --isolated: run every run_shell inside a per-runner Docker container (DinD). When set,
	# path/command permission prompts are dropped (the container is the boundary); target
	# (network) prompts remain. Keyed per runner, NOT per session — subagents may run on
	# another pod's dockerd, so they can't share the parent's container.
	isolated: bool = False
	# Mandate scope (run-opts) propagated to spawned child runners so they enforce the
	# same in_scope/out_of_scope boundary via secator's shipped scope-gate.
	in_scope: List = field(default_factory=list)
	out_of_scope: List = field(default_factory=list)
	_query_engine: Any = field(default=None, repr=False)
	permission_engine: Any = field(default=None, repr=False)

	def get_query_engine(self):
		"""Get or create a QueryEngine (cached for reuse across queries).

		Always queries through the run's REAL driver (mongodb/api on a server,
		local json on the CLI) — the driver's context carries `drivers`, so the
		backend resolves correctly. The old scope=="current" path passed only
		`{"results": self.results}` with no driver; the JsonBackend no longer reads
		an in-memory results context (it streams from disk), so that path silently
		returned nothing. This run's live in-flight findings are unioned in for the
		local driver in handle_query (mongodb/api persist them already).
		"""
		if self._query_engine is None:
			from secator.query import QueryEngine
			self._query_engine = QueryEngine(self.context.get("workspace_id", ""), context=dict(self.context))
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


def _ask_and_check(ctx: ActionContext, is_remote: bool, question: str, permission_type: str,
					value: str, deny_message: str, command: Optional[str] = None,
					reason: Optional[str] = None):
	"""Ask the user/backend to approve one "ask" guardrail layer (shell/target/path).

	Builds the common ask_kwargs, emits the remote pending-prompt (if any), then
	calls ``ctx.backend.ask_user()`` and checks approval. This is a generator so a
	remote backend's pending prompt can be yielded up through the caller's
	``yield from``. Returns ``None`` if approved, else ``deny_message``.
	"""
	ask_kwargs = dict(
		question=question,
		choices=["allow", "allow_all", "deny"],
		session_id=ctx.session_id,
		prompt_type="permission",
		permission_type=permission_type,
		value=value,
		engine=ctx.permission_engine,
		# unique id per prompt so its remote poll matches only its own answer
		prompt_uuid=str(uuid.uuid4()),
	)
	if command is not None:
		ask_kwargs["command"] = command
	if reason is not None:
		ask_kwargs["reason"] = reason
	if is_remote:
		yield ctx.backend.build_pending_prompt(**ask_kwargs)
	response = ctx.backend.ask_user(**ask_kwargs) if ctx.backend else None
	if not _is_approved(response):
		return deny_message
	return None


def check_guardrails(action: Dict, ctx: ActionContext):
	"""Check action against guardrails before dispatching.

	Generator that yields Warning and pending Ai items (for remote backends).
	Returns denial_reason (str or None) via generator return.

	Use from generators: denial = yield from check_guardrails(action, ctx)
	Use from regular code: denial, items = check_guardrails_sync(action, ctx)
	"""
	from secator.ai.interactivity import RemoteBackend
	from secator.ai.guardrails import detect_paths_with_access

	if ctx.permission_engine is None:
		return None

	# The engine is THE decision point: it returns the final verdict already accounting
	# for isolation and any checker fault (see PermissionEngine.check_action). We only act
	# on allow/deny/ask here — no post-processing of the verdict.
	result = ctx.permission_engine.check_action(action)
	if result.decision == "deny":
		# Out-of-scope denials carry the target + a machine-readable reason so clients/CLI
		# can render a clear "Target X is not in the allowed scope" message (and the model
		# can retry an in-scope target) rather than a bare reason code.
		if result.reason == "out_of_scope" and result.targets:
			return f"Target {result.targets[0]} is not in the allowed scope (reason: out_of_scope)"
		return f"Action denied by guardrails: {result.reason}"

	is_remote = isinstance(ctx.backend, RemoteBackend)

	# Prompt loop: check_action returns the first unresolved "ask" layer (shell, then
	# targets, then paths); prompt via ctx.backend.ask_user() and re-check until resolved.
	max_rounds = 5
	rounds = 0
	while result.decision == "ask" and rounds < max_rounds:
		rounds += 1
		cmd_display = _build_action_display(action)

		# Handle shell command prompts (unknown commands or parse failures). Isolation is
		# already resolved by the engine (isolated shell never reaches here as an ask), so
		# this is purely the interactive/remote approval path.
		if result.shell_command:
			parse_failed = "Could not parse" in (result.reason or "")
			denial = yield from _ask_and_check(
				ctx, is_remote,
				question=result.reason or "Shell command requires approval",
				permission_type="shell",
				value=result.shell_command,
				deny_message="Action denied: shell command not approved",
				reason=result.reason,
			)
			if denial:
				return denial
			# Approved: mark the WHOLE command approved for this run so the re-check
			# below doesn't re-parse its sub-commands and re-prompt (one prompt, not
			# max_rounds). Hard-deny checks still apply on the next check_action.
			ctx.permission_engine.approved_shell_commands.add(result.shell_command.strip())
			if parse_failed:
				return None

		# Handle target prompts
		for target in result.targets:
			recheck = ctx.permission_engine._check_value("target", target)
			if recheck.decision == "allow":
				continue
			denial = yield from _ask_and_check(
				ctx, is_remote,
				question=f"Target {target} requires approval",
				permission_type="target",
				value=target,
				deny_message=f"Action denied: target {target} not approved",
				command=cmd_display,
			)
			if denial:
				return denial

		# Handle path prompts. Isolation is resolved by the engine (isolated path asks never
		# reach here), so this is purely the interactive/remote approval path.
		if result.paths:
			cmd = action.get("command", "")
			path_access_map = {p: a for p, a in detect_paths_with_access(cmd)}
			for path in result.paths:
				access_type = path_access_map.get(path, "read")
				denial = yield from _ask_and_check(
					ctx, is_remote,
					question=f"{access_type.capitalize()} access to {path} requires approval",
					permission_type=access_type,
					value=path,
					deny_message=f"Action denied: {access_type} access to {path} not approved",
					command=cmd_display,
				)
				if denial:
					return denial

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
		"subagent": _handle_subagent,
		"workflow": _handle_workflow,
		"shell": _handle_shell,
		"query": _handle_query,
		"follow_up": _handle_follow_up,
		"add_finding": _handle_add_finding,
		"mark_vuln_exploited": _handle_mark_vuln_exploited,
		"mark_vuln_false_positive": _handle_mark_vuln_false_positive,
		"mark_vuln_exploit_failed": _handle_mark_vuln_exploit_failed,
		"update_finding": _handle_update_finding,
		"change_mode": _handle_change_mode,
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


def _child_run_opts(ctx: ActionContext) -> Dict:
	"""Common run_opts shared by every child runner (task/workflow/shell command)."""
	opts = {
		"print_item": not ctx.silent,
		"print_line": ctx.verbose and not ctx.silent,
		"print_progress": False,
		"print_reports_message": False,
		"enable_reports": True,
		"exporters": [],
		"sync": ctx.sync,
		# Every runner an AI session spawns is a child of the AI task: mark it so it
		# drops out of the root runners list and doesn't consume a concurrency slot
		# (the parent AI task already holds one). run_opts is the single source of
		# truth for has_parent (Runner reads self.run_opts['has_parent'] at init).
		"has_parent": True,
		# SECURITY (ISOLATION): child force-inherits the parent `isolated`; it can't set or lower it.
		"isolated": ctx.isolated,
	}
	# Flow the mandate scope down so each child runner enforces it too (shipped gate).
	if ctx.in_scope:
		opts["in_scope"] = ctx.in_scope
	if ctx.out_of_scope:
		opts["out_of_scope"] = ctx.out_of_scope
	return opts


def _child_preamble(
	ctx: ActionContext, context: Dict, runner_type: str = "task"
) -> Tuple[Dict, Optional["Warning"]]:
	"""Shared child-runner prelude: stamp the child's own chunk id + subagent flag,
	then rebuild persistence hooks (or return a denial).

	Propagates driver hooks (mongodb/api): a sync sub-runner skips the pickle path
	that normally re-registers them, so without this its results never persist.
	Don't silently spawn a persistence-less child when the parent has drivers.

	Returns ``(hooks, denial)``; if ``denial`` is non-None the caller must yield it
	and skip the spawn.
	"""
	# Give the child its own fresh runner id so the driver hooks key its OWN doc.
	# _get_result_context already stripped the parent's task_id/workflow_id/scan_id, so
	# there's no parent id to collide with. A task legitimately CHUNKS, so a task child
	# keeps a `task_chunk_id` (the mongo hook keys a task doc on `task_chunk_id` when
	# present, else `task_id`). A workflow/scan child is a STANDALONE runner, not a chunk
	# — key it on `{type}_id`, which BOTH the mongo hook (no chunk id -> `{type}_id`) and
	# the api hook (`Runner.chunk` unset -> `{type}_id`) agree on, so the AI runner card
	# points at the id the active driver actually persisted. (Stamping a `task_chunk_id`
	# on a workflow/scan left it with no valid doc id -> `ObjectId(None)` minted a fresh
	# doc on every update -> stuck PENDING; see #452.) has_parent (run_opts, see
	# _child_run_opts) already drops these children from the root runners list.
	id_key = "task_chunk_id" if runner_type == "task" else f"{runner_type}_id"
	context[id_key] = str(uuid.uuid4())
	if ctx.subagent:
		context["subagent"] = ctx.context.get("subagent", True)
	return _build_child_hooks_or_denial(context)


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

	# A subagent is an `ai` task spawned by another `ai` task. It gets its OWN
	# conversation id (below) so its transcript is a separate conversation, surfaced in
	# the parent as a single "Ran subagent" card rather than folded/duplicated into the
	# parent's turns.
	is_ai_subagent = runner_type == "task" and name.lower() == "ai"
	parent_session = context.get("session_id")  # the card belongs to THIS (parent) conversation
	subagent_label = ""
	sub_session = None

	# Force subagent flags when spawning an AI task from a parent AI task
	if is_ai_subagent:
		# Bound recursive fan-out before constructing/running the child
		denial = _guard_subagent_fanout(ctx, context)
		if denial is not None:
			yield denial
			return
		opts["subagent"] = True
		opts["interactive"] = False
		# `_handle_subagent` already set the child's mode per the run_subagent policy
		# (pinned-chat forced to chat; auto/attack may choose). Fall back to the parent's
		# mode if somehow unset, so a concrete mode is hard-set in the child and it never
		# re-detects upward.
		if ctx.mode:
			opts.setdefault("mode", ctx.mode)
		# Inherit the parent's resolved LLM config (else it falls back to the default
		# model/provider with no key set -> AuthenticationError). The model may be
		# LLM-chosen (setdefault), but transport CREDENTIALS are forced from the parent:
		# a tool-supplied api_base could otherwise redirect the injected parent api_key
		# to an attacker endpoint (setdefault wouldn't override it). Never trust opts here.
		opts.setdefault("model", ctx.model)
		opts.pop("api_key", None)
		opts.pop("api_base", None)
		if ctx.api_key:
			opts["api_key"] = ctx.api_key
		if ctx.api_base:
			opts["api_base"] = ctx.api_base
		# 1.b/1.c: structure the subagent's prompt and inject prior findings for its
		# scope so it doesn't re-run work already done.
		_objective = opts.get("prompt", "")
		opts["prompt"] = build_subagent_prompt(_objective, targets, _gather_subagent_evidence(ctx, targets))
		# Give the subagent its OWN conversation id: its transcript (prompt/responses/tool
		# calls) and its own child runners persist under this id, keeping the parent
		# conversation clean. The parent link is preserved for correlation, and the card
		# emitted below (under the PARENT session) carries this id so a client can open the
		# subagent's transcript.
		subagent_label = action.get("description") or _objective
		sub_session = str(uuid.uuid4())
		context["parent_session_id"] = parent_session
		context["session_id"] = sub_session
		# Give the subagent the SAME turn budget as the parent (else the exploit/attack
		# mode floor of 5 iterations starves it). setdefault so an explicit per-subagent
		# max_iterations the LLM supplied (already clamped to _MAX_CHILD_ITERATIONS by
		# _sanitize_child_opts above) still wins. inf/0 parents are skipped -> subagent
		# resolves via its own mode/config path (uncapped stays uncapped for both).
		if isinstance(ctx.max_iterations, int) and ctx.max_iterations > 0:
			opts.setdefault("max_iterations", ctx.max_iterations)

	# defense in depth: a spawned runner is never dangerous (CLI --dangerous unaffected)
	opts["dangerous"] = False

	# Validate the runner NAME up front and fail with a clean, actionable message.
	# An LLM routinely invents task/workflow names (e.g. `url_crawl`, `code_scan`).
	# For a task, `TemplateLoader(input=...)` accepts any name and the miss only
	# surfaces later inside `build_celery_workflow -> get_task_class`, which raises a
	# `TaskNotFoundError` DURING `yield from runner` — escaping as a full Python
	# TRACEBACK in the tool result (the construction-time `except TaskNotFoundError`
	# below never sees it). For a workflow, an unknown name loads an EMPTY template
	# that fails obscurely downstream. Both waste iterations and pollute the model's
	# context with a stack trace; catch them here and hand back the valid names.
	if runner_type == "task":
		try:
			Task.get_task_class(name)
		except TaskNotFoundError:
			from secator.loader import discover_tasks, find_templates
			available = sorted(t.__name__ for t in discover_tasks())
			# The most common miss is a real WORKFLOW name called via run_task (the
			# model confuses the two tools — e.g. `url_crawl`, `code_scan`). Point it
			# at the right tool instead of only listing tasks.
			workflows = {t['name'] for t in find_templates() if t.get('type') == 'workflow'}
			hint = (f" '{name}' IS a workflow — call it with run_workflow, not run_task."
			        if name in workflows else
			        f" Pick one of the available tasks: {', '.join(available)}.")
			yield Error(message=(
				f"Task '{name}' not found — not a valid secator task.{hint}"
			), _context=context)
			return
		tpl = TemplateLoader(input={'type': 'task', 'name': name})
		runner_cls = Task
	else:
		tpl = TemplateLoader(name=f'workflows/{name}')
		if not tpl.get('name'):
			from secator.loader import find_templates
			available = sorted(t['name'] for t in find_templates() if t.get('type') == 'workflow')
			yield Error(message=(
				f"Workflow '{name}' not found — not a valid secator workflow. "
				f"Pick one of the available workflows: {', '.join(available)}."
			), _context=context)
			return
		runner_cls = Workflow

	# Decrypt targets
	if ctx.encryptor:
		targets = [ctx.encryptor.decrypt(str(t)) for t in targets]

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run {runner_type}: {name} on {targets}", _context=context)
		return

	run_opts = {
		**_child_run_opts(ctx),
		"print_cmd": not ctx.silent and not ctx.subagent,
		"print_cmd_icon": "└",
		"tty": not ctx.subagent and ctx.sync,
		**opts,
	}
	# Human-readable description the LLM supplied for this action (Runner maps
	# run_opts['description'] -> self.description -> persisted `descr`, shown by clients
	# instead of the bare task name). Only set when non-empty so it never blanks out a
	# task's own config.description.
	if action.get("description"):
		run_opts["description"] = action["description"]
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

	hooks, denial = _child_preamble(ctx, context, runner_type)
	if denial is not None:
		yield denial
		return
	try:
		runner = runner_cls(tpl, targets, run_opts=run_opts, hooks=hooks, context=context)
	except TaskNotFoundError as e:
		yield Error(message=str(e), _context=context)
		return

	# Emit the action Ai item now the runner exists (on_init stamped the runner id) so
	# clients can render a RunnerCard; always emitted, even when silent. Use the id the
	# driver keyed the child's doc on: a task child on its own `task_chunk_id`, a
	# workflow/scan child on its `{type}_id` (see _child_preamble). Fall back through
	# both, then `runner.id`.
	runner_id = (context.get(f"{runner_type}_chunk_id")
	             or context.get(f"{runner_type}_id", "") or runner.id)
	extra_data = {
		"targets": targets,
		# Never persist transport credentials into the (DB-stored, client-rendered) action item.
		"opts": {k: v for k, v in opts.items() if k not in ("api_key", "api_base")},
		"runner_id": runner_id,
		"runner_type": runner_type,
		# LLM-supplied human-readable description, rendered in the AI chat row.
		"description": action.get("description", ""),
	}
	# A subagent card lives in the PARENT conversation and links to the subagent's own
	# conversation (its transcript). Tag it so clients render a "Ran subagent <desc>" row
	# that opens `subagent_session_id`, and pin its _context to the parent session (the
	# runner itself already carries the sub-session in `context`). CRUCIAL: strip the
	# `_context.subagent` MARKER — that flag means "this doc is subagent-INTERNAL" and is
	# what restore/UI use to keep subagent chatter out of a conversation. The card is the
	# parent's record of the spawn, NOT internal, so it must not carry it (a nested
	# subagent's context DOES set it — `_child_preamble` — which would otherwise drop the
	# card from the very conversation it belongs to). The label rides on extra_data.subagent.
	card_context = context
	if is_ai_subagent:
		extra_data["subagent"] = subagent_label
		extra_data["subagent_session_id"] = sub_session
		card_context = {
			**{k: v for k, v in context.items() if k != "subagent"},
			"session_id": parent_session,
		}
	yield Ai(
		content=name,
		ai_type=runner_type,
		extra_data=extra_data,
		_context=card_context,
	)

	if is_ai_subagent:
		# The subagent's outputs persist under its OWN session (its transcript), which the
		# parent's LLM cannot read. Stream them, but ALSO capture the final response + what
		# it persisted and hand the parent ONE clean summary as the run_task tool_result —
		# instead of the raw, fragmented output stream it used to receive.
		last_response = ""
		persisted = []
		for out in runner:
			if isinstance(out, Ai):
				if out.ai_type == "response" and (out.content or "").strip():
					last_response = out.content
				elif out.ai_type in ("add_finding", "add_vuln_poc"):
					persisted.append(out.ai_type)
			yield out
		note = (f" Persisted: {', '.join(persisted)}." if persisted
		        else " Persisted: NOTHING (subagent made no add_finding/add_vuln_poc call).")
		handback = (last_response.strip() or "(subagent produced no summary)") + "\n[subagent handback]" + note
		# Stamped for the PARENT conversation (card_context strips the subagent marker) and
		# with THIS run_task's tool_call_id so it becomes the tool_result the parent reads.
		yield Ai(content=handback, ai_type="response",
		         _context={**card_context, "tool_call_id": action.get("tool_call_id")})
	else:
		yield from runner

	# Auto-allow reading from the spawned runner's reports folder
	if ctx.permission_engine and hasattr(runner, 'reports_folder') and runner.reports_folder:
		reports_path = str(runner.reports_folder)
		ctx.permission_engine.add_runtime_allow([f"read({reports_path}/*)", f"read({reports_path})"])


def _get_result_context(action, ctx):
	"""Build the CHILD runner's context.

	Stamps the conversation ``session_id`` (parenting link — see the runner-parenting
	design) and STRIPS the parent's runner-identity keys (`task_id`/`workflow_id`/
	`scan_id`): a NON-chunk child that inherited them would make `update_runner`/
	`runner_id` target the PARENT's doc. ``_child_preamble`` then re-links the child as
	a CHUNK of the parent AI task (its own ``task_chunk_id`` + the parent's ``task_id``),
	so the hook keys the child's own doc on ``task_chunk_id`` while ``task_id`` groups it
	under the parent. The child keeps drivers/workspace so it persists into the same
	workspace, linked to the conversation by ``session_id``. ``has_parent`` is NOT set
	here — it rides on ``run_opts`` (the Runner's single source of truth), see
	``_child_run_opts``.
	"""
	new_ctx = ctx.context.copy()
	for identity_key in ("task_id", "workflow_id", "scan_id", "task_chunk_id"):
		new_ctx.pop(identity_key, None)
	if ctx.session_id and not new_ctx.get("session_id"):
		new_ctx["session_id"] = ctx.session_id
	action_context = {}
	tool_call_id = action.get("tool_call_id")
	tool_call_name = action.get("tool_call_name")
	if tool_call_id:
		action_context["tool_call_id"] = tool_call_id
		action_context["tool_call_name"] = tool_call_name
	return {**new_ctx, **action_context}


def _handle_task(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator task. Spawning an AI subagent goes through run_subagent, not
	run_task(name="ai") — reject the latter with a clear pointer."""
	if (action.get("name") or "").strip().lower() == "ai":
		yield Error(
			message="To spawn an AI subagent, use the run_subagent tool, not run_task(name=\"ai\").",
			_context=_get_result_context(action, ctx),
		)
		return
	yield from _run_runner(action, ctx, "task")


def _handle_subagent(action: Dict, ctx: ActionContext) -> Generator:
	"""Spawn an AI subagent (the ONLY subagent entrypoint).

	Mode policy:
	- A user-PINNED read-only ``chat`` session forces the subagent to ``chat``; if the
	  model asks for a different mode, refuse and tell it to have the user switch to
	  ``auto`` (a read-only session must not spawn an acting subagent behind the user).
	- An ``auto`` or ``attack`` session may set the subagent's ``mode`` (e.g. hand a vuln
	  to an ``exploit`` subagent); omitted means inherit the parent's current mode.
	``exploit`` mode isn't given this tool at all (see MODES), so a focused exploit run
	can't fan out."""
	requested_mode = (action.get("mode") or "").strip().lower() or None
	pinned_chat = (not getattr(ctx, "mode_is_auto", True)) and ctx.mode == "chat"
	if pinned_chat:
		if requested_mode and requested_mode != "chat":
			yield Error(
				message=(
					"A subagent cannot be spawned in a different mode than the current 'chat' mode. "
					"Ask the user to change the current mode to 'auto' so the subagent can pick its mode."
				),
				_context=_get_result_context(action, ctx),
			)
			return
		child_mode = "chat"
	else:
		child_mode = requested_mode or ctx.mode or "chat"
	objective = action.get("objective") or action.get("prompt") or ""
	opts = {"prompt": objective, "mode": child_mode}
	model = (action.get("model") or "").strip()
	if model:
		opts["model"] = model
	task_action = {
		"action": "task",
		"name": "ai",
		"targets": action.get("targets", ctx.targets),
		"description": action.get("description", ""),
		"opts": opts,
		"tool_call_id": action.get("tool_call_id"),
		"tool_call_name": action.get("tool_call_name"),
	}
	yield from _run_runner(task_action, ctx, "task")


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator workflow."""
	yield from _run_runner(action, ctx, "workflow")


# --isolated sandbox: image + resource caps for the per-runner DinD container. Stock Kali image
# (no custom build); kali-rolling is bare (no pre-toolset Kali image exists — "headless" is an apt
# metapackage), so we auto-install a base toolset at container spin-up (SECATOR_AI_SANDBOX_PACKAGES)
# since the LLM doesn't reliably self-install. The LLM apt-gets anything extra at runtime.
_SANDBOX_IMAGE = os.environ.get("SECATOR_AI_SANDBOX_IMAGE", "kalilinux/kali-rolling")
_SANDBOX_MEMORY = os.environ.get("SECATOR_AI_SANDBOX_MEMORY", "1g")
_SANDBOX_PIDS = os.environ.get("SECATOR_AI_SANDBOX_PIDS", "256")
# Base tools the exploit workflow needs (clone/fetch/run PoCs). Empty string disables auto-install.
_SANDBOX_PACKAGES = os.environ.get("SECATOR_AI_SANDBOX_PACKAGES", "git curl wget python3 python3-pip ca-certificates")


def _sandbox_container_name(ctx: "ActionContext", context: Dict) -> str:
	"""Per-RUNNER container name (run_id), not per-session: a subagent may run on another pod's
	dockerd, so it can't share the parent's container. Falls back to session id / 'adhoc'."""
	key = str(context.get("run_id") or getattr(ctx, "session_id", "") or "adhoc")
	return "sbx-" + re.sub(r"[^A-Za-z0-9_.-]", "-", key)[:48]


def _sandbox_is_running(name: str) -> bool:
	"""True iff a container `name` exists and is running."""
	import subprocess
	r = subprocess.run(
		["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
	return r.returncode == 0 and r.stdout.strip() == "true"


def _ensure_sandbox_container(ctx: "ActionContext", context: Dict) -> str:
	"""Lazily create the per-runner Kali sandbox container (idempotent via docker inspect).
	Returns the container name. dockerd runs in the pod (DinD); the metadata DROP + egress policy
	are set once in the pod's DinD entrypoint, not here."""
	import subprocess
	name = _sandbox_container_name(ctx, context)
	if _sandbox_is_running(name):
		return name
	# Bind-mount the reports dir into the sandbox at the SAME path so the LLM's clone/build/run
	# in ~/.secator/reports/<ws>/tasks/<n>/.outputs/ works (that path lives on a shared volume the
	# worker + dind both mount; the dind bind resolves it into the nested container). Without this
	# the model's worker-style paths 404 and it wastes a turn `mkdir -p`-ing them.
	from secator.config import CONFIG
	reports_dir = str(CONFIG.dirs.reports)
	created = False
	# Serialize the create: shells in the SAME run share one container, so two arriving
	# before it exists would both `rm` + `run` the same name — the loser's `docker run`
	# fails "name already in use" (exit 125), the intermittent "could not start isolation
	# container". The lock covers only the fast create; the slow gai.conf/apt bootstrap
	# runs outside it so a 5-min install never blocks a shell that just needs the box.
	with _SANDBOX_CREATE_LOCK:
		if not _sandbox_is_running(name):
			subprocess.run(["docker", "rm", "-f", name], capture_output=True)
			run = subprocess.run([
				"docker", "run", "-d", "--name", name,
				"--memory", _SANDBOX_MEMORY, "--pids-limit", _SANDBOX_PIDS,
				"-v", f"{name}:/work", "-v", f"{reports_dir}:{reports_dir}", "-w", "/work",
				_SANDBOX_IMAGE, "sleep", "infinity",
			], capture_output=True, text=True)
			if run.returncode != 0:
				# A concurrent creator (another thread on this dockerd) may have won the
				# race — if the container is up now, use it. Otherwise surface docker's
				# real stderr, not a bare "exit status 125".
				if _sandbox_is_running(name):
					return name
				err = (run.stderr or run.stdout or "").strip() or f"docker run exited {run.returncode}"
				raise RuntimeError(err)
			created = True
	# Only bootstrap the container WE created (best-effort; a failure must not break the
	# shell path — the LLM can apt-get on demand).
	if created:
		# gVisor's sandbox network is IPv4-only, but DNS returns AAAA records → every hostname op
		# (git/curl/ssh/pip/apt) tries IPv6 first and HANGS. Prefer IPv4 in glibc via gai.conf (fixes
		# git/curl/ssh/python); apt needs its own ForceIPv4 (libapt ignores gai.conf).
		try:
			subprocess.run(
				["docker", "exec", name, "sh", "-c", 'printf "precedence ::ffff:0:0/96 100\\n" > /etc/gai.conf'],
				capture_output=True, timeout=30)
		except Exception:
			pass
		if _SANDBOX_PACKAGES.strip():
			try:
				subprocess.run(
					["docker", "exec", name, "sh", "-c",
					 "apt-get -o Acquire::ForceIPv4=true update -qq && "
					 f"apt-get -o Acquire::ForceIPv4=true install -y -qq --no-install-recommends {_SANDBOX_PACKAGES}"],
					capture_output=True, timeout=300)
			except Exception:
				pass  # tools missing → the LLM can still apt-get on demand
	return name


def _teardown_sandbox_container(ctx: "ActionContext", context: Dict) -> None:
	"""Remove the per-runner sandbox container (+ its /work volume). Best-effort; called at AI-task
	end and as orphan cleanup. Safe to call when isolation was never used (no-op)."""
	import subprocess
	name = _sandbox_container_name(ctx, context)
	subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


def _wrap_docker_exec(name: str, command: str) -> str:
	"""Wrap an arbitrary shell command to run inside the sandbox container. base64 round-trip so any
	quoting in `command` survives verbatim (no shell-escaping pitfalls)."""
	import base64
	b64 = base64.b64encode(command.encode()).decode()
	return f"docker exec {name} sh -lc 'echo {b64} | base64 -d | sh'"


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

	# Unconditional secret-source deny (holds even when dangerous=True disables the
	# permission engine): never let the AI read secator's config/.env or /proc environ.
	# Skipped when --isolated: the command runs in the container, which has none of the
	# worker's config/.env/secrets, so the deny is moot (and would over-block in-container reads).
	if not ctx.isolated:
		secret_denial = _denied_secret_read(command)
		if secret_denial:
			yield Ai(content=command, ai_type="shell", _context=context)
			yield Ai(content=f"[denied] {secret_denial}", ai_type="shell_output", _context=context)
			return

	if ctx.dry_run:
		where = f" (in sandbox {_sandbox_container_name(ctx, context)})" if ctx.isolated else ""
		yield Info(message=f"[DRY RUN]{where} Would run: {command}", _context=context)
		return

	# --isolated: run the command inside a per-runner Kali container via `docker exec`. The Ai
	# transcript still shows the ORIGINAL command; only what CommandTask executes is wrapped.
	exec_command = command
	if ctx.isolated:
		try:
			exec_command = _wrap_docker_exec(_ensure_sandbox_container(ctx, context), command)
		except Exception as e:
			yield Ai(content=command, ai_type="shell", _context=context)
			yield Ai(content=f"[sandbox error] could not start isolation container: {e}",
			         ai_type="shell_output", _context=context)
			return

	try:
		# Don't silently run a persistence-less child when the parent has drivers
		# (same guard _run_runner uses for spawned tasks/workflows).
		hooks, denial = _child_preamble(ctx, context)
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
			**_child_run_opts(ctx),
			"print_cmd": False,
			"dangerous": False,
			"env": _sanitized_env(),
		}
		# Human-readable description the LLM supplied (shown by clients instead of the
		# bare "command" name). See _run_runner for the run_opts['description'] mapping.
		if action.get("description"):
			run_opts["description"] = action["description"]

		# Instantiate `command` directly (bypasses the Task wrapper, which discards `.output`)
		# so stdout survives while persist hooks still fire. Spread **run_opts, not `run_opts=`
		# (would nest and drop `env`); import locally to avoid a circular import.
		from secator.tasks.command import command as CommandTask
		runner = CommandTask([exec_command], hooks=hooks, context=context, **run_opts)

		# 60s cap on ad-hoc AI shell commands. max_timeout is NOT run_opts-settable
		# (Command.__init__ resolves it from CONFIG.tasks.overrides); setting the
		# instance attribute here is honored by get_max_timeout().
		runner.max_timeout = _SHELL_TIMEOUT

		# Emit the command Ai now that the runner exists: its on_init hook has
		# stamped the runner id into context, so clients can link this item to the
		# persisted runner doc (mirrors _run_runner:688-699).
		yield Ai(
			content=command,
			ai_type="shell",
			extra_data={
				# Chunk doc `_id` is keyed on task_chunk_id (task_id now points at the
				# parent ai task for grouping). See _run_runner for the same ordering.
				"runner_id": context.get("task_chunk_id") or context.get("task_id", "") or runner.id,
				"runner_type": "task",
				# LLM-supplied human-readable description, rendered in the AI chat row.
				"description": action.get("description", ""),
			},
			_context=context,
		)

		# Run to completion in-process (fires persist hooks like a normal task/workflow).
		# Do NOT `yield from runner` — raw stdout lines aren't separate transcript items;
		# the single shell_output below is the contract.
		runner.run()

		# Scrub secrets BEFORE truncating (a secret in the middle would survive if we
		# truncated first), then cap so it can't blow up history.
		output = _truncate(_scrub_secrets(runner.output or "(no output)"), _MAX_SHELL_OUTPUT_CHARS)
		yield Ai(content=output, ai_type="shell_output", _context=context)

	except Exception as e:
		yield Error(message=f"Shell command failed: {e}", _context=context)


# Mongo operators the LLM must never send: server-side JS / arbitrary expression
# evaluation (per-document code execution — a DoS and, on some drivers, worse). The
# workspace scope filter still bounds WHICH docs are seen, but a $where runs code
# against each. Workspace queries never legitimately need these.
_FORBIDDEN_QUERY_OPERATORS = frozenset({"$where", "$expr", "$function", "$accumulator"})
# Cap regex length fed to Mongo to bound catastrophic-backtracking DoS (reuses the
# scope engine's ceiling).
_MAX_QUERY_REGEX = 2048


def _validate_query_operators(node) -> Optional[str]:
	"""Recursively reject forbidden Mongo operators and over-long $regex in an LLM
	query. Returns an error message, or None if the query is acceptable."""
	if isinstance(node, dict):
		for key, value in node.items():
			if key in _FORBIDDEN_QUERY_OPERATORS:
				return (f"query operator {key} is not allowed. Use plain field filters "
				        "($in/$regex/$gt/$lt/etc.) on finding fields.")
			if key == "$regex" and isinstance(value, str) and len(value) > _MAX_QUERY_REGEX:
				return f"$regex is too long ({len(value)} chars, max {_MAX_QUERY_REGEX})."
			err = _validate_query_operators(value)
			if err:
				return err
	elif isinstance(node, list):
		for item in node:
			err = _validate_query_operators(item)
			if err:
				return err
	return None


def _handle_query(action: Dict, ctx: ActionContext) -> Generator:
	"""Query workspace or current results for findings.

	Args:
		action: Action dict with query (MongoDB query dict)
		ctx: Action context (queries through the run's real driver; live in-run
			findings are unioned in for the local json driver)
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
	# (known tool-calling quirk); coerce it back, tolerating a stray trailing brace /
	# prose the LLM sometimes appends (loads_lenient), else fail with a clear error.
	if isinstance(query_filter, str):
		try:
			query_filter = loads_lenient(query_filter)
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

	# Reject server-side-JS / expression operators and over-long regex before the
	# query reaches the DB (workspace scope bounds WHICH docs, not per-doc code cost).
	op_err = _validate_query_operators(query_filter)
	if op_err:
		yield Error(message=op_err, _context=context)
		return

	engine = ctx.get_query_engine()
	is_local = getattr(engine.backend, "name", "") == "json"

	# A non-local backend (mongodb/api) needs a workspace to query. The local (json)
	# driver can always answer from this run's in-memory findings (unioned below), so
	# it is exempt from the workspace_id requirement.
	if not is_local and not ctx.context.get("workspace_id"):
		yield Warning(message="No workspace available for query", _context=context)
		return

	try:
		query_str = json.dumps(query_filter, separators=(',', ':'))
		# Surface only the PRIMARY of each finding group: skip hidden duplicates
		# (_context.workspace_duplicate=True) so the AI never operates on a demoted
		# copy — e.g. records a PoC on a doc that isn't the one clients show. Only
		# the mongo-backed drivers (mongodb/api) tag duplicates; the json driver
		# doesn't. Respect an explicit _context filter from the model rather than
		# fighting it. Applied to the search only, so the shown query stays the
		# model's own.
		search_query = query_filter
		if not is_local and "_context" not in query_filter and "_context.workspace_duplicate" not in query_filter:
			search_query = {**query_filter, "_context.workspace_duplicate": {"$ne": True}}
		results = engine.search(search_query, limit=limit)
		# Local driver only writes to disk at end-of-run, so union this run's live
		# in-flight findings to make query_workspace the source of truth (mongodb/api
		# persist live already, so they need no union).
		if is_local:
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
	multiple = bool(action.get("multiple", False))
	# Store choices on the top-level `choices` field (what clients read) AND in
	# extra_data (back-compat). Without the top-level field, the persisted follow-up
	# doc has `choices: []` and clients render no choice buttons. `multiple` tells
	# clients to render multi-select (checkboxes) vs single-pick.
	yield Ai(
		content=reason, ai_type="follow_up", choices=choices, multiple=multiple,
		extra_data={"choices": choices, "multiple": multiple}, _context=context)


def _handle_stop(action: Dict, ctx: ActionContext) -> Generator:
	"""Handle stop action - signals session completion."""
	context = _get_result_context(action, ctx)
	reason = action.get("reason", "completed")
	yield Ai(content=reason, ai_type="stopped", _context=context)


def _handle_change_mode(action: Dict, ctx: ActionContext) -> Generator:
	"""Handle a model-driven mode change.

	Signals the requested mode back to the loop via ``Ai(ai_type="mode_changed")``;
	the runner applies it (rebuilds the tool surface + persona and continues the turn).
	The loop treats this as a normal tool result (the call still gets a response, since
	the turn continues).

	Gating: a user-PINNED read-only ``chat`` session can never self-escape — the tool
	is not even built for it (see ``build_tool_schemas``); this rejects it as defense in
	depth. Self-de-escalation is not allowed (no capability benefit), so the only valid
	targets are ``attack``/``exploit``.
	"""
	context = _get_result_context(action, ctx)
	requested = (action.get("mode") or "").strip().lower()
	if (not getattr(ctx, "mode_is_auto", True)) and ctx.mode == "chat":
		yield Error(
			message="Cannot change mode: this session is pinned to read-only chat. "
			"Ask the user to switch the mode to 'auto' or an action mode.",
			_context=context)
		return
	if requested not in ("attack", "exploit"):
		yield Error(
			message=f"Invalid change_mode target '{requested}'. Choose 'attack' or 'exploit'.",
			_context=context)
		return
	# change_mode only escalates — it can't de-escalate (e.g. exploit -> attack), which
	# would silently drop capability. Rank chat < attack < exploit; reject anything that
	# isn't a strict escalation from the current mode. (`auto` ranks below all, so an auto
	# session can still escalate to either.)
	_rank = {"chat": 0, "attack": 1, "exploit": 2}
	current = (getattr(ctx, "mode", "") or "").strip().lower()
	if _rank[requested] <= _rank.get(current, -1):
		yield Error(
			message=f"Cannot change mode from '{current}' to '{requested}': change_mode "
			"only escalates (e.g. attack -> exploit), it cannot de-escalate.",
			_context=context)
		return
	yield Ai(content=requested, ai_type="mode_changed", _context=context)


def _handle_add_finding(action: Dict, ctx: ActionContext) -> Generator:
	"""Create a secator finding from LLM-provided data.

	Args:
		action: Action dict with _type and finding fields
		ctx: Action context
	"""
	context = _get_result_context(action, ctx)

	finding_type = action.get("_type", "")
	finding_data = {k: v for k, v in action.items() if k not in ("action", "_type", "tool_call_id", "tool_call_name")}
	# SECURITY: strip framework/server-owned + `*_path` fields the agent must not set (identity,
	# provenance, dedup, verdict/derived) — see _drop_readonly_fields. `_context` is then set
	# server-side below, so the finding is always scoped to THIS session's workspace.
	finding_data = _drop_readonly_fields(finding_data)
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
			# Carry the created finding so clients can render the finding
			# (VulnerabilityCard/SubdomainCard/…) — it routes on `_type`.
			extra_data={"finding": finding.toDict()},
			_context=context
		)
		yield finding
	except Exception as e:
		yield Error(message=f"Failed to create {finding_type}: {e}\nExpected schema:\n{cls.schema()}", _context=context)


def _scoped_vuln_update(ctx: ActionContext, uuid: str, update: Dict):
	"""Apply a workspace-scoped ``$set`` to the vulnerability with this ``_uuid``.

	Returns ``(modified, updated, label, error_msg)``: ``modified`` docs count,
	the re-fetched vuln (dict, or None), a display ``label`` (the vuln's ``name``,
	falling back to the uuid), and an ``error_msg`` string when nothing matched.

	Uses ``QueryEngine.update`` (an in-place ``$set`` on the matched doc) rather than
	re-yielding the finding, so it works uniformly across backends without risking a
	duplicate insert. On the mongodb driver a ``_uuid`` lookup/update is a native ``_id``
	index seek (the query layer rewrites a valid-ObjectId ``_uuid`` to ``_id`` — findings
	carry ``_uuid = str(_id)``), so the update + re-fetch are point operations, not
	workspace scans. After the update it re-fetches and re-applies the same ``$set`` locally
	— the json store is append-only (last-wins on read) so a tight limit can return a
	pre-update line; on the store-backed drivers the fetch is already current, a no-op there.
	"""
	engine = ctx.get_query_engine()
	query = {"_type": "vulnerability", "_uuid": uuid}
	modified = engine.update(query, {"$set": update})
	if not modified:
		return 0, None, uuid, (
			f"No vulnerability found with _uuid={uuid} in this workspace. "
			"Re-check the `_uuid` from query_workspace results."
		)
	# scope_only: a just-marked false-positive is hidden by the `is_false_positive:{$ne:True}`
	# display filter, so a normal re-fetch returns None — `updated` stays empty and `label`
	# falls back to the bare uuid (the chat row then reads "Updated Marked <uuid>…" instead
	# of "Updated <name>", and extra_data.finding is empty). Drop the display filters for this
	# targeted by-uuid read so the finding comes back regardless of its display state.
	updated = (engine.search(query, limit=1, scope_only=True) or [None])[0]
	if updated:
		from secator.query.json import _apply_set
		_apply_set(updated, update)
	label = (updated.get("name") if isinstance(updated, dict) else None) or uuid
	return modified, updated, label, None


def _merge_extra_data(update: Dict, extra_data) -> None:
	"""Merge caller ``extra_data`` into ``update`` with dotted keys so existing keys survive."""
	if isinstance(extra_data, dict):
		for k, v in extra_data.items():
			key = str(k)
			if key and "." not in key and not key.startswith("$"):
				update[f"extra_data.{key}"] = v


def _handle_mark_vuln_exploited(action: Dict, ctx: ActionContext) -> Generator:
	"""Mark an EXISTING vulnerability as exploited, recording its proof-of-concept.

	Fills the vuln's ``poc`` (markdown: the commands + outputs proving exploitation) and
	sets ``status=EXPLOITED`` / ``verified=True`` / ``is_false_positive=False`` via a scoped
	``$set`` matched by the ``_uuid`` the LLM saw in ``query_workspace`` results. This is the
	exploitation-result sink used INSTEAD of ``add_finding(exploit)``: an exploited vuln ends
	up with its own filled ``poc``, not a separate Exploit finding. A claimed exploitation
	MUST carry proof — an empty ``poc`` is refused. Also fills the vuln's own ``remediation``
	and ``impact`` fields when supplied, and stamps the exploitation date into the ``poc``
	(the model can't be trusted for the real date, so we set it server-side).
	"""
	from datetime import datetime, timezone
	context = _get_result_context(action, ctx)
	uuid = str(action.get("_uuid") or "").strip()
	poc = action.get("poc") or ""
	remediation = action.get("remediation") or ""
	impact = action.get("impact") or ""
	if ctx.encryptor:
		dec = _decrypt_dict({"poc": poc, "remediation": remediation, "impact": impact}, ctx.encryptor)
		poc = dec.get("poc", poc)
		remediation = dec.get("remediation", remediation)
		impact = dec.get("impact", impact)

	if not uuid:
		yield Error(message="mark_vuln_exploited requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
		return
	if not str(poc).strip():
		yield Error(message="mark_vuln_exploited requires a non-empty `poc` (commands + outputs proving exploitation).", _context=context)  # noqa: E501
		return

	# Stamp the exploitation date at the top of the PoC (authoritative server-side date).
	poc = f"_Exploited on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}_\n\n{str(poc).strip()}"

	update = {"poc": poc, "status": "EXPLOITED", "verified": True, "is_false_positive": False}
	if str(remediation).strip():
		update["remediation"] = str(remediation).strip()
	if str(impact).strip():
		update["impact"] = str(impact).strip()
	# Confidence re-prioritizes the vuln (confidence_nb: high=1 sorts first .. low=3).
	confidence = str(action.get("confidence") or "").strip().lower()
	if confidence in ("low", "medium", "high"):
		update["confidence"] = confidence
		update["confidence_nb"] = {"high": 1, "medium": 2, "low": 3}[confidence]
	_merge_extra_data(update, action.get("extra_data"))

	try:
		modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update)
	except Exception as e:
		yield Error(message=f"Failed to mark vulnerability exploited: {e}", _context=context)
		return
	if err:
		yield Error(message=err, _context=context)
		return
	yield Ai(
		content=f"Marked {label} as exploited (PoC recorded).",
		ai_type="mark_vuln_exploited",
		extra_data={"finding": updated} if updated else {},
		_context=context,
	)


def _handle_mark_vuln_false_positive(action: Dict, ctx: ActionContext) -> Generator:
	"""Mark an EXISTING vulnerability as a false positive.

	Sets ``is_false_positive=True`` (the authoritative hide-flag the store base query
	filters on EVERY backend, so the finding disappears from all reads/reports),
	``status=FALSE_POSITIVE`` and ``verified=False`` via a scoped ``$set`` matched by the
	``_uuid`` from ``query_workspace``. Non-destructive: the finding is kept and stays
	recoverable (unset ``is_false_positive``). An optional ``reason`` is stored in
	``extra_data.false_positive_reason``.
	"""
	context = _get_result_context(action, ctx)
	uuid = str(action.get("_uuid") or "").strip()
	if not uuid:
		yield Error(message="mark_vuln_false_positive requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
		return
	reason = str(action.get("reason") or "").strip()
	if ctx.encryptor and reason:
		reason = _decrypt_dict({"reason": reason}, ctx.encryptor).get("reason", reason)

	update = {"is_false_positive": True, "status": "FALSE_POSITIVE", "verified": False}
	if reason:
		update["extra_data.false_positive_reason"] = reason
	_merge_extra_data(update, action.get("extra_data"))

	try:
		modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update)
	except Exception as e:
		yield Error(message=f"Failed to mark vulnerability false positive: {e}", _context=context)
		return
	if err:
		yield Error(message=err, _context=context)
		return
	msg = f"Marked {label} as a false positive" + (f" ({reason})." if reason else ".")
	yield Ai(
		content=msg,
		ai_type="mark_vuln_false_positive",
		extra_data={"finding": updated} if updated else {},
		_context=context,
	)


def _handle_mark_vuln_exploit_failed(action: Dict, ctx: ActionContext) -> Generator:
	"""Mark an EXISTING vulnerability as EXPLOIT FAILED — a real vuln this attempt could not
	exploit, kept VISIBLE so a later attempt can retry (unlike mark_vuln_false_positive, which
	hides a not-real finding). Sets ``status="EXPLOIT FAILED"`` via a scoped ``$set`` matched by
	``_uuid``; leaves ``is_false_positive`` and ``verified`` untouched. Fills ``remediation`` /
	``impact`` when supplied (they still apply), and stores an optional ``reason`` in
	``extra_data.exploit_failed_reason``.
	"""
	context = _get_result_context(action, ctx)
	uuid = str(action.get("_uuid") or "").strip()
	if not uuid:
		yield Error(message="mark_vuln_exploit_failed requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
		return
	reason = str(action.get("reason") or "").strip()
	remediation = action.get("remediation") or ""
	impact = action.get("impact") or ""
	if ctx.encryptor:
		dec = _decrypt_dict({"reason": reason, "remediation": remediation, "impact": impact}, ctx.encryptor)
		reason = dec.get("reason", reason)
		remediation = dec.get("remediation", remediation)
		impact = dec.get("impact", impact)

	update = {"status": "EXPLOIT FAILED"}
	if str(remediation).strip():
		update["remediation"] = str(remediation).strip()
	if str(impact).strip():
		update["impact"] = str(impact).strip()
	if reason:
		update["extra_data.exploit_failed_reason"] = reason
	_merge_extra_data(update, action.get("extra_data"))

	try:
		modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update)
	except Exception as e:
		yield Error(message=f"Failed to mark vulnerability exploit-failed: {e}", _context=context)
		return
	if err:
		yield Error(message=err, _context=context)
		return
	msg = f"Marked {label} as exploit-failed" + (f" ({reason})." if reason else ".")
	yield Ai(
		content=msg,
		ai_type="mark_vuln_exploit_failed",
		extra_data={"finding": updated} if updated else {},
		_context=context,
	)


# Fields that must never be overwritten via update_finding (identity / routing / scope).
_FINDING_IMMUTABLE_FIELDS = {"_uuid", "_type", "_id", "_context", "id"}

# Real scan-finding types (vulnerability/url/port/…) update_finding may edit. Restricting to
# these stops a known `_uuid` from editing a non-finding record: error/warning/info (EXECUTION_TYPES)
# and stat (STAT_TYPES) aren't in FINDING_TYPES already, and `ai` IS in FINDING_TYPES but is the
# conversation/action-doc type — editing it would tamper the transcript, so exclude it.
_FINDING_TYPE_NAMES = frozenset(cls.get_name().lower() for cls in FINDING_TYPES) - {"ai"}


# Server/pipeline-owned finding fields the GENERIC add_finding/update_finding must never let the
# agent write. The dedicated mark_vuln_* tools set the verdict fields themselves via a server-built
# `$set`, so they are unaffected — only the free-form tools are restricted.
_AGENT_READONLY_FIELDS = frozenset({
	"workspace_id",                                                 # scope lives on _context, never top-level
	"verified", "status", "is_false_positive", "is_acknowledged",   # verdict — forging bypasses mark_vuln_* gates
	"confidence_nb", "severity_nb",                                 # server-derived in __post_init__
})


def _drop_readonly_fields(data: Dict) -> Dict:
	"""Strip fields an LLM-supplied finding write must not set.

	SECURITY: these tools write STRAIGHT to the store on the worker, bypassing the API's ingest
	guards, so a prompt-injected agent must not reach:
	- ``*_path`` — worker-filesystem paths streamed back by the finding-storage endpoint
	  (authenticated arbitrary-file-read / foreign-blob read);
	- any ``_``-prefixed framework field — identity/scope (``_uuid``/``_context``/``_id``),
	  provenance (``_source``/``_timestamp``), dedup (``_tagged``/``_duplicate``/``_related``),
	  the notification flag (``_email_notified``), etc.;
	- verdict/derived fields (``_AGENT_READONLY_FIELDS``) — forging ``verified``/``status``/
	  ``is_false_positive`` bypasses the dedicated tools' gates (e.g. mark_vuln_exploited's
	  mandatory PoC); ``confidence_nb``/``severity_nb`` are recomputed by the server.
	Deny-by-default on the framework (``_`` prefix) keeps future ``_``-fields safe automatically.
	"""
	return {
		k: v for k, v in data.items()
		if not str(k).startswith("_")
		and not str(k).endswith("_path")
		and k not in _AGENT_READONLY_FIELDS
	}


def _lookup_finding(ctx: "ActionContext", uuid: str):
	"""Return the live workspace finding with this ``_uuid`` (dict), or None. Workspace-scoped
	via the engine's base query, so it never reaches another workspace or an already-removed doc."""
	engine = ctx.get_query_engine()
	return (engine.search({"_uuid": uuid}, limit=1) or [None])[0]


def _handle_update_finding(action: Dict, ctx: ActionContext) -> Generator:
	"""Set fields on an EXISTING finding (any type) identified by ``_uuid``.

	A workspace-scoped ``$set`` touching only the caller-named fields — immutable
	identity/routing keys are stripped, and mutating a ``target`` finding is refused so the
	AI can't widen scope. Used to fix a wrong field (e.g. severity), add tags/cves, or enrich
	extra_data. For a vulnerability's exploited / false-positive verdict, prefer the dedicated
	``mark_vuln_exploited`` / ``mark_vuln_false_positive`` tools.
	"""
	context = _get_result_context(action, ctx)
	uuid = str(action.get("_uuid") or "").strip()
	if not uuid:
		yield Error(message="update_finding requires the finding `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
		return

	fields = action.get("fields") or {}
	extra_data = action.get("extra_data") or {}
	if isinstance(fields, str):
		try:
			fields = json.loads(fields)
		except (json.JSONDecodeError, TypeError):
			fields = {}
	if isinstance(extra_data, str):
		try:
			extra_data = json.loads(extra_data)
		except (json.JSONDecodeError, TypeError):
			extra_data = {}
	if not isinstance(fields, dict) or not isinstance(extra_data, dict):
		yield Error(message="update_finding `fields` and `extra_data` must be JSON objects.", _context=context)
		return
	if ctx.encryptor:
		fields = _decrypt_dict(fields, ctx.encryptor)
		extra_data = _decrypt_dict(extra_data, ctx.encryptor)

	existing = _lookup_finding(ctx, uuid)
	if not existing:
		yield Error(
			message=f"No finding found with _uuid={uuid} in this workspace. Re-check the `_uuid` from query_workspace results.",  # noqa: E501
			_context=context,
		)
		return
	etype = str(existing.get("_type", "")).lower()
	if etype == "target":
		yield Error(message="Refusing to update a 'target' finding (scope integrity).", _context=context)
		return
	if etype not in _FINDING_TYPE_NAMES:
		yield Error(message=f"Refusing to update a non-finding record (_type={etype!r}).", _context=context)
		return
	cls = {c.get_name().lower(): c for c in FINDING_TYPES}[etype]

	# Only agent-writable content fields (framework/server-owned + `*_path` stripped); `id`
	# stays blocked on UPDATE via _FINDING_IMMUTABLE_FIELDS below.
	fields = _drop_readonly_fields(fields)
	# An `extra_data` object passed INSIDE `fields` must merge via dotted keys (like the dedicated
	# `extra_data` arg) — a whole-object $set would clobber existing keys AND conflict with the
	# dotted `extra_data.*` paths on Mongo. Fold it into extra_data (the dedicated arg wins).
	fields_extra = fields.pop("extra_data", None)
	if isinstance(fields_extra, dict):
		extra_data = {**fields_extra, **extra_data}
	# Validate the remaining content fields against the finding's schema (coerce sloppy scalars
	# first, like add_finding) so a wrong-shaped value (e.g. tags="xss" where a list is required)
	# is rejected up front, not persisted raw.
	fields = _coerce_finding_fields(cls, fields)
	errors = cls.validate_fields(fields)
	if errors:
		yield Error(message=f"Invalid {etype} fields: {'; '.join(errors)}", _context=context)
		return

	update = {}
	for k, v in fields.items():
		key = str(k)
		if key in _FINDING_IMMUTABLE_FIELDS or key.startswith("$") or "." in key:
			continue
		update[key] = v
	for k, v in extra_data.items():
		key = str(k)
		if key and "." not in key and not key.startswith("$"):
			update[f"extra_data.{key}"] = v
	if not update:
		yield Error(message="update_finding: nothing to update (pass `fields` and/or `extra_data`).", _context=context)  # noqa: E501
		return

	engine = ctx.get_query_engine()
	try:
		modified = engine.update({"_uuid": uuid}, {"$set": update})
	except Exception as e:
		yield Error(message=f"Failed to update finding: {e}", _context=context)
		return
	if not modified:
		yield Error(message=f"No finding updated for _uuid={uuid}.", _context=context)
		return

	updated = _lookup_finding(ctx, uuid)
	if updated:
		from secator.query.json import _apply_set
		_apply_set(updated, update)
	yield Ai(
		content=f"Updated finding {uuid} ({', '.join(sorted(update.keys()))}).",
		ai_type="update_finding",
		extra_data={"finding": updated} if updated else {},
		_context=context,
	)


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

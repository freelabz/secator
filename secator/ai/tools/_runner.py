"""Shared helpers for the runner tools (run_task / run_workflow / run_subagent / run_shell):
child-runner context, scope/opts propagation, subagent fan-out bounds, and the common
``_run_runner`` execution path.

Moved verbatim from ``secator/ai/actions.py``.
"""
import threading
import uuid
from collections import Counter
from typing import Dict, Generator, Optional, Tuple
from secator.runners import Task, Workflow
from secator.runners.task import TaskNotFoundError
from secator.output_types import Ai, Error, FINDING_TYPES, Info, Warning
from secator.template import TemplateLoader
from secator.ai.utils import _PERSIST_AI_TYPES, _is_heavy_runner, _sanitize_child_opts, build_subagent_prompt
from secator.ai.actions import ActionContext, _get_result_context


# Bound recursive AI-subagent fan-out so injected output can't drive an
# exponential subagent/token blow-up. Depth caps recursion (child inherits +1 via
# context); breadth caps how many subagents one parent turn may spawn.
_MAX_SUBAGENT_DEPTH = 3


_MAX_SUBAGENTS_PER_TURN = 5


_SUBAGENT_TURN_LOCK = threading.Lock()


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
	# Order by hook phase (pre, persistence, post) — same ordering as _apply_context_drivers.
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


def _guard_subagent_fanout(ctx: "ActionContext", context: Dict) -> Optional["Warning"]:
	"""Cap AI-subagent recursion depth + per-turn fan-out.

	Returns a denial ``Warning`` if a cap is hit (caller yields it and skips the
	spawn); otherwise stamps the child's depth (+1) into ``context`` and bumps the
	per-turn counter. Breadth is only counted within a batch (one LLM turn); a
	lone spawn is inherently breadth-1.
	"""
	# A subagent is already scoped to one task and no longer has the run_subagent tool;
	# refuse a nested spawn defensively, before the depth/breadth caps, in case a call
	# somehow reaches here (e.g. a replayed/text-parsed tool call).
	if ctx.subagent:
		return Warning(
			message="Subagent spawn denied: a subagent cannot spawn nested subagents",
			_context=context,
		)
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


def _child_dangerous(ctx: ActionContext, is_ai_subagent: bool) -> bool:
	"""Whether a spawned child runs in `dangerous` (bypass) mode.

	A spawned runner is NEVER dangerous — EXCEPT an AI subagent, which INHERITS the
	parent's operator-chosen `dangerous`. `dangerous` is user-only: it is agent-readonly
	AND an LLM-supplied `dangerous` is stripped from child opts (`_sanitize_child_opts`),
	so the LLM still cannot self-escalate — but a bypass the OPERATOR enabled
	(`--dangerous` / shift+tab) must extend to the exploit/recon work it delegates to a
	subagent, otherwise the subagent gets Blocked on the very actions the operator opted
	into. Non-AI children (task/workflow/shell) stay False: `dangerous` is an ai-task
	concept, meaningless for them.
	"""
	return bool(ctx.dangerous) if is_ai_subagent else False


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
	# Flow the mandate scope down so each child runner enforces it too (shipped gate) —
	# unless the operator bypassed the permission engine (`dangerous`), in which case scope
	# is intentionally dropped so nothing is filtered as out-of-scope.
	if not ctx.dangerous:
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
		# `RunSubagent.run` already set the child's mode per the run_subagent policy
		# (pinned-chat forced to chat; auto/scan may choose). Fall back to the parent's
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
		# A subagent runs on the non-interactive AutoBackend — it can never surface an
		# `ask` prompt, so without the parent's approvals every target/shell/path that
		# would normally ask (subpaths of an approved host, an approved command, etc.)
		# auto-denies. Scope (in_scope/out_of_scope) already flows via opts; hand down the
		# human-granted runtime allow-list too so the child operates within the SAME
		# envelope the user vetted for the parent.
		if ctx.permission_engine is not None:
			inherited = ctx.permission_engine.export_runtime_allow()
			if inherited:
				context["ai_inherited_runtime_allow"] = inherited
		# Give the subagent the SAME turn budget as the parent (else the exploit/scan
		# mode floor of 5 iterations starves it). setdefault so an explicit per-subagent
		# max_iterations the LLM supplied (already clamped to _MAX_CHILD_ITERATIONS by
		# _sanitize_child_opts above) still wins. inf/0 parents are skipped -> subagent
		# resolves via its own mode/config path (uncapped stays uncapped for both).
		if isinstance(ctx.max_iterations, int) and ctx.max_iterations > 0:
			opts.setdefault("max_iterations", ctx.max_iterations)

	opts["dangerous"] = _child_dangerous(ctx, is_ai_subagent)

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
			task_cls = Task.get_task_class(name)
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
		# Hydrate the task's own metadata (description / input_types / tags) from its class,
		# the way instantiating the task class directly would. A bare {type, name} template
		# leaves these UNSET, and DotMap serializes an unset field as `{}` — not a str/list —
		# which the `api` driver's runner schema rejects (description must be a str,
		# input_types a list) and which also disables this task's input-type filtering.
		tpl = TemplateLoader(input={
			'type': 'task',
			'name': name,
			'description': (task_cls.__doc__ or '').strip() or None,
			'input_types': list(getattr(task_cls, 'input_types', []) or []),
			'tags': list(getattr(task_cls, 'tags', []) or []),
		})
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
	# `dangerous` runs free: the LLM-supplied `opts` is merged AFTER _child_run_opts, so it
	# could re-add in_scope/out_of_scope that _child_run_opts dropped and re-enable the child
	# scope-gate. Strip them so bypass genuinely means no scope filtering.
	if ctx.dangerous:
		run_opts.pop("in_scope", None)
		run_opts.pop("out_of_scope", None)
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
	# If a display (TUI) is active, let it tap child command output + findings. No-op
	# otherwise; hooks are picklable so async/Celery children don't break (see secator.rich).
	if runner_type in ("task", "workflow", "scan"):
		from secator.rich import attach_display_hooks
		attach_display_hooks(hooks, runner_cls)
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
				# The subagent's conversation lives under its OWN session (its transcript,
				# shown in the drill-in view and streamed there by its own display hook).
				# Do NOT bubble those individual messages up to the parent: re-yielding them
				# makes the parent re-render the whole transcript (its items aren't _uuid-
				# deduped like findings) and pollutes the parent's stream/store. The parent
				# gets ONE clean summary — the handback below. Capture what we need first.
				if out.ai_type == "response" and (out.content or "").strip():
					last_response = out.content
				elif out.ai_type in _PERSIST_AI_TYPES:
					persisted.append(out.ai_type)
				continue
			# Only real findings bubble up to the parent (FINDING_TYPES includes `ai`, already
			# handled above). Execution plumbing/notes stay in the subagent's own transcript.
			if isinstance(out, tuple(FINDING_TYPES)):
				yield out
		if persisted:
			# Collapse repeated action types to counted uniques so a subagent that
			# made N calls of one type reads "mark_vuln_false_positive ×N" instead of
			# listing it N times.
			counts = Counter(persisted)
			summary = ', '.join(f"{atype} ×{n}" if n > 1 else atype for atype, n in counts.items())
			note = f" Persisted: {summary}."
		else:
			note = " Persisted: NOTHING (subagent made no add_finding/mark_vuln_* call)."
		handback = (last_response.strip() or "(subagent produced no summary)") + "\n[subagent handback]" + note
		# Stamped for the PARENT conversation (card_context strips the subagent marker) and
		# with THIS run_task's tool_call_id so it becomes the tool_result the parent reads.
		# Carries the subagent session id (mark THIS subagent's row done — parallel subagents
		# hand back independently) and the subagent's billed token/cost totals so a client can
		# show a usage line under the verdict. The child accumulates usage on ITS OWN
		# `self.context` (which may be a copy of what we passed), so read from `runner.context`
		# — the authoritative final totals — not the parent-side `context`.
		child_ctx = getattr(runner, "context", None) or {}
		usage = {
			"tokens": int(child_ctx.get("ai_tokens", 0) or 0),
			"prompt_tokens": int(child_ctx.get("ai_prompt_tokens", 0) or 0),
			"completion_tokens": int(child_ctx.get("ai_completion_tokens", 0) or 0),
			"cost": float(child_ctx.get("ai_cost", 0.0) or 0.0),
		}
		yield Ai(content=handback, ai_type="response",
		         extra_data={"subagent_session_id": sub_session, "usage": usage},
		         _context={**card_context, "tool_call_id": action.get("tool_call_id")})
	else:
		yield from runner

	# Auto-allow reading from the spawned runner's reports folder
	if ctx.permission_engine and hasattr(runner, 'reports_folder') and runner.reports_folder:
		reports_path = str(runner.reports_folder)
		ctx.permission_engine.add_runtime_allow([f"read({reports_path}/*)", f"read({reports_path})"])

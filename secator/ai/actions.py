"""AI action dispatch: ActionContext, guardrail checks, the tool dispatcher and batching.

Each built-in tool's handler is its ``run(self, action, ctx)`` method in
its resource module under ``secator/ai/tools/`` — the same contract external tools use.
"""
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

from secator.output_types import Ai, Error, Info, Warning, OutputType
from secator.utils import format_token_count
from secator.ai.utils import _build_action_display, _is_approved, _format_action_error, _get_action_label


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
	# Parent's resolved mode (chat/scan/exploit) + whether it is auto. Handed to a
	# spawned AI subagent so run_subagent can enforce its mode policy: a pinned read-only
	# `chat` parent forces a chat subagent; an auto/scan parent may pick the subagent's
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
	# When the operator bypasses the permission engine (`dangerous`), also stop propagating
	# the in_scope/out_of_scope boundary to child runners — bypass means run freely, so the
	# shipped scope-gate shouldn't keep dropping out-of-scope targets.
	dangerous: bool = False
	_query_engine: Any = field(default=None, repr=False)
	permission_engine: Any = field(default=None, repr=False)
	# Runs the runner's on_item_update hooks of one driver phase: ``(item, phase=) -> item``.
	# None (dry-run / library use) skips them.
	run_item_update_hooks: Optional[Callable] = field(default=None, repr=False)
	# Runners this ai task spawned: runner id (doc key and run-scope id) -> the runner object,
	# recorded with each run tool's runner card. Shared by the per-batch copies of the context
	# (dataclasses.replace keeps the same dict). Read by stop_runner's ownership check.
	spawned_runners: Dict = field(default_factory=dict, repr=False)
	# Conversation ids of the subagents this ai task spawned (their runners are its own too).
	subagent_sessions: set = field(default_factory=set, repr=False)

	def record_runner(self, runner, *ids):
		"""Remember a runner this ai task spawned, under each of its ids."""
		for i in ids:
			if i:
				self.spawned_runners[str(i)] = runner

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
				command=result.shell_command,
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
	from secator.ai.tools import TOOLS_BY_ACTION
	action_type = action.get("action", "")
	tool = TOOLS_BY_ACTION.get(action_type)
	if tool:
		yield from tool.handle(action, ctx)
	else:
		context = _get_result_context(action, ctx)
		yield Warning(message=f"Unknown action: {action_type}", _context=context)


def run_task_from_tool(ctx: ActionContext, name: str, targets=None, opts=None, description=None,
                       runner_type: str = "task") -> Generator:
	"""Run a secator task/workflow FROM an AI tool handler, via the SAME path the built-in
	``run_task`` / ``run_workflow`` tools use.

	A custom AI tool must not invoke a runner ad-hoc; it routes through here so the run gets
	the exact same handling as a model-issued ``run_task``:

	1. the SAME guardrail/permission check as the agent loop (``check_guardrails``): the
	   same deny rules, the same target approval and the same interactive/remote prompt —
	   skipped only when the run is ``dangerous``, exactly like the loop. Being called from
	   an auto-allowed tool grants NOTHING: the task action is checked on its own merits;
	2. then the shared ``_run_runner`` execution (mandate scope propagation, child
	   hook/driver wiring, result capture).

	On denial a Warning is yielded and nothing runs. ``name`` is a task/workflow name
	(built-in or custom — see :func:`secator.loader.get_task_class`).
	"""
	action = {
		"action": runner_type,
		"name": name,
		"targets": list(targets or []),
		"opts": dict(opts or {}),
		"description": description or f"Run {name}",
	}
	if not getattr(ctx, "dangerous", False):
		denial = yield from check_guardrails(action, ctx)
		if denial:
			yield Warning(message=f"{runner_type} {name!r} denied: {denial}",
			              _context=_get_result_context(action, ctx))
			return
	yield from dispatch_action(action, ctx)


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


# Usage counters, in the order (LLM usage key, runner context key, type). The `ai` task
# accumulates every LLM call it makes onto these context keys.
USAGE_COUNTERS = (
	("tokens", "ai_tokens", int),
	("prompt_tokens", "ai_prompt_tokens", int),
	("completion_tokens", "ai_completion_tokens", int),
	("cost", "ai_cost", float),
)

# Context keys that account for ONE run and must never flow from a parent to the
# children it spawns: the usage counters and the subagent budget counters.
_PER_RUN_CONTEXT_KEYS = tuple(ctx_key for _, ctx_key, _ in USAGE_COUNTERS) + (
	"ai_subagent_count",
	"ai_subagent_turn_count",
)


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

	Also STRIPS the parent's per-run accounting keys (``_PER_RUN_CONTEXT_KEYS``): the
	usage counters and the subagent budget describe the PARENT run, so a child that
	inherited them would report the parent's usage as its own.
	"""
	new_ctx = ctx.context.copy()
	for identity_key in ("task_id", "workflow_id", "scan_id", "task_chunk_id"):
		new_ctx.pop(identity_key, None)
	for per_run_key in _PER_RUN_CONTEXT_KEYS:
		new_ctx.pop(per_run_key, None)
	if ctx.session_id and not new_ctx.get("session_id"):
		new_ctx["session_id"] = ctx.session_id
	action_context = {}
	tool_call_id = action.get("tool_call_id")
	tool_call_name = action.get("tool_call_name")
	if tool_call_id:
		action_context["tool_call_id"] = tool_call_id
		action_context["tool_call_name"] = tool_call_name
	return {**new_ctx, **action_context}


@contextmanager
def _batch_executor(ctx: ActionContext, max_workers: int):
	"""Thread pool running a batch's actions.

	A stop (Ctrl-C, revoked task) reaches only the calling thread. When the batch exits before its
	actions are done (a stop, or the caller closing it), cancel the queued actions and stop the
	runners they started.
	"""
	spawned_before = set(ctx.spawned_runners.values())
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		try:
			yield executor
		except BaseException:
			executor.shutdown(wait=False, cancel_futures=True)
			for runner in set(ctx.spawned_runners.values()) - spawned_before:
				if not runner.done:
					runner.stop()
			raise


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
	# A Textual TUI owns the screen and shows its own progress — a Rich Progress Live
	# here would raise "Only one live display may be active at once". Skip it. A Celery
	# worker (headless, client polls the DB) has no use for the Rich panel either and
	# streams instead (see stream_live below), so skip it there too.
	from secator.rich import get_tui
	from secator.definitions import IN_WORKER
	use_progress = not ctx.subagent and not has_ai_subagent and get_tui() is None and not IN_WORKER

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

	# A batch that only yields at the very end looks stuck for its whole duration: no
	# runner cards, no "Running <description>" rows until everything finishes. Stream
	# each action's items (runner card + findings) the moment they're produced whenever
	# there's no Rich progress panel to carry live feedback instead — i.e. under a
	# Textual TUI (owns the screen) OR inside a Celery worker (headless; the client UI
	# polls the persisted docs and wants them incrementally). Only the interactive-CLI
	# Rich-panel path keeps the deterministic sorted-at-end order.
	stream_live = get_tui() is not None or IN_WORKER
	if stream_live:
		# immediate feedback so a parallel batch never looks stuck before the first
		# action finishes (the TUI has no Rich progress panel)
		labels = ", ".join(_get_action_label(a) for a in actions)
		yield Info(message=f"Running {len(actions)} tasks in parallel: {labels}", _context=ctx.context)

	# Stream each action's items the moment they're PRODUCED (not when the action
	# completes), via a thread-safe queue the workers push into. This surfaces every
	# task's "Running <description>" card as its runner starts — so all cards appear up
	# front (up to max_workers), in parallel, instead of trickling in one-per-completion.
	# Items interleave across tasks; the display routes them to the right panel by _source.
	if stream_live:
		import queue as _queue
		q: Any = _queue.Queue()
		done_sentinel = object()

		def run_single_stream(act: Dict) -> None:
			try:
				for item in safe_dispatch_action(act, batch_ctx):
					if isinstance(item, Ai) and item.ai_type == "token_usage":
						continue  # progress-only; no Rich panel under the TUI
					q.put(item)
			finally:
				q.put(done_sentinel)  # always signal completion, even on error

		with _batch_executor(ctx, max_workers) as executor:
			for a in actions:
				executor.submit(run_single_stream, a)
			remaining = len(actions)
			while remaining:
				item = q.get()
				if item is done_sentinel:
					remaining -= 1
					continue
				yield item
		return

	all_results = []
	with ctx_mgr:
		if use_progress:
			for i, act in enumerate(actions):
				label = _get_action_label(act)
				progress_ids[i] = progress.add_task('', label=label, state='[bold cyan]RUNNING[/]', count='', tokens='')

		with _batch_executor(ctx, max_workers) as executor:
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

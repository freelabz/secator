"""Action handlers for AI task."""
import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Tuple

from secator.output_types import Ai, Error, Info, Warning, OutputType, INTERNAL_FIELDS
from secator.template import TemplateLoader
from secator.utils import format_token_count


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
	encryptor: Any = None
	dry_run: bool = False
	verbose: bool = False
	context: Dict = field(default_factory=dict)
	scope: str = "workspace"
	results: Optional[List[Dict]] = None
	max_workers: int = 3
	subagent: bool = False
	silent: bool = False
	sync: bool = True
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


def check_guardrails(action: Dict, ctx: ActionContext) -> Tuple[Optional[str], List[str]]:
	"""Check action against guardrails before dispatching.

	Must be called from the main thread (before batch/parallel execution)
	because it may show interactive prompts.

	Args:
		action: Action dict with 'action' key and parameters
		ctx: Shared action context

	Returns:
		Tuple of (denial_reason, warnings) where denial_reason is None if allowed.
	"""
	if ctx.permission_engine is None:
		return None, []

	# Check for non-existent file paths (warn but don't block)
	from secator.ai.guardrails import detect_paths, classify_command
	from pathlib import Path
	action_type = action.get("action", "")
	warnings = []
	if action_type == "shell":
		cmd = action.get("command", "")
		cmd_name = cmd.split()[0] if cmd.split() else ""
		cmd_class = classify_command(cmd_name)
		if cmd_class == "read":
			for path in detect_paths(cmd):
				try:
					expanded = Path(path).expanduser()
					if not expanded.exists():
						warnings.append(f"Path does not exist: {path}")
				except (OSError, ValueError):
					pass

	result = ctx.permission_engine.check_action(action)
	if result.decision == "deny":
		return f"Action denied by guardrails: {result.reason}", warnings
	elif result.decision == "ask":
		# Handle target prompts
		for target in result.targets:
			decision = ctx.permission_engine.prompt_target(target, interactive=ctx.sync)
			if decision == "deny":
				return f"Action denied: target {target} not approved", warnings
		# Handle path prompts
		for path in result.paths:
			cmd = action.get("command", "")
			cmd_name = cmd.split()[0] if cmd.split() else ""
			cmd_class = classify_command(cmd_name)
			access_type = "write" if cmd_class == "write" else "read"
			decision = ctx.permission_engine.prompt_path(path, access_type, interactive=ctx.sync)
			if decision == "deny":
				return f"Action denied: {access_type} access to {path} not approved", warnings
		# Re-check after prompting
		recheck = ctx.permission_engine.check_action(action)
		if recheck.decision != "allow":
			return f"Action denied after prompt: {recheck.reason}", warnings

	return None, warnings


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
	}

	handler = handlers.get(action_type)
	if handler:
		yield from handler(action, ctx)
	else:
		yield Warning(message=f"Unknown action: {action_type}")


def _run_runner(action: Dict, ctx: ActionContext, runner_type: str) -> Generator:
	"""Execute a secator task or workflow.

	Args:
		action: Action dict with name, targets, opts
		ctx: Action context
		runner_type: Either "task" or "workflow"
	"""
	name = action.get("name", "")
	targets = action.get("targets", ctx.targets)
	opts = action.get("opts", {})

	# Validate runner name before proceeding
	if not name:
		yield Error(message=f"Empty {runner_type} name, skipping action")
		return

	if runner_type == "task":
		from secator.runners import Task
		from secator.loader import discover_tasks
		try:
			Task.get_task_class(name)
		except ValueError:
			available = [cls.__name__ for cls in discover_tasks()]
			yield Error(message=f"Task '{name}' not found. Pick from: {', '.join(sorted(available))}")
			return
		tpl = TemplateLoader(input={'type': 'task', 'name': name})
		runner_cls = Task
	else:
		from secator.runners import Workflow
		from secator.loader import find_templates
		available_wfs = [t['name'] for t in find_templates() if t['type'] == 'workflow']
		if name not in available_wfs:
			yield Error(message=f"Workflow '{name}' not found. Pick from: {', '.join(sorted(available_wfs))}")
			return
		tpl = TemplateLoader(name=f'workflows/{name}')
		runner_cls = Workflow

	# Flatten targets (LLMs sometimes pass nested lists) and decrypt
	flat_targets = []
	for t in targets:
		if isinstance(t, list):
			flat_targets.extend(t)
		else:
			flat_targets.append(t)
	targets = flat_targets
	if ctx.encryptor:
		targets = [ctx.encryptor.decrypt(str(t)) for t in targets]

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run {runner_type}: {name} on {targets}")
		return

	if not ctx.silent:
		yield Ai(content=name, ai_type=runner_type, extra_data={"targets": targets, "opts": opts})

	try:

		run_opts = {
			"print_item": True,
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

		context = ctx.context.copy()
		context["task_chunk_id"] = str(uuid.uuid4())
		tool_call_id = action.get("_tool_call_id")
		if tool_call_id:
			context["tool_call_id"] = tool_call_id
		if ctx.subagent:
			context["subagent"] = ctx.context.get("subagent", True)
		runner = runner_cls(tpl, targets, run_opts=run_opts, context=context)
		yield from runner
		# TODO: verify if yielding raw output would be better than JSON findings
		# yield Ai(content=runner.output, ai_type="shell_output")

	except Exception as e:
		yield Error(message=f"{runner_type.title()} {name} failed: {e}")


def _handle_task(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator task."""
	yield from _run_runner(action, ctx, "task")


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a secator workflow."""
	yield from _run_runner(action, ctx, "workflow")


def _handle_shell(action: Dict, ctx: ActionContext) -> Generator:
	"""Execute a shell command.

	Args:
		action: Action dict with command
		ctx: Action context
	"""
	command = action.get("command", "")

	if ctx.encryptor:
		command = ctx.encryptor.decrypt(command)

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run: {command}")
		return

	yield Ai(content=command, ai_type="shell")

	try:
		result = subprocess.run(
			command,
			shell=True,
			capture_output=True,
			text=True,
			timeout=60
		)
		output = result.stdout or result.stderr or "(no output)"
		yield Ai(content=output, ai_type="shell_output")

	except Exception as e:
		yield Error(message=f"Shell command failed: {e}")


def _handle_query(action: Dict, ctx: ActionContext) -> Generator:
	"""Query workspace or current results for findings.

	Args:
		action: Action dict with query (MongoDB query dict)
		ctx: Action context (scope='current' passes results to QueryEngine in-memory)
	"""
	query_filter = action.get("query", {})
	limit = action.get("limit", 100)

	# Decrypt query values
	if ctx.encryptor:
		query_filter = _decrypt_dict(query_filter, ctx.encryptor)

	if ctx.scope != "current" and not ctx.context.get("workspace_id"):
		yield Warning(message="No workspace available for query")
		return

	try:
		query_str = json.dumps(query_filter, separators=(',', ':'))
		engine = ctx.get_query_engine()
		results = engine.search(query_filter, limit=limit)
		yield Ai(
			content=query_str,
			ai_type="query",
			extra_data={"results": len(results), "limit": limit}
		)
		for result in results:
			clean = {k: v for k, v in result.items() if k not in INTERNAL_FIELDS}
			yield clean

	except Exception as e:
		yield Ai(
			content=str(query_filter),
			ai_type="query",
			extra_data={"results": "failed", "limit": limit}
		)
		yield Error.from_exception(e)


def _handle_follow_up(action: Dict, ctx: ActionContext) -> Generator:
	"""Handle follow-up with user.

	Args:
		action: Action dict with reason and optional choices
		ctx: Action context
	"""
	reason = action.get("reason", "completed")
	choices = action.get("choices", [])
	yield Ai(content=reason, ai_type="follow_up", extra_data={"choices": choices})


def _handle_add_finding(action: Dict, ctx: ActionContext) -> Generator:
	"""Create a secator finding from LLM-provided data.

	Args:
		action: Action dict with _type and finding fields
		ctx: Action context
	"""
	from secator.output_types import FINDING_TYPES

	finding_type = action.get("_type", "")
	finding_data = {k: v for k, v in action.items() if k not in ("action", "_type", "_tool_call_id")}

	# Decrypt field values
	if ctx.encryptor:
		finding_data = _decrypt_dict(finding_data, ctx.encryptor)

	# Resolve _type string to OutputType class
	type_map = {cls.get_name(): cls for cls in FINDING_TYPES}
	cls = type_map.get(finding_type)
	if not cls:
		yield Warning(message=f"Unknown finding type: {finding_type}")
		return

	try:
		finding = cls(**finding_data)
		yield Ai(
			content=f'{str(finding)}',
			ai_type="add_finding",
		)
		yield finding
	except Exception as e:
		yield Error(message=f"Failed to create {finding_type}: {e}")


def _get_action_label(action: Dict) -> str:
	"""Get a display label for an action."""
	act_type = action.get("action", "unknown")
	if act_type in ("task", "workflow"):
		name = action.get("name", "?")
		opts = action.get("opts", {})
		session_name = opts.get("session_name", "")
		if session_name:
			return session_name
		targets = action.get("targets", [])
		target_str = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
		return f"{name} on {target_str}"
	elif act_type == "shell":
		cmd = action.get("command", "")[:40]
		return f"shell: {cmd}"
	return act_type


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

	# Silence console output for parallel tasks to avoid interleaved printing
	batch_ctx = replace(ctx, silent=True)

	# Skip Rich progress panel for subagents to avoid nested LiveError
	use_progress = not ctx.subagent

	# Print all task start messages before any task begins
	if use_progress:
		for act in actions:
			act_type = act.get("action", "")
			if act_type in ("task", "workflow"):
				name = act.get("name", "")
				targets = act.get("targets", ctx.targets)
				ai_start = Ai(content=name, ai_type=act_type, extra_data={"targets": targets, "opts": act.get("opts", {})})
				console.print(ai_start)

	progress = None
	progress_ids = {}

	def run_single(act: Dict, idx: int) -> Dict:
		results = []
		for item in dispatch_action(act, batch_ctx):
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


def _decrypt_dict(d: Dict, encryptor: Any) -> Dict:
	"""Recursively decrypt all string values in a dict.

	Args:
		d: Dictionary to decrypt
		encryptor: SensitiveDataEncryptor instance

	Returns:
		Decrypted dictionary
	"""
	result = {}
	for k, v in d.items():
		if isinstance(v, str):
			result[k] = encryptor.decrypt(v)
		elif isinstance(v, dict):
			result[k] = _decrypt_dict(v, encryptor)
		elif isinstance(v, list):
			result[k] = [
				encryptor.decrypt(i) if isinstance(i, str)
				else _decrypt_dict(i, encryptor) if isinstance(i, dict)
				else i
				for i in v
			]
		else:
			result[k] = v
	return result

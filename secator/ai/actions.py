"""Action handlers for AI task."""
import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

from secator.output_types import Ai, Error, Info, Warning, INTERNAL_FIELDS
from secator.template import TemplateLoader


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
	_query_engine: Any = field(default=None, repr=False)

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

	if ctx.encryptor:
		targets = [ctx.encryptor.decrypt(t) for t in targets]

	if ctx.dry_run:
		yield Info(message=f"[DRY RUN] Would run {runner_type}: {name} on {targets}")
		return

	yield Ai(content=name, ai_type=runner_type, extra_data={"targets": targets, "opts": opts})

	try:
		if runner_type == "task":
			from secator.runners import Task
			tpl = TemplateLoader(input={'type': 'task', 'name': name})
			runner_cls = Task
		else:
			from secator.runners import Workflow
			tpl = TemplateLoader(name=f'workflows/{name}')
			runner_cls = Workflow

		run_opts = {
			"print_item": True,
			"print_line": ctx.verbose,
			"print_cmd": True,
			"print_description": True,
			"print_progress": False,
			"enable_reports": False,
			"exporters": [],
			"sync": True,
			**opts,
		}
		if runner_type == "workflow":
			run_opts["print_start"] = True
			run_opts["print_end"] = True

		runner = runner_cls(tpl, targets, run_opts=run_opts)
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
	finding_data = {k: v for k, v in action.items() if k not in ("action", "_type")}

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

"""Action handlers for AI task."""
import json
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional

from secator.output_types import Ai, Error, Info, Warning, OutputType
from secator.template import TemplateLoader


@dataclass
class ActionContext:
    """Shared context for action execution.

    Attributes:
        targets: List of target hosts/URLs
        model: LLM model name
        encryptor: Optional SensitiveDataEncryptor instance
        dry_run: If True, show actions without executing
        auto_yes: If True, auto-accept prompts
        workspace_id: Optional workspace ID for queries
    """
    targets: List[str]
    model: str
    encryptor: Any = None
    dry_run: bool = False
    auto_yes: bool = False
    workspace_id: Optional[str] = None


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
        "done": _handle_done,
    }

    handler = handlers.get(action_type)
    if handler:
        yield from handler(action, ctx)
    else:
        yield Warning(message=f"Unknown action: {action_type}")


def _handle_task(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a secator task.

    Args:
        action: Action dict with name, targets, opts
        ctx: Action context
    """
    name = action.get("name", "")
    targets = action.get("targets", ctx.targets)
    opts = action.get("opts", {})

    # Decrypt targets if encryptor present
    if ctx.encryptor:
        targets = [ctx.encryptor.decrypt(t) for t in targets]

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run task: {name} on {targets}")
        return

    yield Ai(content=f"Running task: {name}", ai_type="task", extra_data={"targets": targets})

    try:
        from secator.runners import Task
        tpl = TemplateLoader(input={'type': 'task', 'name': name})
        run_opts = {
            "print_item": False,
            "print_line": False,
            "print_cmd": False,
            "print_progress": False,
            "exporters": [],
            "sync": True,
            **opts,
        }

        task = Task(tpl, targets, run_opts=run_opts)
        for item in task:
            if item not in FINDING_TYPES + [Info, Warning, Error]:
                continue
            result = item.toDict()
            result.pop('_context')
            result.pop('_uuid')
            result.pop('_related')
            result.pop('_duplicate')
            yield result

    except Exception as e:
        yield Error(message=f"Task {name} failed: {e}")


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a secator workflow.

    Args:
        action: Action dict with name, targets
        ctx: Action context
    """
    name = action.get("name", "")
    targets = action.get("targets", ctx.targets)
    opts = action.get("opts", {})

    if ctx.encryptor:
        targets = [ctx.encryptor.decrypt(t) for t in targets]

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run workflow: {name} on {targets}")
        return

    yield Ai(content=f"Running workflow: {name}", ai_type="workflow", extra_data={"targets": targets})

    try:
        from secator.runners import Workflow
        tpl = TemplateLoader(name=f'workflows/{name}')
        run_opts = {
            "print_item": True,
            "print_line": False,
            "print_cmd": True,
            "print_description": True,
            "print_start": True,
            "print_end": True,
            "print_progress": False,
            "exporters": [],
            "sync": True,
            **opts,
        }

        workflow = Workflow(tpl, targets, run_opts=run_opts)
        for item in workflow:
            if item not in FINDING_TYPES + [Info, Warning, Error]:
                continue
            result = item.toDict()
            result.pop('_context')
            result.pop('_uuid')
            result.pop('_related')
            result.pop('_duplicate')
            yield result

    except Exception as e:
        yield Error(message=f"Workflow {name} failed: {e}")


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

    yield Ai(content=f"Running: {command}", ai_type="shell")

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
    """Query workspace for findings.

    Args:
        action: Action dict with query (MongoDB query dict)
        ctx: Action context
    """
    query_filter = action.get("query", {})

    # Decrypt query values
    if ctx.encryptor:
        query_filter = _decrypt_dict(query_filter, ctx.encryptor)

    if not ctx.workspace_id:
        yield Warning(message="No workspace available for query")
        return

    try:
        from secator.query import QueryEngine
        from secator.output_types import OUTPUT_TYPES
        engine = QueryEngine(ctx.workspace_id)
        results = engine.search(query_filter, limit=50)
        query_str = json.dumps(query_filter, separators=(',', ':'))
        yield Ai(
	        content=f"Query: {query_str} --> {len(results)} results",
	        ai_type="query"
	    )
        for result in results:
            result.pop('_context')
            result.pop('_uuid')
            result.pop('_related')
            result.pop('_duplicate')
            yield result

    except Exception as e:
        yield Ai(
	        content=f"Query: {query_str} --> failed",
	        ai_type="query"
	    )
        yield Error.from_exception(e)


def _handle_done(action: Dict, ctx: ActionContext) -> Generator:
    """Handle completion.

    Args:
        action: Action dict with reason
        ctx: Action context
    """
    reason = action.get("reason", "completed")
    yield Ai(content=f"Done: {reason}", ai_type="stopped")


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
            result[k] = [encryptor.decrypt(i) if isinstance(i, str) else i for i in v]
        else:
            result[k] = v
    return result

"""Action handlers for AI task."""
import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

from secator.output_types import Ai, Error, Info, Warning


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
        attack_context: Mutable dict for tracking attack state
    """
    targets: List[str]
    model: str
    encryptor: Any = None
    dry_run: bool = False
    auto_yes: bool = False
    workspace_id: Optional[str] = None
    attack_context: Dict = field(default_factory=dict)


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
        task_cls = Task.get_task_class(name)

        run_opts = {
            "print_item": False,
            "print_line": False,
            "print_cmd": False,
            "print_progress": False,
            "sync": True,
            **opts,
        }

        task = task_cls(targets, **run_opts)
        results = []
        for item in task:
            results.append(item)
            yield item

        # Track in attack context
        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "task",
            "name": name,
            "targets": targets,
            "result_count": len(results)
        })

    except Exception as e:
        yield Error(message=f"Task {name} failed: {e}")
        ctx.attack_context.setdefault("failed_attacks", []).append({
            "type": "task",
            "name": name,
            "error": str(e)
        })


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a secator workflow.

    Args:
        action: Action dict with name, targets
        ctx: Action context
    """
    name = action.get("name", "")
    targets = action.get("targets", ctx.targets)

    if ctx.encryptor:
        targets = [ctx.encryptor.decrypt(t) for t in targets]

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run workflow: {name} on {targets}")
        return

    yield Ai(content=f"Running workflow: {name}", ai_type="workflow", extra_data={"targets": targets})

    try:
        from secator.runners import Workflow
        workflow = Workflow(targets, name=name, sync=True)
        results = []
        for item in workflow:
            results.append(item)
            yield item

        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "workflow",
            "name": name,
            "targets": targets,
            "result_count": len(results)
        })

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
        yield Ai(content=output[:2000], ai_type="shell_output")

        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "shell",
            "command": command,
            "output": output[:500]
        })

    except Exception as e:
        yield Error(message=f"Shell command failed: {e}")


def _handle_query(action: Dict, ctx: ActionContext) -> Generator:
    """Query workspace for findings.

    Args:
        action: Action dict with type and filter
        ctx: Action context
    """
    query_filter = action.get("filter", {})
    output_type = action.get("type", "")

    if output_type:
        query_filter["_type"] = output_type

    # Decrypt query values
    if ctx.encryptor:
        query_filter = _decrypt_dict(query_filter, ctx.encryptor)

    yield Ai(
        content=f"Query: {json.dumps(query_filter, separators=(',', ':'))}",
        ai_type="query"
    )

    if not ctx.workspace_id:
        yield Warning(message="No workspace available for query")
        return

    try:
        from secator.query import QueryEngine
        engine = QueryEngine(ctx.workspace_id)
        results = engine.search(query_filter, limit=50)
        yield Info(message=f"Query returned {len(results)} results")

        # Store for next iteration
        ctx.attack_context["_query_results"] = results

    except Exception as e:
        yield Error(message=f"Query failed: {e}")


def _handle_done(action: Dict, ctx: ActionContext) -> Generator:
    """Handle completion.

    Args:
        action: Action dict with reason
        ctx: Action context
    """
    reason = action.get("reason", "completed")
    yield Ai(content=f"Done: {reason}", ai_type="stopped")
    ctx.attack_context["_should_stop"] = True


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

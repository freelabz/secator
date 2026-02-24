"""Compact prompt templates for AI task."""
import json
from typing import Any, List

# System prompt for attack mode (~400 tokens)
SYSTEM_ATTACK = """Security testing assistant. Execute actions against provided targets.

RESPONSE FORMAT:
1. Brief reasoning (2-3 sentences max)
2. JSON array of actions

ACTIONS:
- task: {{"action":"task","name":"<tool>","targets":[...],"opts":{{}}}}
- workflow: {{"action":"workflow","name":"<name>","targets":[...]}}
- shell: {{"action":"shell","command":"<cmd>"}}
- query: {{"action":"query","type":"<output_type>","filter":{{}}}}
- done: {{"action":"done","reason":"<why>"}}

RULES:
- One action array per response
- Never invent tool output
- Use workspace queries to get historical workspace data to get more context if needed
- Targets are encrypted as [HOST:xxxx] - use as-is

TOOLS: {tools}
WORKFLOWS: {workflows}
WORKSPACE QUERIES: "type" can be any of "url", "vulnerability", "tag", "ip", "ai", "user_account", "domain", "subdomain"
"""

# System prompt for chat mode (~200 tokens)
SYSTEM_CHAT = """Security assistant for workspace queries and analysis.

RESPONSE FORMAT: Markdown explanation, then optional JSON action.

ACTIONS:
- query: {{"action":"query","type":"<type>","filter":{{}}}}
- done: {{"action":"done"}}

Answer questions using workspace data. Use query action to fetch data."""


def get_tools_list() -> str:
    """Get comma-separated list of available tasks."""
    from secator.loader import discover_tasks
    tasks = discover_tasks()
    return ", ".join(sorted(t.__name__ for t in tasks if t.__name__ != "Ai"))


def get_workflows_list() -> str:
    """Get comma-separated list of available workflows."""
    from secator.loader import get_configs_by_type
    workflows = get_configs_by_type('workflow')
    return ", ".join(sorted(w.name for w in workflows))


def build_tasks_reference() -> str:
    """Build compact task reference: name|description|options."""
    from secator.loader import discover_tasks
    from secator.definitions import OPT_NOT_SUPPORTED

    lines = []
    for task_cls in sorted(discover_tasks(), key=lambda t: t.__name__):
        if task_cls.__name__.lower() == "ai":
            continue
        name = task_cls.__name__
        desc = (task_cls.__doc__ or "").strip().split('\n')[0][:50]

        # Get task-specific options
        task_opts = list(getattr(task_cls, 'opts', {}).keys())

        # Get generic options that this task supports
        opt_key_map = getattr(task_cls, 'opt_key_map', {})
        generic_opts = [k for k, v in opt_key_map.items() if v is not None and v != OPT_NOT_SUPPORTED]

        all_opts = ",".join(sorted(set(task_opts + generic_opts)))
        lines.append(f"{name}|{desc}|{all_opts}")

    return "\n".join(lines)


def build_workflows_reference() -> str:
    """Build compact workflow reference: name|description."""
    from secator.loader import get_configs_by_type
    workflows = get_configs_by_type('workflow')
    lines = []
    for w in sorted(workflows, key=lambda x: x.name):
        desc = getattr(w, 'description', '') or ''
        lines.append(f"{w.name}|{desc}")
    return "\n".join(lines)


def build_profiles_reference() -> str:
    """Build compact profiles reference: name|description."""
    from secator.loader import get_configs_by_type
    profiles = get_configs_by_type('profile')
    lines = []
    for p in sorted(profiles, key=lambda x: x.name):
        desc = getattr(p, 'description', '') or ''
        lines.append(f"{p.name}|{desc}")
    return "\n".join(lines)


def get_system_prompt(mode: str) -> str:
    """Get system prompt for mode with tools/workflows filled in.

    Args:
        mode: Either "attack" or "chat"

    Returns:
        Formatted system prompt string
    """
    if mode == "attack":
        return SYSTEM_ATTACK.format(
            tools=get_tools_list(),
            workflows=get_workflows_list()
        )
    elif mode == "chat":
        return SYSTEM_CHAT
    else:
        return SYSTEM_CHAT


def format_user_initial(targets: List[str], instructions: str) -> str:
    """Format initial user message as compact JSON.

    Args:
        targets: List of target hosts/URLs
        instructions: User instructions for the task

    Returns:
        Compact JSON string (no whitespace)
    """
    return json.dumps({
        "targets": targets,
        "instructions": instructions or "Conduct security testing."
    }, separators=(',', ':'))


def format_tool_result(name: str, status: str, count: int, results: Any) -> str:
    """Format tool result as compact JSON.

    Args:
        name: Tool/task name
        status: Execution status (success/error)
        count: Number of results
        results: Full results from the action

    Returns:
        Compact JSON string
    """
    return json.dumps({
        "task": name,
        "status": status,
        "count": count,
        "results": results
    }, separators=(',', ':'), default=str)


def format_continue(iteration: int, max_iterations: int) -> str:
    """Format continue message as compact JSON.

    Args:
        iteration: Current iteration number
        max_iterations: Maximum iterations allowed

    Returns:
        Compact JSON string
    """
    return json.dumps({
        "iteration": iteration,
        "max": max_iterations,
        "instruction": "continue"
    }, separators=(',', ':'))

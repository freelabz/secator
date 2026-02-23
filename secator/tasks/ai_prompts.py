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
- Use query to check results before concluding
- Targets are encrypted as [HOST:xxxx] - use as-is

TOOLS: {tools}
WORKFLOWS: {workflows}"""

# System prompt for chat mode (~200 tokens)
SYSTEM_CHAT = """Security assistant for workspace queries and analysis.

RESPONSE FORMAT: Markdown explanation, then optional JSON action.

ACTIONS:
- query: {{"action":"query","type":"<type>","filter":{{}}}}
- done: {{"action":"done"}}

Answer questions using workspace data. Use query action to fetch data."""


def get_tools_list() -> str:
    """Get comma-separated list of available tasks."""
    try:
        from secator.loader import discover_tasks
        tasks = discover_tasks()
        return ", ".join(sorted(t.__name__ for t in tasks))
    except Exception:
        return "nmap, httpx, nuclei, ffuf, katana, subfinder"


def get_workflows_list() -> str:
    """Get comma-separated list of available workflows."""
    try:
        from secator.loader import get_configs_by_type
        workflows = get_configs_by_type('workflow')
        return ", ".join(sorted(w.name for w in workflows))
    except Exception:
        return "host_recon, subdomain_recon, url_crawl"


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


def format_tool_result(name: str, status: str, count: int, sample: Any) -> str:
    """Format tool result as compact JSON.

    Args:
        name: Tool/task name
        status: Execution status (success/error)
        count: Number of results
        sample: Sample of results (will be truncated to 3 items if list)

    Returns:
        Compact JSON string
    """
    return json.dumps({
        "task": name,
        "status": status,
        "count": count,
        "sample": sample[:3] if isinstance(sample, list) else sample
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

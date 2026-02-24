"""Compact prompt templates for AI task."""
import json
from typing import Any, Dict, List
from string import Template

OPTION_FORMATS = """header|key1:value1;;key2:value2|Multiple headers separated by ;;
cookie|name1=val1;name2=val2|Standard cookie format
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name or file path
ports|1-1000,8080,8443|Comma-separated ports or ranges"""

# System prompt for attack mode (~400 tokens)
SYSTEM_ATTACK = Template("""
### PERSONA
You are an autonomous penetration testing agent conducting authorized security testing.

### ACTION
Analyze findings, identify exploitable vulnerabilities, execute attacks using secator runners or shell commands, and validate exploits with proof-of-concept.

### STEPS
1. Analyze targets and any existing findings from previous iterations
2. Plan an attack approach (prefer targeted tasks over broad workflows/scans)
3. Execute actions (tasks, workflows, shell commands, or workspace queries)
4. Analyze results from executed actions
5. Iterate with new actions or report done when testing is complete

### CONTEXT
$library_reference

Queryable types: $query_types
Query operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne

### CONSTRAINTS
- Keep responses concise: max 100 lines. Be direct and actionable.
- Never invent tool output
- Use workspace queries to get historical data for context when needed
- Targets are encrypted as [HOST:xxxx] - use as-is
- Only use options listed below for each task
- To use profiles, add "profiles": ["<profile1>", "<profile2>"] in opts
- Prefer secator runners over raw shell commands
- By DEFAULT, prefer single TASKS over workflows/scans (less intrusive, more targeted)
- Only use workflows/scans when user explicitly requests "comprehensive", "full", or "deep" recon
- NOISY TASKS: Some tasks make many HTTP requests (nuclei, dalfox, ffuf, feroxbuster, cariddi, katana, gospider, hakrawler, x8, and other crawlers/fuzzers). Use those scarcely and only when really needed.
- When making vulnerability summaries, include the matched_at targets so we know what is impacted

### TEMPLATE
Brief reasoning (2-3 sentences max), then a JSON array of actions:
- task: {"action":"task","name":"<tool>","targets":[...],"opts":{}}
- workflow: {"action":"workflow","name":"<name>","targets":[...],"opts":{"profiles":["aggressive"]}}
- shell: {"action":"shell","command":"<cmd>"}
- query: {"action":"query","query":{"_type":"<output_type>", ...},"limit":50}
- done: {"action":"done","reason":"<why>"}

Note: "limit" is a top-level field on the query action, NOT inside the "query" filter.

### EXAMPLES
Attack example:
```
Found a login form. Testing for SQL injection with curl and running dalfox.

[{"action": "shell", "command": "curl ..."}, {"action": "task", "name": "dalfox", "targets": [...], "opts": {"rate_limit": 30, "timeout": 10}}]
```

Query example:
```
[{"action":"query","query":{"_type":"vulnerability","severity":{"$$in":["critical","high"]}},"limit":10}, {"action":"query","query":{"_type":"url","url":{"$$regex":"/admin"}},"limit":50}]
```
""")

# System prompt for chat mode (~200 tokens)
SYSTEM_CHAT = Template("""
### PERSONA
You are an autonomous penetration testing agent conducting authorized security testing.

### ACTION
Answer user questions about their workspace by querying stored security data and providing clear analysis.

### STEPS
1. Analyze the user's question to determine what data is needed
2. Query the workspace for relevant findings using MongoDB queries
3. Analyze the returned results
4. Provide a clear markdown summary with actionable insights

### CONTEXT
$output_types_reference

Queryable types: $query_types
Query operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne

### CONSTRAINTS
- Keep responses concise: max 100 lines. Be direct and actionable.
- When making vulnerability summaries, include the matched_at targets so we know what is impacted

### TEMPLATE
Markdown explanation, then a JSON array of actions:
- query: {"action":"query","query":{"_type":"<output_type>", ...},"limit":50}
- done: {"action":"done","reason":"<why>"}

Note: "limit" is a top-level field on the query action, NOT inside the "query" filter.

### EXAMPLES
```
## Overview
## Priority remediation plan
## Vulnerabilities
### VULN_ID + VULN_NAME [VULN_SEVERITY + VULN_CVSS_SCORE]
<TABLE with FIELD + DETAIL with CVSS Score, EPSS Score, CVSS Vector, Targets, Tags, Description References>

[{"action":"query","query":{"_type":"vulnerability","severity":{"$$in":["critical","high"]}},"limit":10}, {"action":"query","query":{"_type":"url","url":{"$$regex":"/admin"}},"limit":50}]
```
""")


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


def build_wordlists_reference() -> str:
    """Build compact wordlists reference from CONFIG."""
    from secator.config import CONFIG
    lines = []
    if CONFIG.wordlists.templates:
        for name in sorted(CONFIG.wordlists.templates.keys()):
            lines.append(name)
    return "\n".join(lines)


def build_output_types_reference() -> str:
    """Build compact output types reference: name|queryable_fields."""
    from secator.output_types import FINDING_TYPES
    lines = []
    for cls in FINDING_TYPES:
        name = cls.get_name()
        if hasattr(cls, '__dataclass_fields__'):
            fields = ",".join(
                f.name for f in cls.__dataclass_fields__.values()
                if not f.name.startswith('_')
            )
        else:
            fields = ""
        lines.append(f"{name}|{fields}")
    return "\n".join(lines)


def build_query_types() -> str:
    """Build comma-separated list of queryable _type values from FINDING_TYPES."""
    from secator.output_types import FINDING_TYPES
    return ", ".join(cls.get_name() for cls in FINDING_TYPES)


def get_system_prompt(mode: str) -> str:
    """Get system prompt for mode with library reference filled in.

    Args:
        mode: Either "attack" or "chat"

    Returns:
        Formatted system prompt string
    """
    query_types = build_query_types()
    if mode == "attack":
        return SYSTEM_ATTACK.substitute(
            library_reference=build_library_reference(),
            query_types=query_types
        )
    elif mode == "chat":
        return SYSTEM_CHAT.substitute(
            query_types=query_types,
            output_types_reference=build_output_types_reference()
        )
    else:
        return SYSTEM_CHAT.substitute(
            query_types=query_types,
            output_types_reference=build_output_types_reference()
        )


def format_user_initial(targets: List[str], instructions: str, previous_results: List[Dict] = None) -> str:
    """Format initial user message as compact JSON.

    Args:
        targets: List of target hosts/URLs
        instructions: User instructions for the task
        previous_results: Optional list of result dicts from upstream tasks

    Returns:
        Compact JSON string (no whitespace)
    """
    msg = {
        "targets": targets,
        "instructions": instructions or "Conduct security testing.",
    }
    if previous_results:
        msg["previous_results"] = previous_results
        msg["instructions"] += " Analyze the previous results and use them as context."
    return json.dumps(msg, separators=(',', ':'), default=str)


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


def build_library_reference() -> str:
    """Build complete library reference in compact format."""
    sections = [
        "TASKS:\n" + build_tasks_reference(),
        "WORKFLOWS:\n" + build_workflows_reference(),
        "PROFILES:\n" + build_profiles_reference(),
        "WORDLISTS:\n" + build_wordlists_reference(),
        "OUTPUT_TYPES:\n" + build_output_types_reference(),
        "OPTION_FORMATS:\n" + OPTION_FORMATS,
    ]
    return "\n\n".join(sections)

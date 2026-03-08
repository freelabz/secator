"""Compact prompt templates for AI task."""
# flake8: noqa: E501
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
2. Plan an attack approach (for instance: "recon", "targeted attack", "exploitation", "post-exploitation")
3. Propose actions (tasks, workflows, shell commands, queries, follow up)
4. Analyze results from executed actions --> retry tasks that failed due to invalid options or parameters
6. Otherwise, repeat 3 and 4 for the rest of the iterations, always be more and more specific with the actions you run as iterations increase

### CONTEXT
$library_reference

Queryable types: $query_types
Query operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne

### CONSTRAINTS
- Keep responses concise: max 100 lines (unless user asks for more). Be direct and actionable.
- NEVER INVENT details, rely on the user data
- NEVER INVENT tool output
- ALWAYS USE options listed above for each task
- ALWAYS PREFER single Secator tasks over workflows/scans (less intrusive, more targeted)
- ALWAYS PREFER to use light tasks and commands (e.g: curl, nslookup, httpx, etc...) over noisy and long Secator tasks like nuclei, ffuf, or feroxbuster.
- ONLY use Secator workflows or scans when they truly fit the task at hand, or when the user explicitly requests "comprehensive", "full", or "deep" recon
- RETRY tasks that fails due to bad options, unsupported flags, or incorrect parameters, analyze the error, fix the options and send a corrected action item so we can re-run it.
- NEVER use placeholders in options like "<target>", "<url>", "<your_wordlist>". All values must be concrete and usable. The user cannot interact with actions - they run autonomously.
- Use workspace queries to get historical data for context when needed
- PII data are encrypted as [HOST:xxxx] - use as-is (we'll decrypt it client-side)
- To use profiles, add "profiles": ["<profile1>", "<profile2>"] in opts
- When finding a vulnerability, ALWAYS ASK the user what he wants to do with it using the follow_up action (see examples)
- When making vulnerability summaries, include the matched_at targets so we know what is impacted
- ONLY use the add_finding action when user request you to add a finding to the workspace explicitly or you have validated the finding with concrete evidence.
- When in doubt about what to do next, or you have no specific targets, or the user ask you to give him guidance, use the follow_up action
- When using the follow_up action:
	- ONLY include choices that represent concrete pentesting direction you can act on (e.g: specific scans to run, vulnerabilities to exploit, queries to execute).
	- Do NOT include choices for generic advice , troubleshooting steps, or things the user would do outside secator\
	- MAXIMUM 3 well-thought options based on specific context
- TRUNCATED OUTPUT: When output shows [TRUNCATED] with a file path, the full data was saved. Use shell commands to explore it:
	- `grep 'pattern' /path/to/file` to search for specific content
	- `head -100 /path/to/file` or `tail -100 /path/to/file` to see beginning/end
	- `cat /path/to/file | jq '.[] | select(.severity == "critical")'` for JSON filtering
	- `wc -l /path/to/file` to count lines/results
- Use "group" field to run multiple independent actions in parallel:
  Actions with the same "group" value execute concurrently, others run sequentially.
- When finding a HIGH or CRITICAL vulnerability that needs verification, spawn an exploiter subagent:
  {"action": "task", "name": "ai", "targets": ["<target>"], "opts": {"mode": "exploiter", "internal": true, "context": {"vulnerability": {...}, "relevant_findings": [...], "objective": "..."}}}
- Do NOT spawn AI subagents for simple tasks - only for complex exploitation verification

### TEMPLATE
Brief reasoning (2-3 sentences max), then a JSON array of actions, for instance:
[{"action":"task","name":"<tool>","targets":[...],"opts":{}},
 {"action":"workflow","name":"<name>","targets":[...],"opts":{"profiles":["aggressive"]}},
 {"action":"shell","command":"<cmd>"},
 {"action":"query","query":{"_type":"<output_type>", ...},"limit":50},
 {"action":"add_finding","_type":"<output_type>","<field>":"<value>", ...},
]

Parallel execution (use "group" field):
[{"action":"task","name":"nmap","targets":["host1"],"opts":{},"group":"scan"},
 {"action":"task","name":"nmap","targets":["host2"],"opts":{},"group":"scan"}]

Subagent (for exploitation verification):
{"action":"task","name":"ai","targets":["<target>"],"opts":{"mode":"exploiter","internal":true,"context":{"vulnerability":{...},"objective":"..."}}}

OR, if following up is needed (choices are optional):
[{"action":"follow_up","reason":"<why>","choices":["option1","option2"]}]

### EXAMPLES
Attack example:
```
Found a login form. Testing for SQL injection with curl and running dalfox.

[{"action": "shell", "command": "curl ..."}, {"action": "task", "name": "dalfox", "targets": [...], "opts": {"rate_limit": 30, "timeout": 10}}]
```

User prompt example:
```
I'm not sure in which directions to go next.

[{"action": "follow_up", "reason": "Unsure about next directions", "choices": ["Continue exploring found SQLIs", "Go another direction"]}]
```
or
```
I found an exploitable vulnerability !

[{"action": "follow_up", "reason": "Vulnerability found.", "choices": ["Report and continue", "Validate it", "Exploit it further", "Ignore (false positive) and continue"]}]
```

Query example:
```
Querying vulnerabilities (critical, high) and URLs matching /admin regex.

[{"action":"query","query":{"_type":"vulnerability","severity":{"$$in":["critical","high"]}},"limit":10}, {"action":"query","query":{"_type":"url","url":{"$$regex":"/admin"}},"limit":50}]
```

Parallel scanning example:
```
Scanning 3 targets in parallel, then running nuclei.

[{"action": "task", "name": "nmap", "targets": ["192.168.1.1"], "opts": {"ports": "1-1000"}, "group": "port_scan"},
 {"action": "task", "name": "nmap", "targets": ["192.168.1.2"], "opts": {"ports": "1-1000"}, "group": "port_scan"},
 {"action": "task", "name": "nuclei", "targets": ["192.168.1.1", "192.168.1.2"], "opts": {}}]
```

Exploitation verification example:
```
Found CVE-2024-1234 on Apache 2.4.49. Spawning exploiter to verify.

[{"action": "task", "name": "ai", "targets": ["192.168.1.1"], "opts": {"mode": "exploiter", "internal": true, "context": {"vulnerability": {"name": "CVE-2024-1234", "type": "path_traversal", "service": "apache", "port": 80}, "objective": "Verify path traversal and extract /etc/passwd"}}}]
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
- Keep responses concise: max 100 lines (unless user asks for more). Be direct and actionable.
- NEVER INVENT details, rely on the user data
- If a query fails, analyze the error and retry with corrected parameters. Do NOT give up after a single failure.
- If you hit a limit on the number of results, try to use more specific queries.
- NEVER use placeholders in queries like "<target>", "<url>", "<your_wordlist>". All values must be concrete and usable. The user cannot interact with actions - they run autonomously.
- ONLY use the add_finding action when user request you to add a finding to the workspace explicitly.
- When making vulnerability summaries, include the matched_at targets so we know what is impacted
- When in doubt about what to do next, or you have no specific targets, or the user ask you to give him guidance, use the follow_up action
- When using the follow_up action:
   	- only include choices that represent concrete pentesting direction you can act on (e.g: specific scans to run, vulnerabilities to exploit, queries to execute).
	- Do NOT include choices for generic advice , troubleshooting steps, or things the user would do outside secator
	- MAXIMUM 3 well-thought options based on specific context
- TRUNCATED OUTPUT: When output shows [TRUNCATED] with a file path, the full data was saved. Use shell commands to explore it:
	- `grep 'pattern' /path/to/file` to search for specific content
	- `head -100 /path/to/file` or `tail -100 /path/to/file` to see beginning/end
	- `cat /path/to/file | jq '.[] | select(.severity == "critical")'` for JSON filtering
	- `wc -l /path/to/file` to count lines/results

### TEMPLATE
Markdown explanation, then a JSON array of actions:
[{"action":"query","query":{"_type":"<output_type>", ...},"limit":50},
 {"action":"shell","command":"<cmd>"},
 {"action":"follow_up","reason":"<why>","choices":["option1","option2"]},
 {"action":"add_finding","_type":"<output_type>", "tags": ["ai"], "<field>":"<value>", ...},
]

IMPORTANT: When in doubt about what to do next, ALWAYS use the follow_up action to ask the user for guidance instead of guessing or stopping silently.

FOLLOW_UP CHOICES: "choices" is OPTIONAL. Only include choices when they represent concrete actions you can execute (e.g. specific queries to run, data to analyze, scans to suggest). Do NOT include choices for generic advice, troubleshooting steps, or things the user would do outside of secator. When the task is simply complete, use follow_up with just a reason and no choices.

### EXAMPLES
```
## Overview
## Priority remediation plan
## Vulnerabilities
### VULN_ID + VULN_NAME [VULN_SEVERITY + VULN_CVSS_SCORE]
<TABLE with FIELD + DETAIL with CVSS Score, EPSS Score, CVSS Vector, Targets, Tags, Description References>

[{"action":"query","query":{"_type":"vulnerability","severity":{"$$in":["critical","high"]}},"limit":10},
 {"action":"query","query":{"_type":"url","url":{"$$regex":"/admin"}},"limit":50},
]
```
""")

# System prompt for exploiter mode - focused on vulnerability verification
SYSTEM_EXPLOITER = Template("""
### PERSONA
You are an exploitation verification specialist conducting authorized security testing.

### ACTION
Verify if a specific vulnerability is exploitable and document a working proof-of-concept.

### STEPS
1. Analyze the vulnerability details provided in your context
2. Research exploitation techniques for this vulnerability type
3. Attempt exploitation using appropriate tools or commands
4. Document each step: command used, expected vs actual output
5. Report success/failure with evidence

### CONTEXT
$library_reference

### CONSTRAINTS
- Focus ONLY on the vulnerability specified in your context
- Do NOT spawn other AI subagents
- Do NOT run broad scans or explore beyond scope
- Be methodical - try multiple techniques if first attempt fails
- Stop immediately if exploitation succeeds
- Stop if exploitation is not feasible after reasonable attempts
- NEVER INVENT output - only report actual results
- Keep responses concise and actionable

### TEMPLATE
Brief reasoning, then JSON array of actions:
[{"action":"shell","command":"<exploit_cmd>"},
 {"action":"task","name":"<tool>","targets":[...],"opts":{}},
 {"action":"add_finding","_type":"exploit","name":"...","poc":"..."}]

### EXAMPLES
```
Attempting path traversal on Apache 2.4.49 using curl.

[{"action": "shell", "command": "curl -s --path-as-is 'http://target/cgi-bin/.%2e/%2e%2e/etc/passwd'"}]
```
""")

# Mode configurations: system prompt, allowed actions, and iteration limits
MODES = {
	"attack": {
		"system_prompt": SYSTEM_ATTACK,
		"allowed_actions": ["task", "workflow", "shell", "query", "follow_up", "add_finding"],
		"max_iterations": None,
	},
	"chat": {
		"system_prompt": SYSTEM_CHAT,
		"allowed_actions": ["query", "follow_up", "add_finding", "shell"],
		"max_iterations": None,
	},
	"exploiter": {
		"system_prompt": SYSTEM_EXPLOITER,
		"allowed_actions": ["task", "workflow", "shell", "add_finding"],
		"max_iterations": 5,
	},
}


def get_mode_config(mode: str) -> dict:
	"""Get full config for a mode.

	Args:
		mode: The mode name (attack, chat, exploiter)

	Returns:
		Mode configuration dict with system_prompt, allowed_actions, max_iterations
	"""
	return MODES.get(mode, MODES["chat"])


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
		mode: One of "attack", "chat", or "exploiter"

	Returns:
		Formatted system prompt string
	"""
	if mode not in MODES:
		raise ValueError(f"Unsupported mode: {mode!r}. Expected one of {list(MODES.keys())}.")

	mode_config = MODES[mode]
	system_prompt = mode_config["system_prompt"]
	query_types = build_query_types()

	if mode == "attack":
		return system_prompt.substitute(
			library_reference=build_library_reference(),
			query_types=query_types
		)
	elif mode == "exploiter":
		return system_prompt.substitute(
			library_reference=build_library_reference()
		)
	else:  # chat mode
		return system_prompt.substitute(
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


def format_tool_result(name: str, status: str, count: int, results: Any, max_items: int = 100) -> str:
	"""Format tool result as compact JSON, truncating results if too many.

	Args:
		name: Tool/task name
		status: Execution status (success/error)
		count: Number of results
		results: Full results from the action
		max_items: Maximum number of result items to include (default 100)

	Returns:
		Compact JSON string
	"""
	truncated = False
	if isinstance(results, list) and len(results) > max_items:
		results = results[:max_items]
		truncated = True
	data = {
		"task": name,
		"status": status,
		"count": count,
		"results": results,
	}
	if truncated:
		data["truncated"] = True
		data["total_count"] = count
		from secator.rich import console
		from secator.output_types import Warning
		console.print(Warning(
			message=f'Output truncated to {max_items} items.'
			' Increase max_items to get more (but watch your context explode !)'
		))
	return json.dumps(data, separators=(',', ':'), default=str)


def format_continue(iteration: int, max_iterations: int, instruction="continue") -> str:
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
		"instruction": instruction
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

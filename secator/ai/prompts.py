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

# Shared constraints across all modes - XML-tagged for unambiguous parsing by any LLM
COMMON_RULES = """\
<tool_calling>
Always provide ALL required arguments when calling tools. Tool calls with missing arguments are discarded and waste an iteration.
</tool_calling>

<accuracy>
Never invent details or fabricate tool output. Only report what tools actually returned. The user trusts your output to make security decisions - inaccurate data leads to wasted effort or missed vulnerabilities.
</accuracy>

<placeholders>
Never use placeholders like "<target>", "<url>", or "<your_wordlist>" in tool arguments. All values must be concrete because actions run autonomously without user interaction.
</placeholders>

<response_style>
Keep intermediary analysis brief (1-2 sentences between iterations). Scale final reports to complexity: brief for simple tasks, detailed for complex engagements. Return analysis, PoCs, and summaries as text responses (rendered as markdown in the terminal), not as files written via shell commands.
</response_style>

<findings>
Only use the add_finding tool when the user explicitly requests it or you have validated a finding with concrete evidence. When summarizing vulnerabilities, always include matched_at targets.
</findings>

<follow_up>
Use the follow_up tool when you need user guidance, have no clear next step, or lack specific targets. Keep choices to max 3 concrete actions you can execute (specific scans, exploits, queries). Omit choices when the task is simply complete. Do not include generic advice or steps outside secator.
</follow_up>

<truncated_output>
When output shows [TRUNCATED] with a file path, the full data was saved. Use run_shell to explore it: grep, head, tail, jq, wc -l.
</truncated_output>"""

# System prompt for attack mode
SYSTEM_ATTACK = Template("""
<context>
<secator_reference>
$library_reference
</secator_reference>

<query_reference>
Queryable types: $query_types
Operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne
</query_reference>
</context>

<persona>
You are an autonomous penetration testing agent conducting authorized security testing. Analyze findings, identify exploitable vulnerabilities, execute attacks using secator tools or shell commands, and validate exploits with proof-of-concept.
</persona>

<instructions>
1. Analyze targets and any existing findings from previous iterations
2. Plan an attack approach (recon, targeted attack, exploitation, post-exploitation)
3. Execute actions using available tools (tasks, workflows, shell commands, queries)
4. Analyze results - if a task failed due to invalid options or parameters, fix and retry
5. Repeat steps 3-4, becoming more specific and targeted as iterations increase
</instructions>

<constraints>
$common_rules

<tool_preferences>
Prefer single secator tasks over workflows/scans - they are less intrusive and more targeted. Prefer lightweight tools (curl, nslookup, httpx) over slow, noisy ones (nuclei, ffuf, feroxbuster) unless depth is needed. Only use workflows or scans when they truly fit the task, or the user explicitly requests comprehensive/full/deep recon.
</tool_preferences>

<error_recovery>
When a task fails due to bad options, unsupported flags, or incorrect parameters, analyze the error, fix the options, and re-run. Do not give up after a single failure.
</error_recovery>

<task_options>
Only use options listed in the task reference above. To apply profiles, add "profiles": ["profile_name"] in opts. Use workspace queries to retrieve historical data for context.
</task_options>

<encrypted_data>
PII data appears as [HOST:xxxx] - pass these tokens as-is in tool arguments. They are decrypted client-side.
</encrypted_data>

<vulnerability_handling>
When you find a vulnerability, use the follow_up tool to ask the user what they wants to do with it before proceeding with exploitation.
</vulnerability_handling>

<subagents>
You can spawn autonomous AI subagents by calling run_task with name "ai". Each subagent gets a fresh context window and runs non-interactively.

Pass opts: {"prompt": "<objective>", "mode": "<mode>", "subagent": true, "session_name": "<descriptive_id>", "max_iterations": <N>}

session_name must use the actual target name (e.g. "recon-example.com", "exploit-sqli-10.0.0.1"). Include all necessary context in the prompt (vulnerability details, credentials, service versions).

Valid modes: "attack" (full recon/pentest), "chat" (analysis/queries), "exploiter" (focused exploitation, max_iterations: 5).

Use subagents when:
- A vulnerability needs focused exploitation/verification
- A complex sub-task benefits from dedicated context
- The user explicitly asks for a subagent
- Current context is large and a fresh agent would be more efficient

Do not spawn subagents for simple tasks achievable with a single tool call.
</subagents>
</constraints>
""")

# System prompt for chat mode
SYSTEM_CHAT = Template("""
<context>
$output_types_reference

<query_reference>
Queryable types: $query_types
Operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne
</query_reference>
</context>

<persona>
You are an autonomous penetration testing agent conducting authorized security testing. Answer user questions about their workspace by querying stored security data and providing clear analysis.
</persona>

<instructions>
1. Analyze the user's question to determine what data is needed
2. Query the workspace for relevant findings using MongoDB-style queries
3. Analyze the returned results
4. Provide a clear markdown summary with actionable insights
</instructions>

<constraints>
$common_rules

<error_recovery>
If a query fails, analyze the error and retry with corrected parameters. If you hit a result limit, use more specific queries. Do not give up after a single failure.
</error_recovery>

<follow_up_choices>
The "choices" field in follow_up is optional. Only include choices when they represent concrete actions you can execute. When the task is simply complete, use follow_up with just a reason and no choices.
</follow_up_choices>
</constraints>
""")

# System prompt for exploiter mode - focused on vulnerability verification
SYSTEM_EXPLOITER = Template("""
<context>
<secator_reference>
$library_reference
</secator_reference>
</context>

<persona>
You are an exploitation verification specialist conducting authorized security testing. Your goal is to verify if a specific vulnerability is exploitable and document a working proof-of-concept.
</persona>

<instructions>
1. Analyze the vulnerability details provided in your context
2. Research exploitation techniques for this vulnerability type
3. Attempt exploitation using appropriate tools or commands
4. Document each step: command used, expected vs actual output
5. Report success/failure with evidence
</instructions>

<constraints>
$common_rules

<scope>
Focus only on the vulnerability specified in your context. Do not spawn other AI subagents. Do not run broad scans or explore beyond scope.
</scope>

<methodology>
Be methodical - try multiple techniques if the first attempt fails. Retry as many times as needed: if a PoC fails, analyze the error, fix the script (sed, patch, missing deps), and re-run. Stop immediately if exploitation succeeds. Stop if exploitation is not feasible after reasonable attempts.
</methodology>

<docker_isolation>
Never run PoCs or exploits directly on the host. Always use disposable Docker containers via run_shell for isolation. Use `echo '...' | docker run --rm -i <image> bash` to pipe multi-line scripts. Choose the base image that fits the PoC (python, node, golang, gcc, ubuntu, etc.).

<examples>
<example_1>
Clone and run a PoC:
```
echo 'apt-get update && apt-get install -y git python3 pip
git clone https://github.com/author/CVE-XXXX-YYYY && cd CVE-XXXX-YYYY
pip install -r requirements.txt
python3 exploit.py --target TARGET_URL' | docker run --rm -i python:3.12-slim bash
```
</example_1>

<example_2>
Fix a PoC script before running:
```
echo 'apt-get update && apt-get install -y git curl
git clone https://github.com/author/poc-repo && cd poc-repo
sed -i "s|ATTACKER_IP|172.17.0.1|g" exploit.sh
sed -i "s|TARGET_URL|http://target:8080|g" exploit.sh
chmod +x exploit.sh && ./exploit.sh' | docker run --rm -i ubuntu bash
```
</example_2>

<example_3>
Compile and run a C exploit:
```
echo 'apt-get update && apt-get install -y git gcc make
git clone https://github.com/author/cve-exploit && cd cve-exploit
make && ./exploit TARGET_HOST TARGET_PORT' | docker run --rm -i gcc:latest bash
```
</example_3>
</examples>
</docker_isolation>
</constraints>
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


def _format_opt_type(opt_config: dict) -> str:
	"""Format option type as a compact string."""
	opt_type = opt_config.get('type', 'flag' if opt_config.get('is_flag') else 'unknown')
	if isinstance(opt_type, type):
		opt_type = opt_type.__name__
	return str(opt_type)


def _build_runner_reference(config_type: str) -> str:
	"""Build compact runner reference: name|description|opts|meta:meta_opt_names.

	Meta options (shared across tools) are listed by name only since their
	definitions appear in the META_OPTIONS section.

	Args:
		config_type: 'task' or 'workflow'

	Returns:
		Formatted reference string.
	"""
	from secator.loader import get_configs_by_type
	from secator.template import get_config_options

	lines = []
	runner_refs = get_configs_by_type(config_type)
	for r in sorted(runner_refs, key=lambda x: x.name):
		desc = getattr(r, 'long_description', '') or getattr(r, 'description', '') or ''
		desc = desc.strip().split('\n')[0][:50]
		opts = get_config_options(r)
		non_meta = []
		meta_names = []
		for opt_name, opt_config in opts.items():
			opt_name = opt_name.replace('-', '_')
			if opt_config.get('prefix') == 'Meta':
				meta_names.append(opt_name)
			else:
				non_meta.append(f"{opt_name}({_format_opt_type(opt_config)})")
		line = f"{r.name}|{desc}|{','.join(non_meta)}"
		if meta_names:
			line += f"|meta:{','.join(meta_names)}"
		lines.append(line)

	return "\n\n".join(lines)


def build_meta_options_reference() -> str:
	"""Build meta options reference: name(type) for all meta options across tasks and workflows."""
	from secator.loader import get_configs_by_type
	from secator.template import get_config_options

	meta_opts = {}
	for config_type in ('task', 'workflow'):
		for r in get_configs_by_type(config_type):
			opts = get_config_options(r)
			for k, v in opts.items():
				k = k.replace('-', '_')
				if v.get('prefix') == 'Meta' and k not in meta_opts:
					meta_opts[k] = _format_opt_type(v)

	return ",".join(f"{k}({v})" for k, v in sorted(meta_opts.items()))


def build_tasks_reference() -> str:
	"""Build compact task reference: name|description|options|meta:meta_opts."""
	return _build_runner_reference('task')


def build_workflows_reference() -> str:
	"""Build compact workflow reference: name|description|options|meta:meta_opts."""
	return _build_runner_reference('workflow')


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
		from secator.rich import console
		from secator.output_types import Warning
		console.print(Warning(message=f"Unknown mode {mode!r}, falling back to 'attack'. Valid modes: {list(MODES.keys())}"))
		mode = "attack"

	mode_config = MODES[mode]
	system_prompt = mode_config["system_prompt"]
	query_types = build_query_types()

	if mode == "attack":
		return system_prompt.substitute(
			common_rules=COMMON_RULES,
			library_reference=build_library_reference(),
			query_types=query_types
		)
	elif mode == "exploiter":
		return system_prompt.substitute(
			common_rules=COMMON_RULES,
			library_reference=build_library_reference()
		)
	else:  # chat mode
		return system_prompt.substitute(
			common_rules=COMMON_RULES,
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
		f"<meta_options>\n{build_meta_options_reference()}\n</meta_options>",
		f"<tasks>\n{build_tasks_reference()}\n</tasks>",
		f"<workflows>\n{build_workflows_reference()}\n</workflows>",
		f"<profiles>\n{build_profiles_reference()}\n</profiles>",
		f"<wordlists>\n{build_wordlists_reference()}\n</wordlists>",
		f"<output_types>\n{build_output_types_reference()}\n</output_types>",
		f"<option_formats>\n{OPTION_FORMATS}\n</option_formats>",
	]
	return "\n\n".join(sections)

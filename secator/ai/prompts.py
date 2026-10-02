"""Compact prompt templates for AI task."""
# flake8: noqa: E501
import json
import re
from pathlib import Path
from typing import Any, Dict, List
from string import Template

PROMPTS_DIR = Path(__file__).parent / "prompts"
SECATOR_DIR = Path(__file__).parent.parent
TASKS_PATH = SECATOR_DIR / "tasks"
WORKFLOWS_PATH = SECATOR_DIR / "configs" / "workflows"
PROFILES_PATH = SECATOR_DIR / "configs" / "profiles"

OPTION_FORMATS = """header|key1:value1;;key2:value2|Multiple headers separated by ;;
cookie|name1=val1;name2=val2|Standard cookie format
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name or file path
ports|1-1000,8080,8443|Comma-separated ports or ranges"""


def load_prompt(path: str) -> str:
	"""Load a prompt file and resolve ${includes} from common/.

	Include syntax: ${common_name} resolves to common/<common_name>.txt content.
	Standard $variable substitution is handled later by string.Template.

	Args:
		path: Relative path within the prompts directory (e.g. 'modes/attack.txt')

	Returns:
		Prompt string with includes resolved.
	"""
	return _resolve_includes((PROMPTS_DIR / path).read_text())


def _resolve_includes(content: str) -> str:
	"""Resolve ${include_name} patterns that match a constraints/<name>.txt file.

	Shared by load_prompt() and custom-mode loading so a user-authored mode can pull
	the same built-in ${queries}/${common}/... blocks. Unknown ${...} names are left
	untouched (they are Template variables substituted later).
	"""
	common_dir = PROMPTS_DIR / "constraints"
	available = {f.stem for f in common_dir.glob("*.txt")}

	def _resolve(match):
		name = match.group(1)
		if name in available:
			return (common_dir / f"{name}.txt").read_text().rstrip()
		return match.group(0)  # Leave unresolved (it's a Template variable)

	return re.sub(r'\$\{(\w+)\}', _resolve, content)


# Load prompts from files
COMMON_RULES = load_prompt("constraints/common.txt")
QUERIES = load_prompt("constraints/queries.txt")

SYSTEM_ATTACK = Template(load_prompt("modes/attack.txt"))
SYSTEM_CHAT = Template(load_prompt("modes/chat.txt"))
SYSTEM_EXPLOIT = Template(load_prompt("modes/exploit.txt"))

# Mode configurations: system prompt, allowed actions, and iteration limits
MODES = {
	"attack": {
		"system_prompt": SYSTEM_ATTACK,
		"allowed_actions": ["task", "workflow", "shell", "query", "follow_up", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed", "update_finding", "subagent", "stop"],
		"max_iterations": 5,
	},
	"chat": {
		"system_prompt": SYSTEM_CHAT,
		# Chat is strictly READ-ONLY / informational. It can only read workspace data
		# (`query`), ask/suggest (`follow_up`), delegate a same-mode helper (`subagent`),
		# and `stop`. NO `shell` (attack surface), NO `task`/`workflow` (escalation), and
		# NO finding writes (`add_finding`/`mark_vuln_*`/`update_finding`) — recording or
		# changing findings is an active action that belongs in attack/exploit.
		"allowed_actions": ["query", "follow_up", "subagent", "stop"],
		"max_iterations": 5,
	},
	"exploit": {
		"system_prompt": SYSTEM_EXPLOIT,
		# "query" is required so the model can pull the workspace's existing exploit
		# intel (the CVE's `_type:"exploit"` objects / PoC references) before trying
		# to exploit — without it query_workspace isn't even built for this mode.
		# "follow_up" lets exploit mode STOP-and-ask (e.g. confirm before a state-changing
		# action, or hand back after a PoC) instead of only running to its iteration cap.
		"allowed_actions": ["task", "workflow", "shell", "query", "follow_up", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed", "update_finding", "stop"],
		"max_iterations": 5,
	},
}


def get_mode_config(mode: str) -> dict:
	"""Get full config for a mode.

	Args:
		mode: The mode name (built-in attack/chat/exploit, or a custom auto-loaded mode)

	Returns:
		Mode configuration dict with system_prompt, allowed_actions, max_iterations
	"""
	return MODES.get(mode, MODES["chat"])


# Actions a custom mode may enable — the union of the built-in modes' allowed_actions
# (every real tool action appears in at least one built-in mode). Unknown actions in a
# custom mode are dropped with a warning.
# ponytail: if a future tool action is never listed in any built-in mode, add it here.
_KNOWN_ACTIONS = {a for cfg in MODES.values() for a in cfg["allowed_actions"]}


def _parse_frontmatter(text: str):
	"""Split optional leading ``---`` YAML frontmatter from a mode file.

	Returns ``(meta_dict, body)``. No frontmatter -> ``({}, text)``. A malformed
	frontmatter block raises (the caller skips that mode).
	"""
	if not text.startswith("---"):
		return {}, text
	import yaml
	# Frontmatter is the block between the first line (---) and the next --- line.
	parts = re.split(r'(?m)^---\s*$', text, maxsplit=2)
	# parts == ['', '<yaml>', '<body>'] for a well-formed "---\n...\n---\n<body>".
	if len(parts) < 3:
		return {}, text
	meta = yaml.safe_load(parts[1]) or {}
	if not isinstance(meta, dict):
		raise ValueError("frontmatter is not a mapping")
	return meta, parts[2].lstrip("\n")


def discover_ai_modes(modes_dir=None) -> dict:
	"""Discover custom AI modes dropped into ``<templates>/ai/modes/*.txt``.

	Each ``<name>.txt`` becomes a selectable mode alongside the built-ins. The file
	body is the system prompt (``${constraint}`` includes are resolved like built-in
	modes); optional leading YAML frontmatter declares metadata::

	    ---
	    allowed_actions: [query, follow_up, add_finding, stop]
	    max_iterations: 10
	    ---
	    You are a ... (prompt body, may use ${queries} / ${common} / ... includes)

	Missing frontmatter -> inherits chat's allowed_actions + max_iterations. Unknown
	actions are dropped (warned). Fails soft: a broken file logs a warning and is
	skipped, never breaking startup.

	Args:
		modes_dir: Directory to scan (default ``CONFIG.dirs.templates / 'ai' / 'modes'``).

	Returns:
		dict mapping mode name -> mode config (same shape as built-in MODES entries).
	"""
	from secator.rich import console
	from secator.output_types import Warning
	if modes_dir is None:
		from secator.config import CONFIG
		modes_dir = Path(CONFIG.dirs.templates) / "ai" / "modes"
	modes_dir = Path(modes_dir)
	if not modes_dir.is_dir():
		return {}

	chat = MODES["chat"]
	discovered = {}
	for filepath in sorted(modes_dir.glob("*.txt")):
		name = filepath.stem
		try:
			meta, body = _parse_frontmatter(filepath.read_text())
			if not body.strip():
				raise ValueError("empty prompt body")
			actions = meta.get("allowed_actions", chat["allowed_actions"])
			if not isinstance(actions, list):
				raise ValueError("allowed_actions must be a list")
			valid = [a for a in actions if a in _KNOWN_ACTIONS]
			dropped = [a for a in actions if a not in _KNOWN_ACTIONS]
			if dropped:
				console.print(Warning(message=f"Custom AI mode {name!r}: unknown action(s) dropped: {dropped}"))
			max_iters = meta.get("max_iterations", chat["max_iterations"])
			discovered[name] = {
				"system_prompt": Template(_resolve_includes(body)),
				"allowed_actions": valid,
				"max_iterations": int(max_iters),
			}
		except Exception as e:
			console.print(Warning(message=f"Skipping invalid custom AI mode {str(filepath)!r}: {e}"))
	return discovered


def register_custom_modes(modes_dir=None) -> list:
	"""Merge discovered custom modes into MODES. A custom mode whose name clashes with a
	built-in is skipped (built-ins win) with a warning. Returns the names registered."""
	from secator.rich import console
	from secator.output_types import Warning
	registered = []
	for name, cfg in discover_ai_modes(modes_dir).items():
		if name in MODES:
			console.print(Warning(message=f"Custom AI mode {name!r} clashes with a built-in mode — skipping."))
			continue
		MODES[name] = cfg
		registered.append(name)
	return registered


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
		tags = getattr(r, 'tags', []) or []
		tags_str = f"[{','.join(tags)}]" if tags else ""
		opts = get_config_options(r)
		non_meta = []
		meta_names = []
		for opt_name, opt_config in opts.items():
			opt_name = opt_name.replace('-', '_')
			if opt_config.get('prefix') == 'Meta':
				meta_names.append(opt_name)
			else:
				non_meta.append(f"{opt_name}({_format_opt_type(opt_config)})")
		line = f"{r.name}|{desc}|{tags_str}|{','.join(non_meta)}"
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
	lines.append("")
	lines.append("You can also use any remote wordlist URL directly (e.g. from GitHub raw URLs).")
	lines.append("Pick or find wordlists appropriate for the task: LFI, XSS, SQLi, directory brute-force, etc.")
	return "\n".join(lines)


def _type_name(tp) -> str:
	"""Return a human-readable type name for a dataclass field type."""
	type_names = {str: 'str', int: 'int', float: 'float', dict: 'dict', list: 'list', bool: 'bool'}
	if tp in type_names:
		return type_names[tp]
	origin = getattr(tp, '__origin__', None)
	if origin in type_names:
		return type_names[origin]
	return getattr(tp, '__name__', str(tp))


def build_output_types_reference() -> str:
	"""Build compact output types reference: name|field:type,field:type,..."""
	from secator.output_types import FINDING_TYPES
	lines = []
	for cls in FINDING_TYPES:
		name = cls.get_name()
		if hasattr(cls, '__dataclass_fields__'):
			fields = ",".join(
				f"{f.name}({_type_name(f.type)})"
				for f in cls.__dataclass_fields__.values()
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


def build_scope_section(in_scope=None, out_of_scope=None) -> str:
	"""Build an authorized-scope section for the system prompt.

	Lists the in-scope (and out-of-scope, if any) targets so the model knows the
	allowed scope up front — this cuts guardrail-denied retries where the model
	guesses a target form that isn't allowed. Returns "" when no scope is set
	(allow-all), so the section is simply omitted.

	Args:
		in_scope: Allow-list of targets (list or comma-separated string).
		out_of_scope: Deny-list of targets (list or comma-separated string).

	Returns:
		A ``<scope>...</scope>`` block, or "" when no scope is configured.
	"""
	from secator.scope import as_scope_list
	in_scope = as_scope_list(in_scope)
	out_of_scope = as_scope_list(out_of_scope)
	if not in_scope and not out_of_scope:
		return ""
	lines = ["<scope>"]
	if in_scope:
		lines.append("In-scope targets — stay within these. When a host is in scope by name, use the hostname, not its resolved IP, unless that exact IP is also listed:")
		lines.extend(f"- {t}" for t in in_scope)
	if out_of_scope:
		lines.append("Out-of-scope targets — never touch these:")
		lines.extend(f"- {t}" for t in out_of_scope)
	lines.append("</scope>")
	return "\n".join(lines)


def get_system_prompt(mode: str, workspace_path: str = "", backend=None, in_scope=None, out_of_scope=None) -> str:
	"""Get system prompt for mode with library reference filled in.

	Args:
		mode: One of "attack", "chat", or "exploit"
		workspace_path: Path to the workspace/reports directory
		backend: Optional interactivity backend to determine interaction rules
		in_scope: Optional allow-list of targets to surface in the prompt.
		out_of_scope: Optional deny-list of targets to surface in the prompt.

	Returns:
		Formatted system prompt string
	"""
	if mode not in MODES:
		from secator.rich import console
		from secator.output_types import Warning
		console.print(Warning(message=f"Unknown mode {mode!r}, falling back to 'chat'. Valid modes: {list(MODES.keys())}"))
		mode = "chat"

	mode_config = MODES[mode]
	system_prompt = mode_config["system_prompt"]
	ws = workspace_path or "<workspace>"

	# The queries.txt constraint (included by every mode) references $query_types and
	# $output_types_reference, so they must be substituted for all modes — derive both
	# from FINDING_TYPES so they never drift from the registry.
	subst = dict(query_types=build_query_types(), output_types_reference=build_output_types_reference())
	# Any mode that can run tasks/workflows (built-in attack/exploit, or a custom mode that
	# enables them) gets the tool library reference + paths substituted.
	if {"task", "workflow"} & set(mode_config["allowed_actions"]):
		path_vars = dict(tasks_path=str(TASKS_PATH), workflows_path=str(WORKFLOWS_PATH), profiles_path=str(PROFILES_PATH))
		subst.update(library_reference=build_library_reference(), **path_vars)
	result = system_prompt.safe_substitute(**subst)

	# Determine interaction rules based on backend
	# The mode templates already include ${follow_up} for interactive modes.
	# For non-interactive backends, append stop rules instead.
	if backend is not None:
		excluded = backend.get_excluded_tools()
		if "follow_up" in excluded:
			result += "\n" + load_prompt("constraints/stop.txt")

	scope_section = build_scope_section(in_scope, out_of_scope)
	if scope_section:
		result += "\n\n" + scope_section

	return result.replace("$workspace_path", ws)


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
		"max": "unlimited" if max_iterations == float('inf') else max_iterations,
		"instruction": instruction
	}, separators=(',', ':'))


REFERENCE_FORMAT = """\
Format: name|description|[tags]|options|meta:shared_options
- Options: name(type) where type is str, int, float, flag, list, dict, or Choice([...])
- Meta options are shared across tools and defined in <meta_options>. Each task/workflow lists which ones it supports.
- Profiles can be applied to any task/workflow via opts: {"profiles": ["profile_name"]}"""


def build_library_reference() -> str:
	"""Build complete library reference in compact format."""
	sections = [
		REFERENCE_FORMAT,
		f"<meta_options>\n{build_meta_options_reference()}\n</meta_options>",
		f"<tasks>\n{build_tasks_reference()}\n</tasks>",
		f"<workflows>\n{build_workflows_reference()}\n</workflows>",
		f"<profiles>\n{build_profiles_reference()}\n</profiles>",
		f"<wordlists>\n{build_wordlists_reference()}\n</wordlists>",
		f"<output_types>\n{build_output_types_reference()}\n</output_types>",
		f"<option_formats>\n{OPTION_FORMATS}\n</option_formats>",
	]
	return "\n\n".join(sections)


# Auto-load custom AI modes at import so they're selectable everywhere MODES is read
# (get_mode_config, build_tool_schemas, the `mode` opt help). Fail-soft: never break import.
try:
	register_custom_modes()
except Exception:  # noqa: BLE001 - discovery must never break importing the AI task
	pass

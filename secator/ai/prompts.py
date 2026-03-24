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
	filepath = PROMPTS_DIR / path
	content = filepath.read_text()

	# Resolve ${include_name} patterns that match constraints/ files
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
		"allowed_actions": ["task", "workflow", "shell", "query", "follow_up", "add_finding", "stop"],
		"max_iterations": 5,
	},
	"chat": {
		"system_prompt": SYSTEM_CHAT,
		"allowed_actions": ["query", "follow_up", "add_finding", "shell", "stop"],
		"max_iterations": 5,
	},
	"exploit": {
		"system_prompt": SYSTEM_EXPLOIT,
		"allowed_actions": ["task", "workflow", "shell", "add_finding", "stop"],
		"max_iterations": 5,
	},
}


def get_mode_config(mode: str) -> dict:
	"""Get full config for a mode.

	Args:
		mode: The mode name (attack, chat, exploit)

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


def get_system_prompt(mode: str, workspace_path: str = "", backend=None) -> str:
	"""Get system prompt for mode with library reference filled in.

	Args:
		mode: One of "attack", "chat", or "exploit"
		workspace_path: Path to the workspace/reports directory
		backend: Optional interactivity backend to determine interaction rules

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
	ws = workspace_path or "<workspace>"

	path_vars = dict(tasks_path=str(TASKS_PATH), workflows_path=str(WORKFLOWS_PATH), profiles_path=str(PROFILES_PATH))
	if mode == "attack":
		result = system_prompt.safe_substitute(library_reference=build_library_reference(), **path_vars)
	elif mode == "exploit":
		result = system_prompt.safe_substitute(library_reference=build_library_reference(), **path_vars)
	else:  # chat mode
		result = system_prompt.safe_substitute(output_types_reference=build_output_types_reference())

	# Determine interaction rules based on backend
	# The mode templates already include ${follow_up} for interactive modes.
	# For non-interactive backends, append stop rules instead.
	if backend is not None:
		excluded = backend.get_excluded_tools()
		if "follow_up" in excluded:
			result += "\n" + load_prompt("constraints/stop.txt")

	return result.replace("$workspace_path", ws)


# def format_user_initial(targets: List[str], instructions: str, previous_results: List[Dict] = None) -> str:
# 	"""Format initial user message as compact JSON.

# 	Args:
# 		targets: List of target hosts/URLs
# 		instructions: User instructions for the task
# 		previous_results: Optional list of result dicts from upstream tasks

# 	Returns:
# 		Compact JSON string (no whitespace)
# 	"""
# 	results_str = json.dumps(previous_results, default=str)
# 	instructions_str = json.dumps(instructions or "Analyze the previous results first")
# 	return f"""
# <previous_results>
# {instructions_str}
# {results_str}
# </previous_results>
# 	"""


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

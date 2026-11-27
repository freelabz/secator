"""Compact prompt templates for AI task.

Prompt files are Markdown (``*.md``) with an optional YAML frontmatter header that
describes the prompt (``name``/``type``/``description``/``modes``). The frontmatter is
metadata only — it is stripped before the body is rendered, so the rendered prompt is
exactly the body after the closing ``---``. This reuses the frontmatter convention of
the user-provided AI context files (``secator/ai/context.py``) and extends it to the
system prompts.

Frontmatter schema (see :data:`PROMPT_TYPES`):

* ``name`` (str, required) — must equal the file stem.
* ``type`` (str, required) — one of ``mode`` (a full per-mode system prompt),
  ``partial`` (a fragment pulled into a mode prompt via a ``${name}`` include),
  ``injected`` (a fragment appended programmatically at build time, e.g. ``stop``),
  or ``utility`` (a standalone prompt, e.g. the mode ``_selection`` classifier).
* ``description`` (str, required) — one-line human description.
* ``modes`` (list[str], ``type: mode`` only) — the mode(s) this system prompt serves.
"""
# flake8: noqa: E501
import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from string import Template

import yaml

PROMPTS_DIR = Path(__file__).parent / "prompts"
SECATOR_DIR = Path(__file__).parent.parent
TASKS_PATH = SECATOR_DIR / "tasks"
WORKFLOWS_PATH = SECATOR_DIR / "configs" / "workflows"
PROFILES_PATH = SECATOR_DIR / "configs" / "profiles"

# Max result items the AI gets back in ONE page — from a runner tool_result
# (format_tool_result) AND a query_workspace page. Kept a single constant so "run a task"
# and "query the workspace" cap alike; a result at this cap is INCOMPLETE and the model is
# told how to fetch the rest. Mirrors the query backends' default page size
# (secator/query/*.py `_execute_search(limit=100)`).
AI_MAX_RESULTS = 100

OPTION_FORMATS = """header|key1:value1;;key2:value2|Multiple headers separated by ;;
cookie|name1=val1;name2=val2|Standard cookie format
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name or file path
ports|1-1000,8080,8443|Comma-separated ports or ranges"""


# Valid `type:` frontmatter values (see module docstring).
PROMPT_TYPES = ("mode", "partial", "injected", "utility")

# Frontmatter delimiter: a file may start with `---\n`, the YAML block, then `---`.
# Same convention as the user AI context files (secator/ai/context.py).
_FRONTMATTER = re.compile(r'^---\s*\n(.*?)\n---\s*\n?', re.DOTALL)


def split_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
	"""Split a prompt file's text into (frontmatter_dict, body).

	A file with no frontmatter returns ``({}, text)`` unchanged. The body is returned
	verbatim (no stripping) so the rendered prompt stays byte-for-byte what follows the
	closing ``---``.
	"""
	match = _FRONTMATTER.match(text)
	if not match:
		return {}, text
	meta = yaml.safe_load(match.group(1)) or {}
	if not isinstance(meta, dict):
		meta = {}
	return meta, text[match.end():]


def load_prompt_meta(path: str) -> Dict[str, Any]:
	"""Return the frontmatter dict of a prompt file (empty dict if none)."""
	meta, _ = split_frontmatter((PROMPTS_DIR / path).read_text())
	return meta


def load_prompt(path: str) -> str:
	"""Load a prompt file (body only) and resolve ${includes} from constraints/.

	The optional YAML frontmatter header is stripped first (it is metadata, never part
	of the rendered prompt). Include syntax: ``${name}`` resolves to the BODY of
	``constraints/<name>.md`` (its own frontmatter stripped). Standard ``$variable``
	substitution is handled later by :class:`string.Template`.

	Args:
		path: Relative path within the prompts directory (e.g. 'modes/scan.md').

	Returns:
		Prompt string (body, includes resolved).
	"""
	_, content = split_frontmatter((PROMPTS_DIR / path).read_text())

	# Resolve ${include_name} patterns that match constraints/ files
	common_dir = PROMPTS_DIR / "constraints"
	available = {f.stem for f in common_dir.glob("*.md")}

	def _resolve(match):
		name = match.group(1)
		if name in available:
			_, body = split_frontmatter((common_dir / f"{name}.md").read_text())
			return body.rstrip()
		return match.group(0)  # Leave unresolved (it's a Template variable)

	return re.sub(r'\$\{(\w+)\}', _resolve, content)


# Load prompts from files
COMMON_RULES = load_prompt("constraints/common.md")
QUERIES = load_prompt("constraints/queries.md")

SYSTEM_SCAN = Template(load_prompt("modes/scan.md"))
SYSTEM_CHAT = Template(load_prompt("modes/chat.md"))
SYSTEM_EXPLOIT = Template(load_prompt("modes/exploit.md"))
SYSTEM_CONTRIBUTE = Template(load_prompt("modes/contribute.md"))
SYSTEM_MONITOR = Template(load_prompt("modes/monitor.md"))
SYSTEM_RESEARCH = Template(load_prompt("modes/research.md"))

# Mode configurations: system prompt, allowed actions, and iteration limits
MODES = {
	"scan": {
		"system_prompt": SYSTEM_SCAN,
		"description": "actively scan, run tools / shell, exploit, and write or curate findings",
		"allowed_actions": ["task", "workflow", "shell", "query", "fetch_url", "update_plan", "web_search", "list_runners", "get_runner", "stop_runner", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed", "mark_vuln_fixed", "update_finding", "add_note", "subagent", "check_background_jobs", "cancel_background_job", "change_mode", "stop"],
		"max_iterations": 5,
	},
	"chat": {
		"system_prompt": SYSTEM_CHAT,
		# Chat is strictly READ-ONLY / informational. It can read workspace data (`query`),
		# fetch a known page (`fetch_url`), search the web (`web_search`, a read-only external
		# lookup), look up run history (`list_runners`, read-only), maintain a plan
		# (`update_plan`), delegate a same-mode helper (`subagent`), and end its turn / suggest
		# next steps (`stop`). NO `shell` (attack surface), NO `task`/`workflow` (escalation),
		# and NO finding writes (`add_finding`/`mark_vuln_*`/`update_finding`) — recording or
		# changing findings is an active action that belongs in scan/exploit.
		"description": "read-only — read and explain workspace data; you cannot scan, attack or write findings",
		"allowed_actions": ["query", "fetch_url", "update_plan", "web_search", "list_runners", "get_runner", "subagent", "change_mode", "check_background_jobs", "cancel_background_job", "stop"],
		"max_iterations": 5,
	},
	"exploit": {
		"system_prompt": SYSTEM_EXPLOIT,
		"description": "verify a single vulnerability by actually exploiting it and record a PoC",
		# "query" is required so the model can pull the workspace's existing exploit
		# intel (the CVE's `_type:"exploit"` objects / PoC references) before trying
		# to exploit — without it query_workspace isn't even built for this mode.
		# "stop" lets exploit mode end-and-ask (e.g. confirm before a state-changing
		# action, or hand back after a PoC) instead of only running to its iteration cap.
		"allowed_actions": ["task", "workflow", "shell", "query", "fetch_url", "update_plan", "web_search", "list_runners", "get_runner", "stop_runner", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed", "mark_vuln_fixed", "update_finding", "add_note", "subagent", "change_mode", "check_background_jobs", "cancel_background_job", "stop"],
		"max_iterations": 5,
	},
	"contribute": {
		"system_prompt": SYSTEM_CONTRIBUTE,
		"description": "author new secator tasks / workflows / scans (or framework code) and prove them with real, reproducible tests",
		# A code-authoring mode, NOT a findings mode: it RUNS runners (task/workflow/shell) to
		# exercise the code it writes, reads/searches for conventions, and delegates to subagents
		# — but it does NOT write findings (no add_finding / mark_vuln_* / update_finding) and
		# does NOT change_mode (deliberate, directly-selected terminal mode). It needs HOST
		# filesystem access (run it WITHOUT --isolated); writes outside the workspace prompt for
		# approval. On builds that expose read_file/write_file, those are added for this mode too.
		"allowed_actions": ["task", "workflow", "shell", "query", "fetch_url", "update_plan", "web_search", "list_runners", "get_runner", "stop_runner", "subagent", "check_background_jobs", "cancel_background_job", "stop"],
		# Authoring + running the full test matrix (dry-run, single/multi target, sync + worker,
		# fixtures, lint) is long, so a higher iteration floor than the one-shot modes.
		"max_iterations": 20,
	},
	"monitor": {
		"system_prompt": SYSTEM_MONITOR,
		"description": "re-verify the EXISTING finding set against its targets and record what changed; you cannot scan for or add new findings",  # noqa: E501
		# Attack-surface monitoring: a recurring re-verification of the EXISTING finding set.
		# It reads (query), re-probes a finding against its OWN target with `shell`, and records
		# the outcome: an unchanged finding gets an `add_note`; a changed one `update_finding` +
		# `add_note` (the delta); a finding that no longer reproduces is retired with
		# `mark_vuln_false_positive` (reversible) + a note; a previously-exploited vuln that is now
		# gone is closed with `mark_vuln_fixed` + a note. It deliberately CANNOT run
		# tasks/workflows (those re-ingest findings through the normal pipeline and would re-add
		# the very surface it is auditing), add findings, exploit, spawn subagents, or
		# self-escalate — no add_finding, no mark_vuln_exploited/exploit_failed, no subagent, no
		# change_mode. No iteration override/cap: like the other modes it relies on the default
		# budget and the model calling `stop` when the surface has been walked.
		"allowed_actions": ["query", "shell", "mark_vuln_false_positive", "mark_vuln_fixed", "update_finding", "add_note", "check_background_jobs", "cancel_background_job", "stop"],  # noqa: E501
	},
	"research": {
		"system_prompt": SYSTEM_RESEARCH,
		"description": "research a vulnerability (CVE/0-day): find or craft a working PoC in a sandbox lab, with adversarial subagents, and record it",
		# Full active toolset (same as exploit) MINUS change_mode: research is a deliberate,
		# directly-selected terminal mode — it already has the most capable surface, so there
		# is nothing to escalate to and it must not de-escalate out. It leans on `subagent`
		# (adversarial fan-out), `shell` (stand up a sandbox lab), `web_search` (find PoCs) and
		# `add_finding` (record the validated Exploit, linked by `cves`).
		"allowed_actions": ["task", "workflow", "shell", "query", "fetch_url", "update_plan", "web_search", "list_runners", "get_runner", "stop_runner", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed", "mark_vuln_fixed", "update_finding", "add_note", "subagent", "check_background_jobs", "cancel_background_job", "stop"],
		# Research is long-running (stand up labs, fan out subagents, iterate on PoCs), so it
		# gets a higher iteration floor than scan/exploit.
		"max_iterations": 12,
	},
}


# Per-mode tool exposure is declared in each mode prompt's frontmatter `tools:` key — a
# list of fnmatch globs over tool NAMES (e.g. "run_*", "*", "!change_mode"). This is the
# single source of truth for a mode's BASELINE tools, and it resolves against CORE
# (built-in) tools only. External/bundle tools are NEVER matched by these globs; they are
# added on top per-invocation as `extra_tools` (a generic option on the `ai` task), so a
# caller grants a non-core tool (e.g. `add_suggestion`) to a mode only when needed. The
# patterns are loaded into MODES here so MODES stays the one mode registry, and resolved
# by tool_matches_mode(). (Phase 2 makes this the operative driver of build_tool_schemas,
# wires `extra_tools`, and drops the per-tool `modes` list.)
for _mode, _cfg in MODES.items():
	_cfg["tools"] = list(load_prompt_meta(f"modes/{_mode}.md").get("tools") or ["*"])


def mode_tool_patterns(mode: str) -> List[str]:
	"""Return the `tools:` fnmatch patterns declared by a mode (default: all tools)."""
	return MODES.get(normalize_mode(mode), {}).get("tools", ["*"])


def mode_excludes_tool(tool_name: str, patterns: List[str]) -> bool:
	"""Whether a mode's ``!`` exclude patterns remove a tool (by fnmatch over its name).

	Used both for baseline tools and for ``extra_tools`` added on top, so a mode can
	exclude a specific tool from the effective set regardless of how it was included.
	"""
	for pat in patterns:
		p = str(pat)
		if p.startswith("!") and fnmatch.fnmatchcase(tool_name, p[1:]):
			return True
	return False


def tool_matches_mode(tool_name: str, patterns: List[str], external: bool = False) -> bool:
	"""Whether a CORE tool is in a mode's baseline given the mode's `tools:` patterns.

	Patterns are fnmatch globs over tool names, in any order: a plain pattern INCLUDES,
	a leading ``!`` EXCLUDES (applied after includes). A tool is in the baseline iff it
	matches at least one include and no exclude.

	``external=True`` short-circuits to ``False``: a mode's globs match CORE tools only.
	External/bundle tools are never pulled in by a mode's `tools:` globs (not even by an
	exact-name entry) — they are added on top via the `ai` task's ``extra_tools`` option,
	so a broad ``tools: ["*"]`` can never grant a mode a non-core tool (e.g.
	``add_suggestion``). See build_tool_schemas (Phase 2).
	"""
	if external:
		return False
	includes = [str(p) for p in patterns if not str(p).startswith("!")]
	if not any(fnmatch.fnmatchcase(tool_name, p) for p in includes):
		return False
	return not mode_excludes_tool(tool_name, patterns)


def build_mode_banner(mode: str, mode_config: dict = None) -> str:
	"""Generate the authoritative "you are in <mode> mode" statement for a mode.

	Derived from the MODES registry, so ANY mode (incl. ones added later, e.g. a
	`monitor` mode) automatically gets a correct current-mode statement — the model
	always knows which mode it is in and won't redundantly try to switch to it. The
	`change_mode` hint is added only when that mode can actually change mode.
	"""
	cfg = mode_config or MODES.get(mode, {})
	desc = cfg.get("description")
	line = f"You are operating in {mode.upper()} mode"
	line += f": {desc}." if desc else "."
	# change_mode availability is derived from the mode's `tools:` patterns (the single
	# source of truth). Fall back to allowed_actions only for a synthetic mode_config
	# passed without a `tools` key (e.g. in tests).
	if "tools" in cfg:
		can_change_mode = tool_matches_mode("change_mode", cfg["tools"])
	else:
		can_change_mode = "change_mode" in cfg.get("allowed_actions", [])
	if can_change_mode:
		line += (" You are ALREADY in this mode — do NOT call change_mode to re-enter it; "
		         "change_mode only moves UP to a more capable mode and cannot de-escalate.")
	return f"<current_mode>\n{line}\n</current_mode>"


# Legacy mode names -> current names, so persisted sessions and older callers that
# still pass "attack" keep working.
MODE_ALIASES = {"attack": "scan"}


def normalize_mode(mode):
	"""Resolve a legacy mode alias (e.g. "attack") to its current name ("scan")."""
	mode = (mode or "").strip().lower() if isinstance(mode, str) else mode
	return MODE_ALIASES.get(mode, mode)


def get_mode_config(mode: str) -> dict:
	"""Get full config for a mode.

	Args:
		mode: The mode name (scan, chat, exploit)

	Returns:
		Mode configuration dict with system_prompt, allowed_actions, max_iterations
	"""
	return MODES.get(normalize_mode(mode), MODES["chat"])


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


# Cached per-process shell-environment facts (OS / package manager / sudo). These do
# not change within a process, and a resume on a different machine is a NEW process, so
# caching here is safe AND gives the "recompute fresh on resume" property for free. Only
# the clock (date / timestamp) is recomputed on every build. Keyed by `isolated`.
_SHELL_ENV_CACHE: Dict[bool, List[str]] = {}


def _sudo_status_lines() -> List[str]:
	"""Describe host sudo availability for the AI, without ever prompting or blocking.

	Order mirrors ``Command._prompt_sudo``: root → configured password → passwordless
	(`sudo -n`, which NEVER prompts) → unavailable. The unavailable line is actionable:
	it tells the model not to run sudo (it would fail in this non-interactive session)
	and how the user can enable it.
	"""
	import os
	import shutil
	import subprocess
	if hasattr(os, "geteuid") and os.geteuid() == 0:
		return ["Privileges: running as root — no sudo needed."]
	try:
		from secator.config import CONFIG
		if CONFIG.security.sudo_password:
			return ["Privileges: non-root; sudo available via a configured password (security.sudo_password)."]
	except Exception:
		pass
	if shutil.which("sudo") is None:
		return ["Privileges: non-root and sudo is NOT installed — do not use sudo; run only commands that work unprivileged."]
	try:
		# `sudo -n` is guaranteed non-interactive (fails instead of prompting); bound it anyway.
		rc = subprocess.run(
			["sudo", "-n", "true"],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
		).returncode
		if rc == 0:
			return ["Privileges: non-root; passwordless sudo IS available."]
	except Exception:
		pass
	return [
		"Privileges: non-root; sudo requires a password and none is configured. Do NOT run sudo "
		"commands — they fail fast in this non-interactive session (no password prompt). Prefer an "
		"unprivileged alternative, or ask the user to enable passwordless sudo or set "
		"SECATOR_SECURITY_SUDO_PASSWORD.",
	]


def _host_shell_env_lines() -> List[str]:
	"""Host OS + package manager (read-only; never triggers an install) + sudo status."""
	lines = ["Shell environment: this host — run_shell commands execute directly on it."]
	try:
		from secator.installer import get_distro_config
		d = get_distro_config()
		system = getattr(d, "system", "") or ""
		name = getattr(d, "name", "") or ""
		pm_name = getattr(d, "pm_name", "") or ""
		pm_installer = getattr(d, "pm_installer", "") or ""
		os_line = f"Operating system: {system}" + (f" ({name})" if name else "")
		lines.append(os_line + ".")
		if pm_installer:
			lines.append(f"Package manager: {pm_name} — install packages with `{pm_installer} <pkg>`.")
		elif pm_name:
			lines.append(f"Package manager: {pm_name}.")
		else:
			lines.append("Package manager: unknown — detect it before installing anything.")
	except Exception:
		lines.append("Package manager: unknown — detect it before installing anything.")
	lines.extend(_sudo_status_lines())
	return lines


def build_session_context(isolated: bool = False) -> str:
	"""Dynamic per-session context block for the system prompt.

	Two things the model otherwise guesses wrong:
	- the current date (it has no clock);
	- the shell environment its ``run_shell`` commands ACTUALLY run in — the disposable
	  per-run sandbox when ``--isolated`` (details in ``<shell_environment>``), otherwise THIS host's OS + package
	  manager + sudo availability. Stops the model defaulting to ``apk`` on a non-Alpine
	  host, and stops it issuing a sudo command that can only stall/fail.

	DATE ONLY, no clock time: this block sits in the cached system-prompt prefix, so a
	second-precision timestamp would (a) be stale the moment the session runs past it and
	(b) risk busting prompt caching if the prompt is ever rebuilt mid-session. A day-granular
	date stays constant across the session, so the cache holds. The model is told to run
	``date`` when it needs the exact wall-clock time. Rebuilt on every ``get_system_prompt``
	call (including resume), so the date rolls over and host facts are re-detected on resume.
	"""
	from datetime import datetime, timezone
	lines = [
		"<session_context>",
		f"Current date (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
		"Run `date` for the exact current time.",
	]
	if isolated:
		lines += [
			"Shell environment: this run's sandbox container — run_shell runs there, not on the host "
			"(image, package manager and install commands: see <shell_environment>).",
		]
	else:
		if isolated not in _SHELL_ENV_CACHE:
			_SHELL_ENV_CACHE[isolated] = _host_shell_env_lines()
		lines += _SHELL_ENV_CACHE[isolated]
	lines.append("</session_context>")
	return "\n".join(lines)


# The default sandbox image (freelabz/secator:<version>-lite, Alpine) runs as the unprivileged
# `secator` user with passwordless sudo for `apk add` only; the full flavor drops that sudo rule
# (see Dockerfile). Any other configured image is unknown here
# (the sandbox starts lazily on the first run_shell, after the prompt is built), so the model is
# told to detect its OS once.
_DEFAULT_SANDBOX_REPO = "freelabz/secator"


def build_sandbox_packages(image: str) -> str:
	"""Install guidance for the sandbox image: concrete apk commands for the default secator lite
	image, a detect-once step (OS, package manager, root or not) for any other image."""
	java_run = 'run_shell(command="java -jar $runner_dir/.outputs/<tool>/<tool>.jar")'
	repo, _, tag = image.split("@", 1)[0].partition(":")
	if repo == _DEFAULT_SANDBOX_REPO and tag.endswith("-lite"):
		return (
			'- System packages / runtimes (Alpine, unprivileged user: apk via sudo):   '
			'run_shell(command="sudo apk add --no-cache go rust cargo nmap-scripts")\n'
			'- Java tools:   run_shell(command="sudo apk add --no-cache openjdk17-jre-headless"), then ' + java_run
		)
	return (
		"- System packages / runtimes: this image's package manager is not known in advance: run "
		"`cat /etc/os-release; id -u` once, then use its manager (`apk add --no-cache`, "
		"`apt-get install -y`, `dnf install -y`), prefixed with `sudo` when you are not root.\n"
		"- Java tools: install a headless JRE with that manager (e.g. openjdk17-jre-headless, "
		"default-jre-headless or java-17-openjdk-headless), then " + java_run
	)


def build_sandbox_loopback() -> str:
	"""Loopback rule for the sandbox, matching what the permission engine enforces (a private
	network namespace exempts the sandbox's own loopback; host/container networking does not)."""
	from secator.ai.guardrails import _sandbox_has_private_loopback
	if _sandbox_has_private_loopback():
		return (
			"The sandbox has its own network namespace, so its loopback (127.0.0.1, ::1, localhost) is\n"
			"its own: a lab or PoC service you start there can be reached on loopback from run_shell\n"
			"without an approval prompt, unless a deny rule or out_of_scope entry covers it."
		)
	return (
		"The sandbox shares another network namespace (host or container networking), so loopback\n"
		"(127.0.0.1, ::1, localhost) is scoped like any other target."
	)


def build_shell_environment(isolated: bool) -> str:
	"""The <shell_environment> block, picked from where run_shell really executes: the per-run
	sandbox container (``--isolated``; image from ``addons.ai.isolated_container_image``) or the host."""
	if not isolated:
		return load_prompt("constraints/shell_host.md")
	from secator.ai.tools._sandbox import _sandbox_image
	image = _sandbox_image()
	return Template(load_prompt("constraints/shell_sandbox.md")).safe_substitute(
		sandbox_image=image, sandbox_packages=build_sandbox_packages(image),
		sandbox_loopback=build_sandbox_loopback())


def build_contribute_deliverable(backend=None) -> str:
	"""The <deliverable> block for contribute mode, chosen from WHERE the run happens.

	- LOCAL (CLI / TUI on the user's machine): the agent can write into the user's checkout and
	  offer to fork + open the PR directly (the user's git/GitHub creds are available).
	- HOSTED / non-interactive (a RemoteBackend platform sandbox, or any non-interactive run):
	  no PR is possible, so every produced file is pasted INLINE as a fenced Markdown code block
	  headed by its intended repo-relative path, for the user to copy and PR themselves.
	"""
	name = backend.__class__.__name__ if backend is not None else "CLIBackend"
	interactive = getattr(backend, "interactive", True) if backend is not None else True
	is_local = interactive and name in ("CLIBackend", "TUIBackend")
	inline = (
		"Paste EVERY file you produced inline in your final message, each as a fenced code block "
		"headed by a comment with its intended path RELATIVE TO THE SECATOR REPO — e.g.\n"
		"```python\n# secator/tasks/manspider.py\n<file contents>\n```\n"
		"```json\n# tests/fixtures/manspider_output.json\n<anonymized fixture>\n```\n"
		"Cover the task/config file, the fixtures, and the test wiring (tests/integration/inputs.py "
		"+ outputs.py). The user copies these into their own clone and opens the PR."
	)
	if is_local:
		return (
			"<deliverable>\n"
			"You are on the user's OWN machine. Write the finished files into their Secator checkout, "
			"then — if they want to contribute — OFFER to fork `freelabz/secator`, apply the files on a "
			"branch, and open the PR for them (use `gh`; if not authenticated, ask the user to run "
			"`gh auth login` / provide GitHub credentials). If they decline the PR, fall back to pasting "
			"the files inline:\n" + inline + "\n</deliverable>"
		)
	return (
		"<deliverable>\n"
		"You are running on the hosted platform in a DISPOSABLE sandbox — you CANNOT open a PR from here "
		"and must not try. " + inline + "\n</deliverable>"
	)


def get_system_prompt(mode: str, workspace_path: str = "", backend=None, in_scope=None, out_of_scope=None,
                      isolated=None, is_subagent: bool = False, workspace_name=None, workspace_id=None,
                      context_includes=None) -> str:
	"""Get system prompt for mode with library reference filled in.

	Args:
		mode: One of "scan", "chat", or "exploit"
		workspace_path: The runner's reports folder (e.g. <reports>/<workspace>/tasks/<id>), rendered
			in the prompt as ``$runner_dir``. Not the workspace folder itself.
		backend: Optional interactivity backend to determine interaction rules
		in_scope: Optional allow-list of targets to surface in the prompt.
		out_of_scope: Optional deny-list of targets to surface in the prompt.
		isolated: Whether run_shell executes in the per-run sandbox; picks the
			``<shell_environment>`` block (None: the ``security.shell_isolated`` default). When not
			None, also append a dynamic ``<session_context>`` block (clock + shell environment).
			Left None by callers (e.g. tests) that want a deterministic, static prompt.
		is_subagent: When True, strip all subagent-delegation guidance (a subagent has no
			`run_subagent` tool and must not spawn further subagents) and append the
			subagent persona so it carries out its assigned objective itself.
		workspace_name: current workspace name, for scoping user AI context files.
		workspace_id: current workspace id, for scoping user AI context files.
		context_includes: names / relative paths of user AI context files to force-load (from a
			profile's ``ai_context``), bypassing frontmatter mode/workspace scope.

	Returns:
		Formatted system prompt string
	"""
	mode = normalize_mode(mode)
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
	if mode in ("scan", "exploit", "contribute", "monitor", "research"):
		path_vars = dict(tasks_path=str(TASKS_PATH), workflows_path=str(WORKFLOWS_PATH), profiles_path=str(PROFILES_PATH))
		subst.update(library_reference=build_library_reference(), **path_vars)
	if mode == "contribute":
		# How to hand back a finished contribution depends on WHERE this runs: on the user's
		# own machine (CLI/TUI) the agent can fork + open the PR; on the hosted platform (a
		# disposable RemoteBackend sandbox, or any non-interactive run) it cannot, so it must
		# paste the files inline for the user to PR themselves.
		subst["deliverable"] = build_contribute_deliverable(backend)
	if mode in ("scan", "exploit", "contribute", "monitor", "research"):
		# Where run_shell executes (sandbox vs host). `isolated=None` (static callers, tests)
		# falls back to the configured default for the ai task's --isolated option.
		if isolated is None:
			from secator.config import CONFIG
			shell_isolated = bool(CONFIG.security.shell_isolated)
		else:
			shell_isolated = bool(isolated)
		subst["shell_environment"] = build_shell_environment(shell_isolated)
	result = system_prompt.safe_substitute(**subst)

	# Prepend the programmatic current-mode statement (from the registry) so the model
	# always knows its active mode — prevents redundant change_mode calls. Auto-covers
	# any mode added to MODES later.
	result = build_mode_banner(mode, mode_config) + "\n\n" + result

	# A subagent has no `run_subagent` tool and must not spawn further subagents. Strip the
	# baked-in delegation guidance (the <subagents> usage block, and in scan mode the
	# <vulnerability_handling> block that tells the model to hand exploitation to a subagent),
	# then append the subagent persona so it carries out its objective itself. Strips are
	# resilient no-ops when a block is absent (e.g. chat mode has no vulnerability_handling).
	if is_subagent:
		# Anchor the tags to line starts: prompts also mention them inline (e.g. "see
		# <vulnerability_handling>"), and an unanchored match would strip everything from
		# that mention to the closing tag.
		result = re.sub(r'\n*^<subagents>$.*?^</subagents>$\n*', '\n\n', result, flags=re.DOTALL | re.MULTILINE)
		result = re.sub(r'\n*^<background_subagents>$.*?^</background_subagents>$\n*', '\n', result, flags=re.DOTALL | re.MULTILINE)
		result = re.sub(r'\n*^<vulnerability_handling>$.*?^</vulnerability_handling>$\n*', '\n\n', result, flags=re.DOTALL | re.MULTILINE)
		# Scan's role line delegates to that block inline; drop the clause with it.
		result = re.sub(r'; and hand [^;.]*?\(see <vulnerability_handling>\)[^;.]*', '', result)
		result += "\n\n" + load_prompt("constraints/subagent.md")

	# The query rules name get_runner / stop_runner: drop each block in a mode that does not
	# expose its tool (e.g. read-only chat cannot stop runners).
	allowed = set(mode_config.get("allowed_actions") or [])
	for tag, needed in (("query_running_runner", "get_runner"), ("stop_runner_rule", "stop_runner")):
		if needed not in allowed:
			result = re.sub(rf'\n*^<{tag}>$.*?^</{tag}>$\n*', '\n', result, flags=re.DOTALL | re.MULTILINE)

	# Inject the end-of-turn `stop` rules. `stop` is the single end-of-turn signal in
	# every mode; which guidance applies depends only on whether the backend has a user
	# to pause for: interactive backends (CLI/TUI/Remote) get the version that offers
	# `choices`, a non-interactive AutoBackend the choiceless "decide autonomously" one.
	# Spliced in BEFORE the <operating_rules> recap so that recap stays in the
	# high-attention recency tail (see TestOperatingRulesRecap).
	interactive = getattr(backend, "interactive", True) if backend is not None else True
	stop_rules = load_prompt("constraints/stop.md" if interactive else "constraints/stop_autonomous.md")
	marker = "<operating_rules>"
	if marker in result:
		result = result.replace(marker, stop_rules + "\n\n" + marker, 1)
	else:
		result += "\n" + stop_rules

	scope_section = build_scope_section(in_scope, out_of_scope)
	if scope_section:
		result += "\n\n" + scope_section

	if isolated is not None:
		result += "\n\n" + build_session_context(isolated=bool(isolated))

	# Substitute $runner_dir (this runner's reports folder) in the baked-in prompt BEFORE
	# appending the user context, so a user note's body is treated verbatim (never substituted).
	result = result.replace("$runner_dir", ws)

	# User-provided engagement context (~/.secator/templates/ai/**/*.md), appended last so
	# it reads as an authoritative, run-specific overlay on top of the baked-in prompt.
	from secator.ai.context import load_context_blocks
	blocks = load_context_blocks(
		mode, workspace_name=workspace_name, workspace_id=workspace_id, includes=context_includes)
	if blocks:
		# Each block is already wrapped in its own <type:relative/path.md> tag (context.py).
		result += "\n\n" + "\n\n".join(blocks)

	return result


def format_tool_result(name: str, status: str, count: int, results: Any, max_items: int = AI_MAX_RESULTS) -> str:
	"""Format tool result as compact JSON, truncating results if too many.

	Args:
		name: Tool/task name
		status: Execution status (success/error)
		count: Number of results
		results: Full results from the action
		max_items: Maximum number of result items to include (default :data:`AI_MAX_RESULTS`)

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
		# Model-visible narrowing hint: the console Warning below never reaches the
		# model, so without this the model only sees `truncated`/`total_count` flags and
		# no guidance. Keep it generic/future-proof (works before an `offset`/paging arg
		# exists) so it never promises an argument the tool may not yet accept.
		data["hint"] = (
			f'Only the first {max_items} of {count} results are shown. Narrow the scope '
			'to see the rest: add/tighten a filter, target a single runner or item, or '
			'page through results with an offset once supported.')
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

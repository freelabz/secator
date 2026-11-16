"""Registry for native + external LLM tools.

Each tool is one self-contained :class:`~secator.ai.tools.base.BaseTool` subclass,
living one-per-file in this package (``run_task.py``, ``query_workspace.py``, …) the
same way custom secator tasks live one-per-file under ``secator/tasks/``. The class
carries everything that used to be hand-synced across 5 places (schema, dispatch
action, mode exposure, permission auto-allow, handler), and every drift-prone view
derives from the ``TOOLS`` registry:

* ``build_tool_schemas(mode, ...)`` exposes a tool when its NAME matches the mode's
``tools:`` frontmatter globs (:func:`secator.ai.prompts.tool_matches_mode`) — the single
source of truth for mode→tool exposure. A tool no longer declares its modes.
* ``TOOL_ACTION_MAP`` / ``TOOL_SCHEMAS`` are derived dicts (kept for callers).
* ``dispatch_action`` (actions.py) routes via ``TOOLS_BY_ACTION[action].handle``.
* ``PermissionEngine`` (guardrails.py) reads ``tool.auto_allow``.

Adding a BUILT-IN tool is one file: drop a ``BaseTool`` subclass in this package, list
it in ``_TOOL_CLASSES``, and make sure a mode's ``tools:`` globs reach it. An EXTERNAL
tool is dropped into the templates dir and auto-registered by
:func:`secator.loader.discover_ai_tools` via :func:`register_ai_tool` — no core edit —
and a mode opts it in by its EXACT name. The consistency test (test_ai_tools) fails if
a mode's resolved tool exposure and its ``allowed_actions`` drift apart.
"""

import json

from secator.ai.prompts import (
	MODES, normalize_mode, mode_tool_patterns, tool_matches_mode, mode_excludes_tool,
)
from secator.ai.tools.base import BaseTool  # noqa: F401 (re-exported)

from secator.ai.tools.run_task import RunTask
from secator.ai.tools.run_subagent import RunSubagent
from secator.ai.tools.run_workflow import RunWorkflow
from secator.ai.tools.run_shell import RunShell
from secator.ai.tools.query_workspace import QueryWorkspace
from secator.ai.tools.add_finding import AddFinding
from secator.ai.tools.mark_vuln_exploited import MarkVulnExploited
from secator.ai.tools.mark_vuln_false_positive import MarkVulnFalsePositive
from secator.ai.tools.mark_vuln_fixed import MarkVulnFixed
from secator.ai.tools.mark_vuln_exploit_failed import MarkVulnExploitFailed
from secator.ai.tools.update_finding import UpdateFinding
from secator.ai.tools.add_note import AddNote
from secator.ai.tools.fetch_url import FetchUrl
from secator.ai.tools.update_plan import UpdatePlan
from secator.ai.tools.web_search import WebSearch
from secator.ai.tools.list_runners import ListRunners
from secator.ai.tools.change_mode import ChangeMode
from secator.ai.tools.stop import Stop
from secator.ai.tools.background_jobs import CheckBackgroundJobs, CancelBackgroundJob


# Order mirrors the historical TOOL_SCHEMAS order so build_tool_schemas emits tools
# in the same order as before (parity). Dynamic/external tools are appended after.
_TOOL_CLASSES = [
	RunTask,
	RunSubagent,
	RunWorkflow,
	RunShell,
	QueryWorkspace,
	AddFinding,
	MarkVulnExploited,
	MarkVulnFalsePositive,
	MarkVulnFixed,
	MarkVulnExploitFailed,
	UpdateFinding,
	AddNote,
	FetchUrl,
	UpdatePlan,
	WebSearch,
	ListRunners,
	ChangeMode,
	CheckBackgroundJobs,
	CancelBackgroundJob,
	Stop,
]

# The live registry. Built-ins are instantiated once; external tools are appended by
# register_ai_tool(). The derived views below are mutated IN PLACE by _rebuild_registry()
# so lazy importers (actions.py / guardrails.py do `from secator.ai.tools import
# TOOLS_BY_ACTION` inside a function) always see the current set.
TOOLS = [cls() for cls in _TOOL_CLASSES]
TOOLS_BY_NAME = {}
TOOLS_BY_ACTION = {}
# Derived views (kept for existing callers; no longer hand-synced). TOOL_SCHEMAS
# excludes `injected` tools (stop), matching the historical contract.
TOOL_ACTION_MAP = {}
TOOL_SCHEMAS = {}


def _rebuild_registry():
	"""Rebuild the name/action/schema views from ``TOOLS`` (in place)."""
	TOOLS_BY_NAME.clear()
	TOOLS_BY_NAME.update({t.name: t for t in TOOLS})
	TOOLS_BY_ACTION.clear()
	TOOLS_BY_ACTION.update({t.action: t for t in TOOLS})
	TOOL_ACTION_MAP.clear()
	TOOL_ACTION_MAP.update({t.name: t.action for t in TOOLS})
	TOOL_SCHEMAS.clear()
	TOOL_SCHEMAS.update({t.name: t.schema for t in TOOLS if not t.injected})


_rebuild_registry()


# Stop tool schemas — NOT in TOOL_SCHEMAS; injected per-backend via get_extra_tools().
# `stop` is the SINGLE end-of-turn signal in every mode: the backend's own ask_user
# decides what happens next (interactive pause / wait, or non-interactive end).

# Interactive stop (TUI / CLI / remote): may carry `choices`/`multiple` so the pause
# offers the user concrete next steps to pick from. This is the registry's Stop schema.
STOP_TOOL_SCHEMA = TOOLS_BY_NAME["stop"].schema

# Non-interactive stop (AutoBackend: subagents + autonomous workers): a DEFINITIVE stop,
# so NO `choices` — there is no user to pick a next step.
STOP_TOOL_SCHEMA_SIMPLE = {
	"type": "function",
	"function": {
		"name": "stop",
		"description": "Stop the current session. Call when the request has been fulfilled or when you encounter a blocker that cannot be resolved without user input.",  # noqa: E501
		"parameters": {
			"type": "object",
			"properties": {
				"reason": {
					"type": "string",
					"description": "Why you are stopping (summary of accomplishments or description of blocker)."
				}
			},
			"required": ["reason"]
		}
	}
}


def _validate_tool_spec(tool):
	"""Validate an external tool instance, returning an error string or None.

	Clear, actionable errors so a bad drop-in is skipped (never crashes startup) and the
	author sees exactly what is wrong. A dynamic tool is the SAFE auto-allow class only
	(like query/add_finding): it runs WITHOUT target/path network gating, so it must have
	no target/path side effects of its OWN — anything that connects to a target must be run
	as a task/workflow via ``actions.run_task_from_tool``, which applies the SAME guardrail /
	permission check (deny rules, target approval, prompt) as a model-issued ``run_task``:
	the tool's auto-allow never extends to the tasks it launches.
	"""
	if not isinstance(tool, BaseTool):
		return "not a BaseTool subclass/instance"
	name = getattr(tool, "name", "")
	if not isinstance(name, str) or not name.strip():
		return "missing a non-empty string `name`"
	if name in TOOLS_BY_NAME:
		return f"name {name!r} clashes with an existing tool"
	if not isinstance(tool.schema, dict) or not tool.schema:
		return f"{name!r}: `schema` must be a non-empty dict"
	# A tool does NOT declare its modes — a mode opts it in via its `tools:` frontmatter
	# (external tools by EXACT name only). So there is no per-tool mode list to validate.
	# A tool must be dispatchable: it overrides run(action, ctx).
	if type(tool).run is BaseTool.run:
		return f"{name!r}: defines no handler (override run(action, ctx))"
	return None


def register_ai_tool(tool):
	"""Register an external AI tool into the live registry.

	Accepts a :class:`BaseTool` subclass or instance. Validates it (clear errors,
	fail-soft — a bad spec is skipped with a Warning, never raised), stamps it as an
	auto-allowed external tool, appends it to ``TOOLS`` and rebuilds the derived views.
	Returns the registered instance, or None if it was rejected. Idempotent per name.
	"""
	from secator.output_types import Warning
	from secator.rich import console
	tool = tool() if isinstance(tool, type) else tool
	# Default the action to the tool name (parity with built-ins where action==dispatch key),
	# and auto-allow external tools (the safe class — see _validate_tool_spec).
	if isinstance(tool, BaseTool):
		if not tool.action:
			tool.action = tool.name
		tool.external = True
		if not getattr(type(tool), "_auto_allow_set", False):
			tool.auto_allow = True
	err = _validate_tool_spec(tool)
	if err:
		console.print(Warning(message=f"Skipping external AI tool: {err}."))
		return None
	if tool.action in TOOLS_BY_ACTION:
		console.print(Warning(message=f"Skipping external AI tool {tool.name!r}: action {tool.action!r} already registered."))
		return None
	TOOLS.append(tool)
	_rebuild_registry()
	_invalidate_pattern_cache()  # re-validate mode patterns against the new registry
	return tool


def resolve_extra_tools(extra_tools=None):
	"""Resolve the effective extra-tool names: config default ∪ the run's ``extra_tools``.

	``CONFIG.addons.ai.extra_tools`` (a custom installation's always-on tools) is merged
	with the per-run ``extra_tools`` option, order-preserving and deduplicated. Every name
	must resolve to a loaded, valid tool (built-in or discovered external); an unknown name
	raises ``ValueError`` with a clear message so a misconfigured/absent tool fails loudly
	rather than being silently dropped.
	"""
	from secator.config import CONFIG
	names = []
	for src in (list(CONFIG.addons.ai.extra_tools or []), list(extra_tools or [])):
		for n in src:
			if n and n not in names:
				names.append(n)
	unknown = [n for n in names if n not in TOOLS_BY_NAME]
	if unknown:
		raise ValueError(
			f"extra_tools refers to unknown AI tool(s): {unknown}. Known tools: "
			f"{sorted(TOOLS_BY_NAME)}. Check CONFIG.addons.ai.extra_tools / the run's "
			f"extra_tools, and that the tool dir / bundle is loaded.")
	return names


def build_tool_schemas(mode: str, is_subagent: bool = False, backend=None, mode_is_auto: bool = True,
                       extra_tools=None) -> list:
	"""Return list of tool schemas exposed in a mode (derived from the registry).

	Triggers external-tool discovery once (cached in the loader) so a tool dropped into
	the templates dir becomes callable without a core edit. The effective tool set is the
	mode's BASELINE (its `tools:` globs over core tools) PLUS ``extra_tools`` (the config
	default ∪ the run's option), MINUS anything the mode explicitly excludes (`!pattern`).

	Args:
		mode: The AI mode (scan, chat, exploit). Unknown modes fall back to chat.
		is_subagent: If True, exclude change_mode and run_subagent (a subagent runs at its
			assigned mode, does not self-escalate, and must not spawn further subagents).
		backend: Optional interactivity backend for exclusion/extra tools. Every
			backend injects a `stop` tool via get_extra_tools (interactive backends a
			`stop` with `choices`, AutoBackend a choiceless one).
		mode_is_auto: Whether the session is in auto mode (vs a user-pinned mode).
			Gates `change_mode`: the model may self-escalate in an auto session or from
			a pinned ACTION mode, but a user-PINNED read-only `chat` must stay read-only,
			so `change_mode` is withheld there (the model can only suggest the user
			switches). An auto session that happens to resolve to chat KEEPS change_mode.
		extra_tools: Names of EXTRA (typically external) tools to add on top of the mode's
			baseline for this run (e.g. ``["add_suggestion"]``). Merged with
			``CONFIG.addons.ai.extra_tools``; every name must resolve to a loaded tool.

	Returns:
		List of OpenAI-format tool schema dicts.
	"""
	try:
		from secator.loader import discover_ai_tools
		discover_ai_tools()
	except Exception:
		pass
	# An unknown mode exposes the same tools as chat (historical fallback), but the
	# pinned-chat `change_mode` gate below keys off the ORIGINAL mode name — an unknown
	# mode is not literally `chat`, so it is NOT withheld there (parity with the prior
	# get_mode_config-based filter, which only used the chat fallback for tool exposure).
	norm = normalize_mode(mode)
	lookup_mode = norm if norm in MODES else "chat"
	patterns = mode_tool_patterns(lookup_mode)
	_validate_mode_patterns(lookup_mode, patterns)
	extras = set(resolve_extra_tools(extra_tools))
	excluded = set()
	if is_subagent:
		# A subagent runs at its assigned mode; it does not self-escalate and
		# cannot spawn further subagents (no nested subagents).
		excluded.update({"change_mode", "run_subagent"})
	# A user-pinned read-only chat cannot self-escape to an action mode.
	if not mode_is_auto and mode == "chat":
		excluded.add("change_mode")
	if backend is not None:
		excluded.update(backend.get_excluded_tools())
	# Effective set = baseline (mode globs over CORE tools) ∪ extras (named, incl. external),
	# minus the mode's explicit `!` excludes and the runtime exclusions above.
	schemas = []
	for t in TOOLS:
		if t.injected or t.name in excluded:
			continue
		in_baseline = tool_matches_mode(t.name, patterns, external=t.external)
		in_extras = t.name in extras and not mode_excludes_tool(t.name, patterns)
		if in_baseline or in_extras:
			schemas.append(t.schema)
	if backend is not None:
		schemas.extend(backend.get_extra_tools())
	return schemas


# Modes whose include patterns we've already validated (warn once per mode).
_VALIDATED_PATTERN_MODES = set()


def _validate_mode_patterns(mode, patterns):
	"""Warn once if a mode's include pattern matches no registered tool (a likely typo).

	Runs against the FULL live registry (built-ins + already-discovered external tools),
	so an exact-name opt-in for an external tool only warns if that tool really is absent.
	"""
	if mode in _VALIDATED_PATTERN_MODES:
		return
	_VALIDATED_PATTERN_MODES.add(mode)
	import fnmatch
	from secator.output_types import Warning
	from secator.rich import console
	names = [t.name for t in TOOLS]
	for pat in patterns:
		if str(pat).startswith("!"):
			continue
		if not any(fnmatch.fnmatchcase(n, str(pat)) for n in names):
			console.print(Warning(
				message=f"AI mode {mode!r}: tools pattern {pat!r} matches no known tool."))


def _invalidate_pattern_cache():
	"""Re-validate mode patterns after the registry changes (e.g. a new external tool)."""
	_VALIDATED_PATTERN_MODES.clear()


def coerce_stringified_args(tool_name: str, arguments: dict) -> dict:
	"""Coerce args the model serialized as JSON strings back to their declared type.

	Some providers stringify nested object/array parameters even when the tool
	schema says ``type: object`` / ``array`` (e.g. ``opts`` or ``query`` arriving
	as a JSON string). Downstream handlers then call ``.get()`` / ``**opts`` /
	``.items()`` on a ``str`` and raise ``AttributeError`` — or silently drop the
	value (``_sanitize_child_opts`` returns ``{}`` for a non-dict). Parse any such
	arg once, here at the tool-call boundary, so every consumer gets the declared
	type. Best-effort: an unparseable value is left as-is so the handler can return
	a clean error rather than crash.

	Must run BEFORE arg decryption — ``_decrypt_dict`` would otherwise treat a
	stringified object as a single encrypted value.
	"""
	if not isinstance(arguments, dict):
		return arguments
	# `stop` lives outside TOOL_SCHEMAS (injected per-backend); fall back to its schema so a
	# stringified `choices` array is coerced like any other object/array tool arg.
	schema = STOP_TOOL_SCHEMA if tool_name == "stop" else TOOL_SCHEMAS.get(tool_name, {})
	props = schema.get("function", {}).get("parameters", {}).get("properties", {})
	for key, spec in props.items():
		if spec.get("type") in ("object", "array") and isinstance(arguments.get(key), str):
			try:
				arguments[key] = json.loads(arguments[key])
			except (json.JSONDecodeError, TypeError, ValueError):
				pass
	return arguments


def tool_call_to_action(tool_name: str, arguments: dict) -> dict | None:
	"""Convert a tool call to an action dict compatible with existing action handlers.

	Args:
		tool_name: The tool function name from the LLM response.
		arguments: The parsed arguments dict from the LLM response.

	Returns:
		Action dict with "action" key added, or None for unknown tools.
	"""
	action_type = TOOL_ACTION_MAP.get(tool_name)
	if action_type is None:
		return None
	if not arguments:
		# `stop` ends the turn and carries no required data (its `reason` is optional),
		# so a bare stop() with empty/no args is VALID and must succeed — otherwise the
		# empty-args reject below bounces every clean stop as "empty arguments" and the
		# model falls back into a follow-up nag loop instead of ending. Every other tool
		# needs arguments, so keep rejecting those. Covers native + text-parsed stop.
		if tool_name == "stop":
			return {"action": action_type, "description": "stopped"}
		# check_background_jobs() with no args (= check all jobs, no wait) is valid too.
		if tool_name == "check_background_jobs":
			return {"action": action_type, "description": "Check background jobs"}
		return None
	# A model may emit non-object arguments (bare JSON int/array/string) -- `.items()`
	# below would raise and abort the loop, so reject cleanly and let the caller retry.
	if not isinstance(arguments, dict):
		return None
	safe_arguments = {k: v for k, v in arguments.items() if k not in {"action", "description"}}
	# Some models routinely drop the leading underscore on the `_uuid` identity arg,
	# sending `uuid` instead — every finding tool (mark_vuln_exploited /
	# mark_vuln_false_positive / update_finding) then errors "requires `_uuid`".
	# Normalize the common misspelling so the intent isn't lost to a naming quirk.
	if "uuid" in safe_arguments and "_uuid" not in safe_arguments:
		safe_arguments["_uuid"] = safe_arguments.pop("uuid")
	# Prefer the description the model was asked to provide (run_task/run_workflow/run_shell all
	# require it); fall back to name/query/command only when it's missing. Was previously dropped
	# here, so the AI-chat background-tasks list showed the raw command instead of the description.
	descr = (
		arguments.get("description")
		or safe_arguments.get("name", "")
		or safe_arguments.get("query")
		or safe_arguments.get("command")
		or safe_arguments.get("mode")
		or "unknown"
	)
	return {"action": action_type, "description": descr, **safe_arguments}

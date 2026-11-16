"""Base class + shared schema/mode constants for native and external AI tools.

An AI tool is one :class:`BaseTool` subclass carrying everything the registry
needs (schema, dispatch action, mode exposure, permission auto-allow, handler).
Built-in tools live one-per-file in this package and set ``handler`` to the name
of a ``_handle_*`` generator in :mod:`secator.ai.actions`. An EXTERNAL tool
(dropped into the templates dir, see :func:`secator.loader.discover_ai_tools`)
instead defines its own ``run(action, ctx)`` generator in its file — the handler
travels WITH the tool, exactly like a custom secator task.
"""

_TARGETS_SCHEMA = {
	"type": "array",
	"items": {"type": "string"},
	"description": "List of targets (hosts, URLs, IPs)."
}

_DESCRIPTION_SCHEMA = {
	"type": "string",
	"description": "A short plain-English statement of your INTENT — WHY you are running this, in 4-10 words. "
	               "Do NOT paste the command, and do NOT just repeat the task name; describe the PURPOSE. "
	               "BAD (never do this): 'nmap', 'httpx', 'curl -sk http://...'. "
	               "GOOD: 'Scan for open services and versions', 'Probe which HTTP methods are allowed', "
	               "'Fire the reflected-XSS payload at level 1'. Shown to the user in place of the bare task name."
}

# Mode-membership sets, so each tool declares exposure declaratively. These mirror
# the per-mode ``allowed_actions`` in prompts.MODES (enforced by the consistency test).
# Finding-writing / exploit tools (add_finding, mark_vuln_*, update_finding) — the modes
# that RECORD findings: scan, exploit, research. NOT contribute, which authors code, not
# findings.
_ACTIVE_MODES = frozenset({"scan", "exploit", "research"})
# Tools that RUN a runner (task/workflow/shell). `contribute` needs these to exercise the
# code it authors, so it is added here on top of the finding-writing modes.
_RUNNER_MODES = frozenset({"scan", "exploit", "research", "contribute"})
_ALL_MODES = frozenset({"scan", "chat", "exploit", "contribute", "research"})
# Read-only helper tools (web/plan/run-history lookups) — every mode except monitor.
_READONLY_HELPER = _ALL_MODES
# monitor is a bounded re-verification mode over the EXISTING finding set: it re-probes a
# finding with shell, and retires/annotates it (mark_vuln_false_positive / mark_vuln_fixed /
# update_finding / add_note) — but never runs tasks/workflows, add_finding,
# mark_vuln_exploited / exploit_failed, subagent or change_mode. This set is the
# finding-curation tools it SHARES with scan/exploit/research.
_SCAN_EXPLOIT_MONITOR = frozenset({"scan", "exploit", "research", "monitor"})
# `run_shell`: the runner modes plus monitor (a targeted re-check of one finding's own target).
_SHELL_MODES = _RUNNER_MODES | {"monitor"}
# `query` and `stop` are available in EVERY mode (incl. monitor). The read-only helpers
# (_READONLY_HELPER) are NOT exposed in monitor, a focused re-verification loop.
_QUERY_MODES = _ALL_MODES | {"monitor"}
# `change_mode` — every mode EXCEPT contribute, research and monitor: contribute and research
# are deliberate, directly-selected terminal modes (contribute authors secator code; research
# already has the most capable surface), and monitor is a bounded, non-escalating pass. The
# other modes keep the escalation ladder.
_CAN_CHANGE_MODE = frozenset({"scan", "chat", "exploit"})


class BaseTool:
	"""One AI tool. Subclasses set the class attributes; the registry does the rest.

	Attributes:
		name: Tool function name exposed to the LLM (e.g. ``run_task``).
		action: Dispatch key / action type used by handlers (e.g. ``task``).
		schema: OpenAI-format function schema dict.
		modes: Set of modes that expose this tool (``build_tool_schemas`` filter).
		auto_allow: True if ``PermissionEngine`` auto-allows this action at the
			action-type layer (no name/scope rule needed). task/workflow/shell are
			False — they have their own layer-1 handling.
		injected: True for a tool NOT emitted by ``build_tool_schemas`` mode
			filtering and NOT listed in ``TOOL_SCHEMAS``; it is injected separately
			via the interactivity backend's ``get_extra_tools`` (``stop``).
		handler: Name of the ``_handle_*`` generator in ``secator.ai.actions`` (built-in
			tools). Leave empty on an external tool and override :meth:`run` instead.
		external: Set True by the loader for a tool discovered from the templates dir.
	"""

	name: str = ""
	action: str = ""
	schema: dict = {}
	modes: frozenset = frozenset()
	auto_allow: bool = False
	injected: bool = False
	handler: str = ""
	external: bool = False

	def handle(self, action, ctx):
		"""Dispatch to the tool's handler.

		Built-in tools name a ``_handle_*`` generator in :mod:`secator.ai.actions`
		(lazy import avoids a tools<->actions cycle). An external tool leaves
		``handler`` empty and implements :meth:`run` in its own file.
		"""
		if self.handler:
			from secator.ai import actions
			return getattr(actions, self.handler)(action, ctx)
		return self.run(action, ctx)

	def run(self, action, ctx):
		"""Generator handler for an external tool. Override in the tool file."""
		raise NotImplementedError(f"AI tool {self.name!r} defines no handler")

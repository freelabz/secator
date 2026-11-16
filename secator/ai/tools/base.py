"""Base class + shared parameter schemas for native and external AI tools.

An AI tool is one :class:`BaseTool` subclass carrying everything the registry needs
(schema, dispatch action, permission auto-allow, handler). Built-in tools live
one-per-file in this package and set ``handler`` to the name of a ``_handle_*``
generator in :mod:`secator.ai.actions`. An EXTERNAL tool (dropped into the templates
dir, see :func:`secator.loader.discover_ai_tools`) instead defines its own
``run(action, ctx)`` generator in its file — the handler travels WITH the tool, exactly
like a custom secator task.

A tool does NOT declare which modes expose it. Mode exposure is the mode's
responsibility: each mode prompt's frontmatter ``tools:`` globs (see
:func:`secator.ai.prompts.tool_matches_mode`) are the single source of truth for the
mode's BASELINE tools, and resolve against CORE tools only. An external tool is never
pulled in by a mode's globs; it is added on top per-run via the ``ai`` task's
``extra_tools`` option (or ``CONFIG.addons.ai.extra_tools``).

Reusing other dynamically-loaded extensions
--------------------------------------------
A custom tool can reuse the custom tasks and hooks core has already loaded from the
templates dir, through the stable public accessors. Tools load AFTER tasks and hooks, so
the references resolve. Example — an org drops a custom ``cockpit`` task and a custom
reporting hook (e.g. a SysReptor driver) into ``~/.secator/templates``, then adds a tool
that uses both::

	from secator.ai.tools.base import BaseTool
	from secator.loader import get_task_class, get_driver_hooks
	from secator.ai.actions import run_task_from_tool
	from secator.output_types import Info

	class ExportReport(BaseTool):
		name = "export_report"
		schema = {"type": "function", "function": {"name": "export_report",
			"description": "Run the cockpit task and push results to the reporting hook.",
			"parameters": {"type": "object", "properties": {
				"targets": {"type": "array", "items": {"type": "string"}}}}}}

		def run(self, action, ctx):
			# Run a CUSTOM task through the SAME path as the built-in run_task tool
			# (scope/guardrail + child-hook propagation) — never invoke it ad-hoc.
			if get_task_class("cockpit"):
				yield from run_task_from_tool(ctx, "cockpit", targets=action.get("targets"),
				                              description="Collect cockpit data")
			# Reuse a CUSTOM reporting hook core loaded as a driver.
			hooks = get_driver_hooks("sysreptor") or {}
			for fn in hooks.get("on_item", []):
				fn(action)
			yield Info(message="exported")

Activation is unchanged: the tool is only active when named in ``extra_tools`` (per run
or via ``CONFIG.addons.ai.extra_tools``).
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


class BaseTool:
	"""One AI tool. Subclasses set the class attributes; the registry does the rest.

	Attributes:
		name: Tool function name exposed to the LLM (e.g. ``run_task``).
		action: Dispatch key / action type used by handlers (e.g. ``task``).
		schema: OpenAI-format function schema dict.
		auto_allow: True if ``PermissionEngine`` auto-allows this action at the
			action-type layer (no name/scope rule needed). task/workflow/shell are
			False — they have their own layer-1 handling.
		injected: True for a tool NOT emitted by ``build_tool_schemas`` mode
			filtering and NOT listed in ``TOOL_SCHEMAS``; it is injected separately
			via the interactivity backend's ``get_extra_tools`` (``stop``).
		handler: Name of the ``_handle_*`` generator in ``secator.ai.actions`` (built-in
			tools). Leave empty on an external tool and override :meth:`run` instead.
		external: Set True by the loader for a tool discovered from the templates dir.
			External tools are exposed to a mode only by an EXACT-name ``tools:`` entry.
	"""

	name: str = ""
	action: str = ""
	schema: dict = {}
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

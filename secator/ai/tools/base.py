"""Base class + shared parameter schemas for native and external AI tools.

An AI tool is one :class:`BaseTool` subclass carrying everything the registry needs
(schema, dispatch action, permission auto-allow, handler). Every tool — built-in tools
one-per-file in this package, and EXTERNAL tools dropped into the templates dir (see
:func:`secator.loader.discover_ai_tools`) — defines its handler as its own
``run(action, ctx)`` generator in its file: the handler travels WITH the tool, exactly
like a custom secator task. Helpers shared by several built-in tools live in
``_runner.py`` / ``_sandbox.py`` / ``_findings.py``.

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


def _stamp_tool_call(results, call):
	"""Yield ``results``, adding the ``call`` keys to each item's ``_context`` when it has no call id."""
	for item in results:
		if isinstance(item, dict):
			context = item.get("_context") if isinstance(item.get("_context"), dict) else {}
			if "tool_call_id" not in context:
				item["_context"] = {**context, **call}
		elif hasattr(item, "_context"):
			context = item._context if isinstance(item._context, dict) else {}
			if "tool_call_id" not in context:
				item._context = {**context, **call}
		yield item


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
		external: Set True by the loader for a tool discovered from the templates dir.
			External tools are never matched by a mode's ``tools:`` globs; they are added
			per-run via ``extra_tools`` (or ``CONFIG.addons.ai.extra_tools``).

	Every tool — built-in or external — implements its handler as :meth:`run` in its own
	file; dispatch is identical for both.
	"""

	name: str = ""
	action: str = ""
	schema: dict = {}
	auto_allow: bool = False
	injected: bool = False
	external: bool = False

	def handle(self, action, ctx):
		"""Dispatch to the tool's handler, its :meth:`run` generator.

		Every result is tagged with this tool call (``tool_call_id`` / ``tool_call_name`` in its
		``_context``) when it does not carry one yet, so the agent loop can attach it to the model's
		tool call. That covers a result the tool did not stamp itself, and the output of a task it runs
		through ``run_task_from_tool`` (which dispatches a fresh action with no call id). Results that
		are already stamped are left unchanged.
		"""
		call = {k: action.get(k) for k in ("tool_call_id", "tool_call_name") if action.get(k)}
		results = self.run(action, ctx)
		return _stamp_tool_call(results, call) if call else results

	def run(self, action, ctx):
		"""Generator handler: yields OutputTypes. Every tool overrides this in its file."""
		raise NotImplementedError(f"AI tool {self.name!r} defines no handler")

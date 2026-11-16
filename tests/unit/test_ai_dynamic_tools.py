"""Tests for class-based external AI tools (discover_ai_tools / register_ai_tool).

An external AI tool is a ``*.py`` file dropped into the templates dir that defines a
``secator.ai.tools.BaseTool`` subclass with its handler in the same file — the same
drop-in model as a custom secator task. These tests prove the end-to-end wiring: a
dropped-in tool registers (schema per mode, action dispatch, guardrail auto-allow), a
broken sibling is skipped while a good one still loads, and a name clash is refused.
"""
import sys
import textwrap
import unittest

from secator.config import CONFIG
from secator.definitions import ADDONS_ENABLED


def _reset():
	from secator import loader
	from secator.ai import tools
	loader.discover_ai_tools.cache_clear()
	# Drop any external tool registered by a previous test and rebuild the derived views.
	tools.TOOLS[:] = [t for t in tools.TOOLS if not getattr(t, 'external', False)]
	tools._rebuild_registry()
	for key in [k for k in sys.modules if k.startswith('secator.ai.tools_ext.')]:
		del sys.modules[key]


_GOOD_TOOL = textwrap.dedent('''
	from secator.ai.tools.base import BaseTool
	from secator.output_types import Info


	class PingPong(BaseTool):
		name = "ping_pong"
		schema = {
			"type": "function",
			"function": {
				"name": "ping_pong",
				"description": "Echo a message back.",
				"parameters": {
					"type": "object",
					"properties": {"msg": {"type": "string"}},
					"required": ["msg"],
				},
			},
		}

		def run(self, action, ctx):
			yield Info(message=f"pong: {action.get('msg', '')}")
''')

_BROKEN_TOOL = "from secator.ai.tools.base import BaseTool\nthis is not valid python (\n"

_CLASH_TOOL = textwrap.dedent('''
	from secator.ai.tools.base import BaseTool


	class RunTask(BaseTool):
		name = "run_task"
		schema = {"type": "function", "function": {"name": "run_task"}}

		def run(self, action, ctx):
			yield None
''')


@unittest.skipUnless(ADDONS_ENABLED['ai'], "ai addon not installed")
class TestDynamicAITools(unittest.TestCase):
	def setUp(self):
		self.dir = CONFIG.dirs.templates
		self.dir.mkdir(parents=True, exist_ok=True)
		self.written = []
		_reset()

	def tearDown(self):
		for p in self.written:
			if p.exists():
				p.unlink()
		_reset()

	def _write(self, name, content):
		p = self.dir / name
		p.write_text(content)
		self.written.append(p)
		return p

	def test_valid_tool_registers_into_the_registry(self):
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import TOOLS_BY_NAME, TOOLS_BY_ACTION, TOOL_ACTION_MAP
		registered = discover_ai_tools()
		self.assertIn("ping_pong", registered)
		# In the registry, with action defaulting to the name, and marked external.
		self.assertIn("ping_pong", TOOLS_BY_NAME)
		self.assertTrue(TOOLS_BY_NAME["ping_pong"].external)
		self.assertTrue(TOOLS_BY_NAME["ping_pong"].auto_allow)
		self.assertEqual(TOOL_ACTION_MAP["ping_pong"], "ping_pong")
		self.assertIn("ping_pong", TOOLS_BY_ACTION)

	def test_external_tool_not_in_baseline_added_only_via_extra_tools(self):
		"""A mode's globs match CORE tools only — a broad `*` never exposes an external
		tool. The external tool is added only when passed as `extra_tools` for the run."""
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import build_tool_schemas
		discover_ai_tools()
		# scan is `tools: ["*"]` — the glob must not expose the external tool.
		scan_names = [s["function"]["name"] for s in build_tool_schemas("scan")]
		self.assertNotIn("ping_pong", scan_names)
		# Added on top only when requested for the run.
		chat_names = [s["function"]["name"] for s in build_tool_schemas("chat", extra_tools=["ping_pong"])]
		self.assertIn("ping_pong", chat_names)
		# Not sticky: a later run without extra_tools does not expose it.
		self.assertNotIn("ping_pong", [s["function"]["name"] for s in build_tool_schemas("chat")])

	def test_extra_tools_from_config_default(self):
		"""`CONFIG.addons.ai.extra_tools` adds a tool to every run, merged with the option."""
		self._write("ping_pong.py", _GOOD_TOOL)
		from unittest import mock
		from secator.config import CONFIG
		from secator.loader import discover_ai_tools
		from secator.ai.tools import build_tool_schemas, resolve_extra_tools
		discover_ai_tools()
		with mock.patch.object(CONFIG.addons.ai, "extra_tools", ["ping_pong"]):
			self.assertEqual(resolve_extra_tools(), ["ping_pong"])
			# config ∪ run option, deduplicated
			self.assertEqual(resolve_extra_tools(["ping_pong"]), ["ping_pong"])
			names = [s["function"]["name"] for s in build_tool_schemas("chat")]
			self.assertIn("ping_pong", names)

	def test_extra_tools_unknown_name_errors(self):
		"""A configured/requested tool that isn't loaded fails loudly."""
		from secator.ai.tools import resolve_extra_tools, build_tool_schemas
		with self.assertRaises(ValueError):
			resolve_extra_tools(["does_not_exist"])
		with self.assertRaises(ValueError):
			build_tool_schemas("chat", extra_tools=["does_not_exist"])

	def test_mode_exclude_overrides_extra_tools(self):
		"""A mode's `!name` exclude removes a tool even if passed via extra_tools."""
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import build_tool_schemas
		from secator.ai.prompts import MODES
		discover_ai_tools()
		orig = list(MODES["chat"]["tools"])
		MODES["chat"]["tools"] = orig + ["!ping_pong"]
		try:
			names = [s["function"]["name"] for s in build_tool_schemas("chat", extra_tools=["ping_pong"])]
			self.assertNotIn("ping_pong", names)
		finally:
			MODES["chat"]["tools"] = orig

	def test_handler_dispatches_through_run(self):
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import TOOLS_BY_ACTION
		discover_ai_tools()
		tool = TOOLS_BY_ACTION["ping_pong"]
		out = list(tool.handle({"action": "ping_pong", "msg": "hi"}, ctx=None))
		self.assertTrue(any("pong: hi" in str(getattr(o, "message", "")) for o in out))

	def test_guardrail_auto_allows_dynamic_action(self):
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		discover_ai_tools()
		from secator.ai.guardrails import PermissionEngine
		# No rules configured: a built-in auto-allow tool (query/add_finding) resolves to
		# allow purely from `tool.auto_allow`; a dynamic tool must do the same.
		engine = PermissionEngine(config={}, targets=["example.com"])
		result = engine.check_action({"action": "ping_pong", "msg": "hi"})
		self.assertEqual(result.decision, "allow")

	def test_broken_sibling_skipped_good_still_loads(self):
		self._write("ping_pong.py", _GOOD_TOOL)
		self._write("broken_tool.py", _BROKEN_TOOL)
		from secator.loader import discover_ai_tools
		registered = discover_ai_tools()
		self.assertIn("ping_pong", registered)
		self.assertNotIn("broken_tool", registered)

	def test_name_clash_with_builtin_is_refused(self):
		self._write("run_task_ext.py", _CLASH_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import TOOLS_BY_NAME
		registered = discover_ai_tools()
		self.assertNotIn("run_task", registered)
		# The built-in run_task is still the real one (not shadowed).
		self.assertFalse(TOOLS_BY_NAME["run_task"].external)

	def test_external_tools_skipped_by_task_discovery(self):
		"""An AI-tool file must not be mistaken for a custom task."""
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import _file_has_ai_tool
		self.assertTrue(_file_has_ai_tool(self.dir / "ping_pong.py"))


@unittest.skipUnless(ADDONS_ENABLED['ai'], "ai addon not installed")
class TestCustomToolReusesExtensions(unittest.TestCase):
	"""A custom AI tool can reuse OTHER user-defined extensions core loads dynamically:
	a custom task (get_task_class / run_task_from_tool) and a custom reporting hook
	(get_driver_hooks). Tools load AFTER tasks + hooks so the references resolve."""

	def setUp(self):
		self.dir = CONFIG.dirs.templates
		self.dir.mkdir(parents=True, exist_ok=True)
		self.sentinel = self.dir / "hook_calls.log"
		if self.sentinel.exists():
			self.sentinel.unlink()
		self.written = []
		self._clear()

	def tearDown(self):
		for p in self.written + [self.sentinel]:
			if p.exists():
				p.unlink()
		self._clear()

	def _clear(self):
		from secator import loader
		for fn in ("discover_ai_tools", "discover_tasks", "discover_external_tasks",
		           "discover_external_drivers"):
			getattr(loader, fn).cache_clear()
		_reset()
		for key in [k for k in list(sys.modules)
		            if k.startswith(("secator.tasks.cockpit", "secator.hooks.acme_report"))]:
			del sys.modules[key]

	def _write(self, name, content):
		p = self.dir / name
		p.write_text(content)
		self.written.append(p)
		return p

	def test_custom_tool_runs_custom_task_and_calls_custom_hook(self):
		from unittest import mock
		# 1) a custom task (dropped in like any external task)
		self._write("cockpit.py", "class cockpit:\n\tfriendly_name = 'cockpit'\n")
		# 2) a custom reporting hook (an external driver: HOOKS dict) that records calls
		self._write("acme_report.py", textwrap.dedent(f'''
			SENTINEL = r"{self.sentinel}"

			def send_report(payload):
				with open(SENTINEL, "a") as f:
					f.write(f"hook:{{payload}}\\n")

			HOOKS = {{"on_item": [send_report]}}
		'''))
		# 3) a custom AI tool that reuses BOTH
		self._write("export_report.py", textwrap.dedent('''
			from secator.ai.tools.base import BaseTool
			from secator.loader import get_task_class, get_driver_hooks
			from secator.ai.actions import run_task_from_tool
			from secator.output_types import Info

			class ExportReport(BaseTool):
				name = "export_report"
				schema = {"type": "function", "function": {"name": "export_report",
					"description": "Run the cockpit task and push results to the reporting hook.",
					"parameters": {"type": "object", "properties": {}}}}

				def run(self, action, ctx):
					hooks = get_driver_hooks("acme_report") or {}
					for fn in hooks.get("on_item", []):
						fn("from_tool")
					if get_task_class("cockpit") is not None:
						yield from run_task_from_tool(ctx, "cockpit", targets=["example.com"],
						                              description="collect cockpit data")
					yield Info(message="exported")
		'''))

		from secator.config import CONFIG as CFG
		from secator.ai.tools import build_tool_schemas, TOOLS_BY_NAME
		from secator.loader import get_task_class, get_driver_hooks
		import secator.ai.actions as actions

		# Activation ONLY via extra_tools (here the config default).
		with mock.patch.object(CFG.addons.ai, "extra_tools", ["export_report"]):
			# Exposed on a run because it's a configured extra tool.
			names = [s["function"]["name"] for s in build_tool_schemas("chat")]
			self.assertIn("export_report", names)
			# The public accessors resolve the sibling extensions (load order proven).
			self.assertIsNotNone(get_task_class("cockpit"))
			self.assertIn("on_item", get_driver_hooks("acme_report"))

			# Invoke the handler; record task runs via the SAME path (dispatch_action).
			calls = []

			def _rec(action, ctx):
				calls.append(action)
				return iter(())
			with mock.patch.object(actions, "dispatch_action", _rec):
				list(TOOLS_BY_NAME["export_report"].handle({"action": "export_report"}, ctx=None))

		# The custom HOOK was called.
		self.assertTrue(self.sentinel.exists())
		self.assertIn("hook:from_tool", self.sentinel.read_text())
		# The custom TASK was run through the run_task path (same as built-in run_task).
		self.assertTrue(any(c.get("action") == "task" and c.get("name") == "cockpit" for c in calls),
		                f"task not run via run_task_from_tool path: {calls}")

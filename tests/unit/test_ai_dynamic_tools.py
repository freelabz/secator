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

	def test_external_tool_exposed_only_by_exact_name_opt_in(self):
		"""A mode's broad `*` glob must NOT auto-grant the external tool; an exact-name
		`tools:` entry does. This is the Q4 guard against silent privilege creep."""
		self._write("ping_pong.py", _GOOD_TOOL)
		from secator.loader import discover_ai_tools
		from secator.ai.tools import build_tool_schemas
		from secator.ai.prompts import MODES
		discover_ai_tools()
		# scan is `tools: ["*"]` — the glob must not expose the external tool.
		scan_names = [s["function"]["name"] for s in build_tool_schemas("scan")]
		self.assertNotIn("ping_pong", scan_names)
		# Opt chat in by EXACT name -> now exposed there, still not in scan.
		orig = list(MODES["chat"]["tools"])
		MODES["chat"]["tools"] = orig + ["ping_pong"]
		try:
			chat_names = [s["function"]["name"] for s in build_tool_schemas("chat")]
			scan_names = [s["function"]["name"] for s in build_tool_schemas("scan")]
			self.assertIn("ping_pong", chat_names)
			self.assertNotIn("ping_pong", scan_names)
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

"""Tests for dynamic (autoloaded) AI tools dropped into CONFIG.dirs.templates."""
import textwrap
import unittest

from secator.config import CONFIG
from secator.definitions import ADDONS_ENABLED


GOOD_TOOL = '''
from secator.output_types import Ai


def handler(action, ctx):
	yield Ai(content="pong: " + str(action.get("msg", "")), ai_type="ping")


AI_TOOL = {
	"name": "ping",
	"description": "Echo a message back (test dynamic tool).",
	"parameters": {"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]},
	"handler": handler,
	"modes": ["chat", "attack", "exploit"],
}
'''

BROKEN_TOOL = '''
raise RuntimeError("boom at import time")
AI_TOOL = {"name": "broken", "handler": lambda a, c: iter(())}
'''


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDynamicAiTools(unittest.TestCase):
	"""Drop *.py tool files into the real templates dir (the discovery source) and clean up."""

	def setUp(self):
		self.template_dir = CONFIG.dirs.templates
		self.template_dir.mkdir(parents=True, exist_ok=True)
		self._files = []
		self._reset_registry()

	def tearDown(self):
		for f in self._files:
			if f.exists():
				f.unlink()
		self._reset_registry()

	def _reset_registry(self):
		import secator.loader as loader
		import secator.ai.tools as tools
		from secator.ai.prompts import MODES
		loader.discover_ai_tools.cache_clear()
		for name in list(tools.DYNAMIC_TOOL_NAMES):
			tools.TOOL_SCHEMAS.pop(name, None)
			tools.TOOL_ACTION_MAP.pop(name, None)
		for at in list(tools.DYNAMIC_ACTION_TYPES):
			tools.DYNAMIC_HANDLERS.pop(at, None)
			for cfg in MODES.values():
				if at in cfg["allowed_actions"]:
					cfg["allowed_actions"].remove(at)
		tools.DYNAMIC_ACTION_TYPES.clear()
		tools.DYNAMIC_TOOL_NAMES.clear()

	def _drop(self, files: dict):
		for fname, content in files.items():
			path = self.template_dir / fname
			path.write_text(textwrap.dedent(content))
			self._files.append(path)
		import secator.loader as loader
		loader.discover_ai_tools.cache_clear()
		return loader.discover_ai_tools()

	def test_dynamic_tool_registered_end_to_end(self):
		self.assertIn('ping', self._drop({'zzz_ping_tool.py': GOOD_TOOL}))
		from secator.ai.tools import build_tool_schemas, tool_call_to_action, TOOL_ACTION_MAP
		for mode in ('chat', 'attack', 'exploit'):
			self.assertIn('ping', {s['function']['name'] for s in build_tool_schemas(mode)}, mode)
		self.assertEqual(TOOL_ACTION_MAP['ping'], 'ping')
		action = tool_call_to_action('ping', {'msg': 'hi'})
		self.assertEqual(action['action'], 'ping')
		from secator.ai.actions import ActionContext, dispatch_action
		from secator.output_types import Ai
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})
		out = list(dispatch_action(action, ctx))
		self.assertTrue(any(isinstance(o, Ai) and o.content == 'pong: hi' for o in out))

	def test_dynamic_tool_is_guardrail_allowed(self):
		self._drop({'zzz_ping_tool.py': GOOD_TOOL})
		from secator.ai.guardrails import PermissionEngine
		e = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		self.assertEqual(e.check_action({'action': 'ping', 'msg': 'x'}).decision, 'allow')

	def test_broken_tool_skipped_without_crashing(self):
		registered = self._drop({'zzz_broken_tool.py': BROKEN_TOOL, 'zzz_ping_tool.py': GOOD_TOOL})
		self.assertIn('ping', registered)
		self.assertNotIn('broken', registered)
		from secator.ai.tools import TOOL_SCHEMAS
		self.assertNotIn('broken', TOOL_SCHEMAS)
		self.assertIn('ping', TOOL_SCHEMAS)

	def test_name_clash_with_builtin_skipped(self):
		clash = GOOD_TOOL.replace('"name": "ping"', '"name": "run_shell"')
		registered = self._drop({'zzz_clash_tool.py': clash})
		self.assertNotIn('run_shell', registered)
		from secator.ai.tools import TOOL_ACTION_MAP
		self.assertEqual(TOOL_ACTION_MAP['run_shell'], 'shell')  # built-in untouched


if __name__ == '__main__':
	unittest.main()

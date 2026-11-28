"""Live TUI cards for tools without a dedicated renderer.

``web_search`` and ``fetch_url`` yield their own ``Ai`` display item (``ai_type`` = the tool
name). The live view had a branch only for runner and finding tools, so these items reached
the TUI and were dropped: the call left no trace until a resume replayed it. They now render
as the same finished tool card the replay uses. External tools (loaded from a tools dir) only
yield their results, so the shared dispatch path yields that display item for them.
"""
import asyncio
from unittest.mock import patch

import pytest

pytest.importorskip("textual")

from secator.ai.actions import ActionContext, dispatch_action  # noqa: E402
from secator.output_types import Ai  # noqa: E402
from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.widgets import ToolCallPanel  # noqa: E402

HITS = [{"_type": "url", "url": "https://example.com/poc", "title": "PoC"}]
PAGE = {
	"url": "https://example.com/", "status": 200, "title": "Example Domain",
	"content_type": "text/html", "text": "Example Domain\nThis domain is for use in examples.", "truncated": False,
}


def _tool_items(name, **args):
	"""The items a real tool call yields, through the loop's dispatch path."""
	action = {"action": name, "tool_call_id": f"call-{name}", "tool_call_name": name, **args}
	ctx = ActionContext(targets=["example.com"], model="m")
	with patch("secator.ai.tools.web.web_search", return_value=(HITS, "duckduckgo")):
		with patch("secator.ai.tools.web.fetch_url", return_value=(PAGE, None)):
			return list(dispatch_action(action, ctx))


async def _render(items):
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		for item in items:
			await app._render(item)
		await pilot.pause(0.05)
		return [(p.tool_name, p.rname, p.done, p._args, p._result_text) for p in app.query(ToolCallPanel)]


def test_web_search_call_renders_a_tool_card():
	items = _tool_items("web_search", query="example cve poc", mode="exploit")
	assert any(isinstance(i, Ai) and i.ai_type == "web_search" for i in items)
	cards = asyncio.run(_render(items))
	assert len(cards) == 1
	name, title, done, args, result = cards[0]
	assert name == "web_search" and done
	assert title == "example cve poc" and result == "example cve poc"
	assert args["count"] == 1 and args["results"][0]["url"] == "https://example.com/poc"


def test_fetch_url_call_renders_a_tool_card():
	items = _tool_items("fetch_url", url="https://example.com/")
	cards = asyncio.run(_render(items))
	assert len(cards) == 1
	name, title, done, args, result = cards[0]
	assert name == "fetch_url" and title == "fetch_url" and done
	assert result == "Example Domain\nThis domain is for use in examples."
	assert args["url"] == "https://example.com/" and args["title"] == "Example Domain"
	assert "ai_query_result" not in args


def test_items_tagged_with_another_tool_call_stay_hidden():
	# A subagent's own loop items carry the call that spawned it (run_subagent); their
	# ai_type is not that tool's name, so they must not become tool cards.
	spawn_call = {"tool_call_id": "call-sub", "tool_call_name": "run_subagent"}
	internal = Ai(content="", ai_type="turn_completed", _context=spawn_call)
	untagged = Ai(content="", ai_type="chat_compacted")
	assert asyncio.run(_render([internal, untagged])) == []


_EXTERNAL_TOOL = '''
from secator.ai.tools.base import BaseTool
from secator.output_types import Info


class EchoTool(BaseTool):
	name = "echo_tool"
	schema = {"type": "function", "function": {"name": "echo_tool", "description": "Echo a message.",
		"parameters": {"type": "object", "properties": {"msg": {"type": "string"}}}}}

	def run(self, action, ctx):
		yield Info(message="echo: " + action.get("msg", ""))
'''


@pytest.fixture
def echo_tool(tmp_path, monkeypatch):
	"""Load a tiny external tool from a temp tools dir, removed again afterwards."""
	import sys
	from secator import loader
	from secator.ai import tools

	def reset():
		loader.discover_ai_tools.cache_clear()
		tools.TOOLS[:] = [t for t in tools.TOOLS if not t.external]
		tools._rebuild_registry()
		for key in [k for k in sys.modules if k.startswith("secator.ai.tools_ext.")]:
			del sys.modules[key]

	(tmp_path / "echo_tool.py").write_text(_EXTERNAL_TOOL)
	monkeypatch.setenv("SECATOR_AI_TOOLS_DIRS", str(tmp_path))
	reset()
	assert "echo_tool" in loader.discover_ai_tools()
	yield
	reset()


def test_external_tool_call_renders_a_tool_card(echo_tool):
	from secator.ai.tools import tool_call_to_action
	action = {**tool_call_to_action("echo_tool", {"msg": "hi"}), "tool_call_id": "c1", "tool_call_name": "echo_tool"}
	items = list(dispatch_action(action, ActionContext(targets=["example.com"], model="m")))
	ai = [i for i in items if isinstance(i, Ai)]
	assert len(ai) == 1 and ai[0].ai_type == "echo_tool"
	assert ai[0]._context["tool_call_id"] == "c1" and ai[0]._context["tool_call_name"] == "echo_tool"
	cards = asyncio.run(_render(items))
	assert cards == [("echo_tool", "msg=hi", True, {"msg": "hi"}, "msg=hi")]


def test_external_tool_call_with_description_is_titled_by_it(echo_tool):
	from secator.ai.tools import tool_call_to_action
	action = {**tool_call_to_action("echo_tool", {"msg": "hi", "description": "Say hi"}),
	          "tool_call_id": "c1", "tool_call_name": "echo_tool"}
	cards = asyncio.run(_render(list(dispatch_action(action, ActionContext(targets=[], model="m")))))
	assert len(cards) == 1 and cards[0][0] == "echo_tool" and cards[0][1] == "Say hi"


def test_external_tool_call_replays_as_one_tool_card(echo_tool):
	messages = [
		{"role": "user", "content": "echo hi"},
		{"role": "assistant", "content": "", "tool_calls": [
			{"id": "c1", "function": {"name": "echo_tool", "arguments": '{"msg": "hi"}'}}]},
		{"role": "tool", "tool_call_id": "c1", "content": "echo: hi"},
	]

	async def replay():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(120, 40)) as pilot:
			await pilot.pause(0.05)
			await app._replay_history(messages)
			await pilot.pause(0.05)
			return [(p.tool_name, p._args) for p in app.query(ToolCallPanel)]

	assert asyncio.run(replay()) == [("echo_tool", {"msg": "hi"})]


def test_external_tool_named_like_an_ai_item_type_is_refused(echo_tool):
	from secator.ai.tools import register_ai_tool
	from secator.ai.tools.base import BaseTool

	class Stopped(BaseTool):
		name = "stopped"
		schema = {"type": "function", "function": {"name": "stopped"}}

		def run(self, action, ctx):
			yield from ()

	assert register_ai_tool(Stopped) is None

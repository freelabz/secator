"""Live TUI cards for tools without a dedicated renderer.

``web_search`` and ``fetch_url`` yield their own ``Ai`` display item (``ai_type`` = the tool
name). The live view had a branch only for runner and finding tools, so these items reached
the TUI and were dropped: the call left no trace until a resume replayed it. They now render
as the same finished tool card the replay uses.
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

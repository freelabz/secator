"""Resume replay renders a saved session like the live view.

The model-facing history holds per-iteration control messages under the ``user`` role and
tool calls / results as separate messages. The replay must hide the former (they are never
shown live) and render each tool call as a collapsible card holding its args and its
result (linked by tool_call id) — in order, from a history saved to disk and reloaded, and
without changing the history the model is sent.
"""
import asyncio
import copy
import json
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import Static  # noqa: E402

from secator.ai.history import ChatHistory, classify_user_message  # noqa: E402
from secator.ai.prompts import format_continue  # noqa: E402
from secator.ai.session import save_history  # noqa: E402
from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.widgets import ToolCallPanel  # noqa: E402

CONTINUE = "<tool_result_analysis>\nAnalyze the tool results, make a brief summary...\n</tool_result_analysis>"


def _tc(call_id, name, args):
	return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _session():
	"""A two-turn session as the loop builds it: tool calls, results, injected instructions."""
	return [
		{"role": "system", "content": "sys prompt"},
		{"role": "user", "content": "check example.com"},
		{"role": "assistant", "content": "Fetching it.", "tool_calls": [
			_tc("c1", "fetch_url", {"url": "http://example.com"}),
			_tc("c2", "query_workspace", {"query": {"_type": "url"}, "description": "Known URLs"})]},
		{"role": "tool", "tool_call_id": "c1", "name": "fetch_url", "content": "Example Domain page text"},
		{"role": "tool", "tool_call_id": "c2", "name": "query_workspace",
		 "content": json.dumps([{"url": "a"}, {"url": "b"}])},
		{"role": "user", "content": format_continue(1, 101, CONTINUE)},
		{"role": "assistant", "content": "It is the example page."},
		{"role": "user", "content": "[User interjected]: also the plan"},
		{"role": "assistant", "content": "", "tool_calls": [_tc("c3", "update_plan", {"items": [{"text": "step"}]})]},
		{"role": "tool", "tool_call_id": "c3", "name": "update_plan", "content": json.dumps({"error": "bad items"})},
		{"role": "user", "content": format_continue(2, 101, CONTINUE)},
		{"role": "assistant", "content": "Plan updated."},
	]


def test_classify_user_message():
	assert classify_user_message(format_continue(2, 101, CONTINUE)) == ("internal", "")
	assert classify_user_message(format_continue(3, float("inf"), "continue")) == ("internal", "")
	assert classify_user_message("Summary of previous iterations:\n\nwe did x") == ("summary", "we did x")
	assert classify_user_message("[User interjected]: stop that") == ("user", "stop that")
	assert classify_user_message("scan example.com") == ("user", "scan example.com")
	# a user who pastes JSON is still a user turn
	assert classify_user_message('{"instruction": "x"}') == ("user", '{"instruction": "x"}')


def _texts(app):
	out = []
	for w in app._convo().children:
		if isinstance(w, ToolCallPanel):
			out.append(("tool", w.tool_name))
		elif isinstance(w, Static):
			out.append((sorted(w.classes)[0] if w.classes else "", str(w.render())))
	return out


async def _replay_saved_body():
	with tempfile.TemporaryDirectory() as tmp:
		history = ChatHistory()
		history.messages = _session()
		save_history(history, tmp)
		messages = json.loads((Path(tmp) / "history.json").read_text())
	before = copy.deepcopy(messages)

	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 50)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)
		await app._replay_history(messages)
		await pilot.pause(0.1)
		rendered = _texts(app)[base:]

		# no injected instruction is rendered anywhere
		assert not any("iteration" in t or "tool_result_analysis" in t for _, t in rendered)
		# order: bubble, text, 2 tool cards, text, steer bubble (no prefix), tool card, text
		kinds = [k if k == "tool" else k for k, _ in rendered]
		assert kinds == ["user", "ai", "tool", "tool", "ai", "user", "tool", "ai"], rendered
		assert "check example.com" in rendered[0][1]
		assert rendered[5][1].endswith("also the plan") and "interjected" not in rendered[5][1]

		panels = list(app._convo().query(ToolCallPanel))
		assert [p.tool_name for p in panels] == ["fetch_url", "query_workspace", "update_plan"]
		fetch, query, plan = panels
		# finished, collapsed, and expandable to the args + linked result
		assert all(p.done and p._collapsed for p in panels)
		fetch.toggle()
		await pilot.pause(0.05)
		assert not fetch._collapsed
		body = [str(s.render()) for s in fetch.query(".runner-out Static")]
		assert any("http://example.com" in b for b in body)            # args
		assert any("Example Domain page text" in b for b in body)      # result (by tool_call id)
		# a query renders like the live query card: description title, query as command, count
		assert query.kind == "query" and query.rname == "Known URLs" and query.result_count == 2
		assert '"_type": "url"' in query.command
		# an error result marks the card failed
		assert plan.failed and not fetch.failed

	# replay never changes the model-facing history
	assert messages == before


def test_replay_of_saved_session_hides_internal_and_expands_tools():
	asyncio.run(_replay_saved_body())


async def _replay_decrypt_body():
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		msgs = [
			{"role": "user", "content": "look at [HOST:0123456789ab]"},
			{"role": "assistant", "content": "", "tool_calls": [_tc("c1", "fetch_url", {"url": "http://[HOST:0123456789ab]"})]},
			{"role": "tool", "tool_call_id": "c1", "content": "page of [HOST:0123456789ab]"},
		]
		await app._replay_history(msgs, decrypt=lambda t: t.replace("[HOST:0123456789ab]", "real.example.com"))
		await pilot.pause(0.05)
		panel = app._convo().query_one(ToolCallPanel)
		body = " ".join(str(s.render()) for s in panel.query(".runner-out Static"))
		assert "http://real.example.com" in body and "page of real.example.com" in body
		assert any("real.example.com" in t for _, t in _texts(app))


def test_replay_decrypts_for_display():
	asyncio.run(_replay_decrypt_body())

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
from secator.ai.prompts import format_continue, format_tool_result  # noqa: E402
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
	# only the exact format_continue shape is internal (here: no "max")
	pasted = '{"instruction": "explain this", "iteration": 2}'
	assert classify_user_message(pasted) == ("user", pasted)


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
		# args, then the result linked by tool_call id
		assert body == ['args: {"url": "http://example.com"}', "Example Domain page text"]
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
		body = [str(s.render()) for s in panel.query(".runner-out Static")]
		assert body == ['args: {"url": "http://real.example.com"}', "page of real.example.com"]
		assert _texts(app)[-2] == ("user", "› look at real.example.com")


def test_replay_decrypts_for_display():
	asyncio.run(_replay_decrypt_body())


async def _replay_selectable_body():
	from unittest import mock
	from secator.tui.widgets import SelectableStatic

	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		msgs = [
			{"role": "user", "content": "scan the box"},
			{"role": "assistant", "content": "Found **port 80** open.",
			 "tool_calls": [_tc("c1", "fetch_url", {"url": "http://example.com"})]},
			{"role": "tool", "tool_call_id": "c1", "content": "Example Domain page text"},
		]
		await app._replay_history(msgs)
		await pilot.pause(0.05)
		convo = app._convo()
		reply = convo.query_one(SelectableStatic)            # replayed Markdown reply
		bubble = convo.query_one(".user")
		panel = convo.query_one(ToolCallPanel)
		panel.toggle()
		await pilot.pause(0.05)
		result = panel.query_one(".tool-result")

		async def drag(w, end):
			await pilot.mouse_down(w, offset=(0, 0))
			await pilot.hover(w, offset=end)
			await pilot.mouse_up(w, offset=end)
			await pilot.pause(0.05)

		with mock.patch.object(app, "copy_to_clipboard") as copy, mock.patch.object(app, "notify"):
			await drag(reply, (14, 0))
			await drag(bubble, (6, 0))
			await drag(result, (7, 0))
		copied = [c.args[0] for c in copy.call_args_list]
		assert len(copied) == 3, copied
		assert copied[0].startswith("Found port 80")      # Markdown reply (bold markers rendered)
		assert copied[1].startswith("› scan")
		assert copied[2].startswith("Example")             # expanded tool card result


def test_replayed_messages_are_selectable_and_copy_on_select():
	asyncio.run(_replay_selectable_body())


def _enveloped(name, status, results):
	# the saved shape of a runner/query result: format_tool_result JSON fenced as untrusted
	# data (see _yield_tool_results), with guidance appended after the fence
	return f"<workspace_data>\n{format_tool_result(name, status, len(results), results)}\n</workspace_data>\nhint"


async def _replay_envelope_body():
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		msgs = [
			{"role": "assistant", "content": "", "tool_calls": [
				_tc("c1", "run_shell", {"command": "false", "description": "Fails"}),
				_tc("c2", "query_workspace", {"query": {"_type": "port"}, "description": "Ports"})]},
			{"role": "tool", "tool_call_id": "c1", "content": _enveloped("run_shell", "error", [{"message": "boom"}])},
			{"role": "tool", "tool_call_id": "c2",
			 "content": _enveloped("query_workspace", "success", [{"port": 22}, {"port": 80}, {"port": 443}])},
		]
		await app._replay_history(msgs)
		await pilot.pause(0.05)
		shell, query = list(app._convo().query(ToolCallPanel))
		assert shell.failed and not query.failed
		assert query.result_count == 3
		# the fence is stripped for display; the guidance after it is kept
		shell.toggle()
		await pilot.pause(0.05)
		body = str(shell.query_one(".tool-result").render())
		assert "<workspace_data>" not in body and '"status": "error"' in body and body.endswith("hint")
		# finished cards never keep a spinner timer running
		assert shell._spin_timer is None and query._spin_timer is None


def test_replay_reads_status_from_saved_result_envelope():
	asyncio.run(_replay_envelope_body())

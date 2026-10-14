"""TUI item-routing tests.

Guards the rules that decide WHICH panel each streamed item lands in — especially the
parallel-batch case, where a task's output/findings/errors arrive (via the display
hooks) BEFORE its card renders, so they must be buffered by _source and flushed into
the right panel instead of leaking to the top level or cross-wiring to a stale panel.
"""
import asyncio

import pytest

pytest.importorskip("textual")

from secator.tui.ai import AITUI          # noqa: E402
from secator.tui.widgets import RunnerPanel  # noqa: E402


def _run(coro):
	asyncio.run(coro)


def _finding(_type, source, uuid, **fields):
	return {"_type": _type, "_source": source, "_uuid": uuid, "_context": {}, **fields}


def _card(at, name, desc=""):
	return {"_type": "ai", "ai_type": at, "content": name, "extra_data": {"description": desc}}


def _panels(app, kind=None):
	return [p for p in app.query(RunnerPanel) if kind is None or p.kind == kind]


def _by_desc(app, desc):
	return next(p for p in app.query(RunnerPanel) if p.rname == desc)


async def _batch_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)

		# --- BATCH: two tasks stream their items (display hooks) BEFORE any card ---
		await app._set_command("httpx -u http://x", "httpx")
		await app._render_line("probing http://x", "httpx")
		await app._render(_finding("url", "httpx", "u-httpx-1", url="http://x", status_code=200))
		await app._render({"_type": "info", "message": "httpx: 1 url", "_source": "httpx"})

		await app._set_command("nmap x -p-", "nmap")            # interleaved
		await app._render_line("22/tcp open", "nmap")
		await app._render(_finding("port", "nmap", "u-nmap-1", port=22, host="x", ip="1.2.3.4", state="open"))
		await app._render({"_type": "error", "message": "nmap: a warning", "_source": "nmap"})
		await pilot.pause(0.05)

		# nothing leaked to the top level yet — it's all buffered
		assert len(app._convo().children) == base, "batch items leaked to the top level before cards"

		# --- cards render on completion (as in _run_batch), in order ---
		await app._render(_card("task", "httpx", "HTTP probe"))
		app._finish_current()
		await app._render(_card("task", "nmap", "Port scan"))
		app._finish_current()
		await pilot.pause(0.05)

		httpx = _by_desc(app, "HTTP probe")
		nmap = _by_desc(app, "Port scan")

		# each task got ITS OWN command / finding / output+note — no cross-wiring
		assert httpx.command == "httpx -u http://x"
		assert httpx.count == 1                      # the url finding
		assert httpx.lines == 2                      # "probing …" output + "1 url" note
		assert nmap.command == "nmap x -p-"
		assert nmap.count == 1                       # the port finding
		assert nmap.lines == 2                       # "22/tcp open" output + the error note

		# only the two task panels were added at top level (nothing leaked)
		assert len(app._convo().children) == base + 2


def test_batch_items_route_to_their_own_panel():
	_run(_batch_body())


async def _sequential_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)
		# sequential: the card renders FIRST, then items stream live into it
		await app._render(_card("task", "nmap", "Port scan"))
		await app._set_command("nmap x -p22", "nmap")
		await app._render_line("22/tcp open", "nmap")
		await app._render(_finding("port", "nmap", "u1", port=22, host="x", ip="1.2.3.4", state="open"))
		app._finish_current()
		await pilot.pause(0.05)
		p = _by_desc(app, "Port scan")
		assert p.command == "nmap x -p22"
		assert p.count == 1
		assert p.lines == 1
		assert len(app._convo().children) == base + 1   # just the task panel


def test_sequential_items_route_live_to_current_panel():
	_run(_sequential_body())


async def _shell_body():
	app = AITUI(None, session="ai", mode="auto")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)
		await app._render(_card("shell", "cat /etc/hosts"))           # content is the command
		await app._render({"_type": "ai", "ai_type": "shell_output", "content": "127.0.0.1 localhost"})
		# a shell command failure (Error) must fold INTO the shell panel, not top level
		await app._render({"_type": "error", "message": "Command failed with return code 7", "_source": "command"})
		app._finish_current()
		await pilot.pause(0.05)
		shell = _panels(app, "shell")[0]
		assert shell.lines == 2                       # visible output + the error note
		assert len(app._convo().children) == base + 1  # only the shell panel (error didn't leak)


def test_shell_output_visible_and_error_nested():
	_run(_shell_body())


async def _workflow_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# workflow card is the container; its children stream by _source
		await app._render(_card("workflow", "host_recon", "Full recon"))
		# workflow-level note (source == workflow) stays on the container
		await app._render({"_type": "info", "message": "Skipped task naabu", "_source": "host_recon"})
		# child-task findings + a child note nest in per-source sub-panels
		await app._render(_finding("port", "nmap", "w1", port=22, host="x", ip="1.2.3.4", state="open"))
		await app._render(_finding("url", "httpx", "w2", url="http://x", status_code=200))
		await app._render({"_type": "info", "message": "XML saved", "_source": "nmap"})
		app._finish_current()
		await pilot.pause(0.05)
		wf = _panels(app, "workflow")[0]
		assert set(wf.subpanels.keys()) == {"nmap", "httpx"}
		assert wf.subpanels["nmap"].count == 1
		assert wf.subpanels["httpx"].count == 1
		assert wf.subpanels["nmap"].lines == 1       # the "XML saved" child note
		assert wf.lines == 1                          # the workflow-level skip note


def test_workflow_children_nest_by_source():
	_run(_workflow_body())


def _static_texts(app):
	from textual.widgets import Static
	out = []
	for w in app.query(Static):
		try:
			r = w.render()
		except Exception:
			continue
		out.append(r.plain if hasattr(r, "plain") else str(r))
	return out


async def _tool_result_and_mode_body():
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)
		# a REJECTED tool call (extra_data.error) must surface as a visible failure line
		await app._render({"_type": "ai", "ai_type": "tool_result",
		                   "content": "[add_finding] rejected: empty arguments",
		                   "extra_data": {"error": True, "tool_name": "add_finding",
		                                  "reason": "rejected: empty arguments"}})
		# a SUCCESSFUL tool_result is model-facing only — it must render NOTHING
		await app._render({"_type": "ai", "ai_type": "tool_result",
		                   "content": "[run_task] 5 result(s)", "extra_data": {}})
		# a mode switch must show a "Switched to <mode> mode" notice
		await app._render({"_type": "ai", "ai_type": "mode_changed", "content": "scan"})
		await pilot.pause(0.05)

		# exactly two lines added (the rejection + the mode notice; success skipped)
		assert len(app._convo().children) == base + 2
		texts = _static_texts(app)
		assert any("tool call failed" in t and "add_finding" in t for t in texts), texts
		assert any("Switched to" in t and "scan" in t for t in texts), texts
		# the successful tool_result's content never rendered
		assert not any("5 result(s)" in t for t in texts), texts


def test_tool_result_errors_and_mode_change_render():
	_run(_tool_result_and_mode_body())

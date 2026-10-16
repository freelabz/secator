"""TUI item-routing tests.

Guards the rules that decide WHICH panel each streamed item lands in — especially the
parallel-batch case, where a task's output/findings/errors arrive (via the display
hooks) BEFORE its card renders, so they must be buffered by _source and flushed into
the right panel instead of leaking to the top level or cross-wiring to a stale panel.
"""
import asyncio
import threading

import pytest

pytest.importorskip("textual")

from textual.widgets import Input            # noqa: E402
from secator.tui.ai import AITUI          # noqa: E402
from secator.tui.widgets import ActionPanel, ChoicePrompt, RunnerPanel  # noqa: E402
from textual.widgets import OptionList  # noqa: E402


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


def _wfcard(name, desc, rid):
	return {"_type": "ai", "ai_type": "workflow", "content": name,
	        "extra_data": {"description": desc, "runner_id": rid}}


def _wfnote(message, source, wfid):
	return {"_type": "info", "message": message, "_source": source,
	        "_context": {"workflow_id": wfid}}


def _wffinding(_type, source, uuid, wfid, **fields):
	return {"_type": _type, "_source": source, "_uuid": uuid,
	        "_context": {"workflow_id": wfid}, **fields}


async def _parallel_workflows_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# Two workflows run in parallel (one per target): their item streams INTERLEAVE.
		# Both share the same config name AND a same-named child task ("nmap") — the only
		# thing distinguishing them is the owning workflow id in each item's _context.
		await app._render(_wfcard("host_recon", "Recon target A", "wf-A"))
		# A streams a child finding + its own workflow-level skip note
		await app._render(_wffinding("port", "nmap", "a1", "wf-A", port=22, host="a", ip="1.1.1.1", state="open"))
		await app._render(_wfnote("Skipped task naabu", "host_recon", "wf-A"))
		# NOW B's card arrives (the old single-_container global would repoint here) ...
		await app._render(_wfcard("host_recon", "Recon target B", "wf-B"))
		# ... but A is still streaming: these MUST stay on A, not leak into B
		await app._render(_wfnote("XML saved", "nmap", "wf-A"))
		await app._render(_wffinding("url", "httpx", "a2", "wf-A", url="http://a", status_code=200))
		# B's own children
		await app._render(_wffinding("port", "nmap", "b1", "wf-B", port=80, host="b", ip="2.2.2.2", state="open"))
		await app._render(_wfnote("Skipped task naabu", "host_recon", "wf-B"))
		app._finish_current()
		await pilot.pause(0.05)

		wa = _by_desc(app, "Recon target A")
		wb = _by_desc(app, "Recon target B")
		# A kept BOTH its tasks (incl. the ones that streamed after B's card) and its note
		assert set(wa.subpanels.keys()) == {"nmap", "httpx"}
		assert wa.subpanels["nmap"].count == 1        # a1 port finding
		assert wa.subpanels["nmap"].lines == 1        # "XML saved" child note (did NOT leak to B)
		assert wa.subpanels["httpx"].count == 1       # a2 url finding (streamed after B's card)
		assert wa.lines == 1                          # A's workflow-level skip note
		# B got ONLY its own child + note — nothing from A crossed over
		assert set(wb.subpanels.keys()) == {"nmap"}
		assert wb.subpanels["nmap"].count == 1        # b1 only
		assert wb.subpanels["nmap"].lines == 0        # A's "XML saved" note did not land here
		assert wb.lines == 1                          # B's own skip note


def test_parallel_workflows_do_not_crosswire():
	_run(_parallel_workflows_body())


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


async def _startup_prefill_body():
	# no -p prompt -> the runner will ask for the first prompt once it finishes building
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		assert app._awaiting_first_prompt is True
		inp = app.query_one("#input-box Input", Input)
		# user types a prompt BEFORE the runner asked for one (the startup race)
		await app.on_input_submitted(Input.Submitted(inp, "run nmap on scanme.nmap.org"))
		# held as the initial prompt, NOT leaked into steers (which would lose it)
		assert app._prefill == "run nmap on scanme.nmap.org"
		assert app.tui_poll_steers() == []
		# the runner now asks for the first prompt — the prefill answers it immediately
		ev, holder = threading.Event(), {}
		app._show_prompt("What do you want to do?", (ev, holder, [], "stopped"))
		assert holder["value"] == "run nmap on scanme.nmap.org"
		assert ev.is_set()
		assert app._prefill == ""
		assert app._awaiting_first_prompt is False


def test_startup_prefill_feeds_first_prompt():
	_run(_startup_prefill_body())


async def _steer_after_first_prompt_body():
	# with -p, the prompt is provided -> early input is a steer, never held as prefill
	app = AITUI(None, session="ai", mode="scan", initial_prompt="run host_recon on x")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		assert app._awaiting_first_prompt is False
		inp = app.query_one("#input-box Input", Input)
		await app.on_input_submitted(Input.Submitted(inp, "focus on port 443"))
		assert app._prefill == ""
		assert app.tui_poll_steers() == ["focus on port 443"]


def test_input_with_initial_prompt_is_steer():
	_run(_steer_after_first_prompt_body())


async def _add_finding_expandable_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(app._convo().children)
		fd = {"_type": "vulnerability", "name": "XSS", "matched_at": "http://x",
		      "severity": "high", "_uuid": ""}
		# add_finding emits the action row AND (right after) yields the finding itself
		await app._render({"_type": "ai", "ai_type": "add_finding", "content": "XSS",
		                   "extra_data": {"finding": fd}})
		await app._render(_finding("vulnerability", "", "", name="XSS",
		                           matched_at="http://x", severity="high"))
		await pilot.pause(0.05)
		# only the expandable action row was added — the standalone finding card was suppressed
		assert len(app._convo().children) == base + 1, "add_finding rendered a duplicate card"
		panels = [p for p in app.query(ActionPanel)]
		assert len(panels) == 1
		assert panels[0].verb == "Added"
		assert panels[0].finding is not None, "the Added row must expand to the rich finding"

		# the SAME finding re-read later (e.g. via query_workspace) now has a persisted _uuid:
		# it was already shown as the row, so it must NOT render a card either
		await app._render(_finding("vulnerability", "ws", "persisted-uuid-9", name="XSS",
		                           matched_at="http://x", severity="high"))
		await pilot.pause(0.05)
		assert len(app._convo().children) == base + 1, "re-read of an add_finding finding duplicated"
		assert "persisted-uuid-9" in app._shown_uuids, "re-read uuid must migrate to _uuid dedup"


def test_add_finding_row_is_expandable_and_not_duplicated():
	_run(_add_finding_expandable_body())


async def _subview_hides_input_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		assert app.query_one("#input-box").display is True
		await app._ensure_subview("sub-1")
		# drilling into a subagent's (read-only) view hides the input box
		app._open_subview("sub-1")
		assert app.query_one("#input-box").display is False
		# going back to the conversation restores it
		app._show_main()
		assert app.query_one("#input-box").display is True


def test_subview_hides_input_box():
	_run(_subview_hides_input_body())


def _subspawn(sid, label):
	return {"_type": "ai", "ai_type": "task", "content": "ai", "_uuid": "c-" + sid,
	        "_context": {"session_id": "parent"},
	        "extra_data": {"subagent": label, "subagent_session_id": sid, "runner_id": sid}}


def _subitem(sid, uid, text):
	return {"_type": "ai", "ai_type": "response", "content": text, "_uuid": uid,
	        "_context": {"subagent": True, "session_id": sid}}


def _handback(sid):
	return {"_type": "ai", "ai_type": "response", "content": "handback " + sid, "_uuid": "hb-" + sid,
	        "_context": {"session_id": "parent", "tool_call_id": "tc-" + sid},
	        "extra_data": {"subagent_session_id": sid}}


async def _ai_item_dedup_body():
	from textual.widgets import Markdown
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		base = len(list(app.query(Markdown)))
		# multi-level display hooks can feed the SAME ai item twice (subagent + parent levels).
		# A truthy _uuid must dedup it, exactly as findings are deduped.
		item = _subitem("A", "u-step-1", "a subagent step")
		await app._render(item)
		await app._render(item)
		await pilot.pause(0.05)
		assert len(list(app.query(Markdown))) - base == 1, "ai item with same _uuid must render once"


def test_ai_items_deduped_by_uuid():
	_run(_ai_item_dedup_body())


async def _parallel_subagent_rows_body():
	from secator.tui.widgets import SubagentRow
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# two parallel subagents spawn, stream interleaved, then each hands back
		await app._render(_subspawn("A", "probe root"))
		await app._render(_subspawn("B", "probe app"))
		await app._render(_subitem("A", "a1", "step"))
		await app._render(_subitem("B", "b1", "step"))
		await app._render(_handback("A"))
		await app._render(_handback("B"))
		await pilot.pause(0.05)
		rows = {r.sid: r for r in app.query(SubagentRow)}
		# BOTH rows marked "Ran" — not just the last-spawned one
		assert rows["A"].done is True, "first parallel subagent row stuck on 'Running'"
		assert rows["B"].done is True


def test_parallel_subagent_rows_each_marked_done():
	_run(_parallel_subagent_rows_body())


def _idcard(rid, desc):
	return {"_type": "ai", "ai_type": "task", "content": "httpx", "_uuid": "c-" + rid,
	        "_context": {}, "extra_data": {"description": desc, "runner_id": rid}}


def _idfinding(rid, uid, url):
	return {"_type": "url", "_source": "httpx", "_uuid": uid, "_context": {"task_chunk_id": rid},
	        "url": url, "status_code": 200}


async def _same_source_batch_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# two tasks in a parallel batch share the SAME _source ('httpx') and differ only by
		# their owning runner id (task_chunk_id) — route by id, not source
		await app._set_command("httpx -u a.com", "httpx", "A")   # streams before cards
		await app._render(_idfinding("A", "a1", "http://a.com"))
		await app._set_command("httpx -u b.com", "httpx", "B")
		await app._render(_idfinding("B", "b1", "http://b.com"))
		await app._render(_idcard("A", "probe A"))
		app._finish_current()
		await app._render(_idcard("B", "probe B"))
		app._finish_current()
		# a late finding streams LIVE after both cards — must still land on A, not the last card
		await app._render(_idfinding("A", "a2", "http://a.com/late"))
		await pilot.pause(0.05)
		panels = {p.rname: p for p in _panels(app)}
		assert panels["probe A"].command == "httpx -u a.com"
		assert panels["probe A"].count == 2, "task A lost its findings to the same-source sibling"
		assert panels["probe B"].command == "httpx -u b.com"
		assert panels["probe B"].count == 1


def test_same_source_batch_routes_by_runner_id():
	_run(_same_source_batch_body())


async def _unmatched_id_buffers_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# A's card is up; B's output arrives BEFORE B's card renders. It must buffer by B's
		# id and land on B — NOT fall through to source routing and get captured by A's
		# same-tool card.
		await app._render(_idcard("A", "probe A"))
		app._finish_current()
		await app._set_command("httpx -u b.com", "httpx", "B")
		await app._render(_idfinding("B", "b1", "http://b.com"))
		await app._render(_idcard("B", "probe B"))
		app._finish_current()
		await pilot.pause(0.05)
		panels = {p.rname: p for p in _panels(app)}
		assert panels["probe A"].command == "", "A captured B's command (fell through to source)"
		assert panels["probe A"].count == 0, "A captured B's finding (fell through to source)"
		assert panels["probe B"].command == "httpx -u b.com"
		assert panels["probe B"].count == 1


def test_unmatched_runner_id_buffers_not_cross_wired():
	_run(_unmatched_id_buffers_body())


async def _handback_panel_body():
	from secator.tui.widgets import HandbackPanel
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		await app._render(_subspawn("A", "probe root"))
		hb = {"_type": "ai", "ai_type": "response", "content": "Verdict: no vulns found.",
		      "_uuid": "hb-A", "_context": {"session_id": "parent", "tool_call_id": "tc"},
		      "extra_data": {"subagent_session_id": "A", "usage": {"tokens": 12345, "cost": 0.0123}}}
		await app._render(hb)
		await pilot.pause(0.05)
		# the verdict renders as a HandbackPanel in the SUBAGENT view, not the main convo
		sv = app._subviews.get("A")
		assert sv is not None and len(list(sv.query(HandbackPanel))) == 1
		assert len(list(app._convo().query(HandbackPanel))) == 0
		# and the usage line is present
		from textual.widgets import Static
		texts = [w.render().plain for w in app.query(Static) if hasattr(w.render(), "plain")]
		assert any("subagent usage" in t and "12,345 tokens" in t for t in texts), texts


def test_handback_renders_in_subview_with_usage():
	_run(_handback_panel_body())


async def _choice_prompt_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		resolved = {}
		cp = ChoicePrompt("", ["scanme.nmap.org", "example.com"], False, lambda v: resolved.setdefault("v", v))
		await app._convo().mount(cp)
		app._active_choice = cp
		await pilot.pause(0.1)
		ol = cp.query_one(OptionList)
		inp = app.query_one("#input-box Input", Input)
		# choices + a trailing "Something else" row
		assert ol.option_count == 3
		# highlighting an option live-copies it into the input box; Something else clears it
		ol.highlighted = 0
		await pilot.pause(0.05)
		assert inp.value == "scanme.nmap.org"
		ol.highlighted = 2
		await pilot.pause(0.05)
		assert inp.value == ""
		# selecting a real option resolves with its text and collapses the prompt
		ol.highlighted = 0
		await pilot.pause(0.05)
		cp.on_option_list_option_selected(OptionList.OptionSelected(ol, ol._options[0], 0))
		assert resolved.get("v") == "scanme.nmap.org"
		assert cp._value == "scanme.nmap.org"


def test_choice_prompt_prefills_input_and_resolves():
	_run(_choice_prompt_body())


async def _choice_input_submit_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		import threading as _t
		ev, holder = _t.Event(), {}
		# simulate an active choice ask (as _show_prompt would set up)
		app._pending_ask = (ev, holder, ["scanme.nmap.org"], "stopped")
		cp = ChoicePrompt("", ["scanme.nmap.org"], False, app._resolve_pending)
		await app._convo().mount(cp)
		app._active_choice = cp
		await pilot.pause(0.05)
		# user edits the prefilled text in the input box and presses Enter
		inp = app.query_one("#input-box Input", Input)
		await app.on_input_submitted(Input.Submitted(inp, "scanme.nmap.org --top-ports 100"))
		await pilot.pause(0.05)
		assert holder.get("value") == "scanme.nmap.org --top-ports 100"
		assert cp._value == "scanme.nmap.org --top-ports 100"   # collapsed to the submitted answer


def test_choice_prompt_input_submit_collapses_and_resolves():
	_run(_choice_input_submit_body())


async def _choice_numeric_and_clear_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# numeric choices: submitting "2" via the input must resolve "2", NOT index-2 -> "1"
		ev, holder = threading.Event(), {}
		app._pending_ask = (ev, holder, ["2", "1"], "stopped")
		cp = ChoicePrompt("", ["2", "1"], False, app._resolve_pending)
		await app._convo().mount(cp)
		app._active_choice = cp
		await pilot.pause(0.1)
		inp = app.query_one("#input-box Input", Input)
		await app.on_input_submitted(Input.Submitted(inp, "2"))
		assert holder.get("value") == "2", "numeric choice text was reinterpreted as an index"
		# selecting an option clears the shared input box (so the next ask starts empty)
		holder2 = {}
		app._pending_ask = (threading.Event(), holder2, ["scan", "crawl"], "stopped")
		cp2 = ChoicePrompt("", ["scan", "crawl"], False, app._resolve_pending)
		await app._convo().mount(cp2)
		app._active_choice = cp2
		await pilot.pause(0.1)
		ol = cp2.query_one(OptionList)
		ol.highlighted = 0
		await pilot.pause(0.05)
		cp2.on_option_list_option_selected(OptionList.OptionSelected(ol, ol._options[0], 0))
		assert holder2.get("value") == "scan"
		assert inp.value == "", "input box not cleared after a list selection"


def test_choice_prompt_numeric_literal_and_input_cleared():
	_run(_choice_numeric_and_clear_body())
async def _parent_error_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		app._parent_source = "ai"   # set by the item feed from the parent runner's unique_name
		base = len(app._convo().children)
		# the parent ai task's OWN error (e.g. a model NotFoundError) carries _source == "ai";
		# it must render in the conversation, not buffer forever under a card that never renders
		await app._render({"_type": "error", "_source": "ai", "_uuid": "e1", "_context": {},
		                   "message": "litellm.NotFoundError: model not found"})
		await pilot.pause(0.05)
		assert len(app._convo().children) - base == 1, "parent task error was not shown"
		from textual.widgets import Static
		texts = [w.render().plain for w in app._convo().query(Static) if hasattr(w.render(), "plain")]
		assert any("NotFoundError" in t for t in texts), texts


def test_parent_task_error_renders_in_conversation():
	_run(_parent_error_body())


async def _query_card_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		ed = {"description": "Find high/critical vulns", "results": 7, "limit": 100, "offset": 20, "group": True}
		q = {"_type": "ai", "ai_type": "query", "content": '{"_type":"vulnerability"}', "_uuid": "q1",
		     "_context": {}, "extra_data": ed}
		await app._render(q)
		# a result finding routes INTO the query panel
		await app._render(_finding("vulnerability", "nuclei", "v1", name="XSS", severity="high",
		                           matched_at="http://x"))
		await pilot.pause(0.05)
		p = [x for x in _panels(app) if x.kind == "query"][0]
		# running: animated orange spinner glyph + description + result count inline
		assert any(c in p._header().plain for c in RunnerPanel._SPIN)   # spinner while running
		assert "Find high/critical vulns" in p._header().plain
		assert "(7 results)" in p._header().plain                       # count inline, not "(query)"
		assert "(query)" not in p._header().plain
		p.done = True
		assert "✓" in p._header().plain                                  # green check on success
		p.failed = True
		assert "✗" in p._header().plain                                  # red cross when failed
		# the meta line keeps only the skip/limit/group details (count moved to the header)
		assert "7 results" not in p.meta
		assert "skip=20" in p.meta and "limit=100" in p.meta and "grouped" in p.meta
		assert p.count == 1   # the result finding rendered inside the query panel


def test_query_card_shows_description_and_meta():
	_run(_query_card_body())


async def _runner_status_icon_body():
	app = AITUI(None, session="ai", mode="scan")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		# a task card renders running (animated spinner)
		await app._render(_card("task", "nmap", "Port scan"))
		p = _panels(app, "task")[0]
		assert any(c in p._header().plain for c in RunnerPanel._SPIN)
		assert p.done is False and p.failed is False
		# an error routed to it marks it failed -> red cross once finished
		await app._render({"_type": "error", "message": "validator failed", "_source": "nmap"})
		assert p.failed is True
		app._finish_current()
		await pilot.pause(0.05)
		assert "✗" in p._header().plain
		# a clean task finishes with a green check
		await app._render(_card("task", "httpx", "Probe"))
		p2 = _by_desc(app, "Probe")
		app._finish_current()
		await pilot.pause(0.05)
		assert "✓" in p2._header().plain and not p2.failed


def test_runner_status_icons_spinner_check_cross():
	_run(_runner_status_icon_body())

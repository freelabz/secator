"""TUI clipboard tests: copy-on-select and the selection-aware Ctrl+C.

The TUI captures the mouse, so selection happens in-app. These guard that:
- a mouse selection copies itself on release (incl. over Markdown AI replies);
- Ctrl+C with an active selection copies and never quits the app (which would cancel
the running task); without a selection it keeps quitting;
- Ctrl+Shift+C only ever copies.
The terminal clipboard write (OSC 52) is mocked via ``App.copy_to_clipboard``.
"""
import asyncio
from unittest import mock

import pytest

pytest.importorskip("textual")

from rich.text import Text  # noqa: E402
from textual.widgets import Static  # noqa: E402

from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.render import flatten_renderable, markdown_text  # noqa: E402
from secator.tui.widgets import PromptInput, SelectableStatic  # noqa: E402


def _run(coro):
	asyncio.run(coro)


async def _drag(pilot, widget, start, end):
	await pilot.mouse_down(widget, offset=start)
	await pilot.hover(widget, offset=end)
	await pilot.mouse_up(widget, offset=end)
	await pilot.pause(0.05)


def test_flatten_renderable_keeps_text_and_wraps_to_width():
	text, n = flatten_renderable(markdown_text("Hello **world** " + "word " * 30), 40)
	assert isinstance(text, Text)
	assert "Hello world" in text.plain
	assert n == len(text.plain.split("\n")) and n > 1
	assert all(len(line) <= 40 for line in text.plain.split("\n"))


def test_select_markdown_reply_copies_on_release():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			md = SelectableStatic(markdown_text("Hello **world** from the reply"), classes="ai")
			await app._append(md)
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy, mock.patch.object(app, "notify") as notify:
				await _drag(pilot, md, (0, 0), (11, 0))
				copy.assert_called_once_with("Hello world")
				assert "Copied" in notify.call_args.args[0]
	_run(body())


def test_plain_click_does_not_copy():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			w = Static(Text("some line"), classes="ai")
			await app._append(w)
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy:
				await pilot.click(w, offset=(2, 0))
				await pilot.pause(0.05)
				copy.assert_not_called()
	_run(body())


def test_ctrl_c_with_selection_copies_and_does_not_quit():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			w = Static(Text("plain text line here"), classes="ai")
			await app._append(w)
			await pilot.pause(0.05)
			await _drag(pilot, w, (0, 0), (10, 0))
			with mock.patch.object(app, "copy_to_clipboard") as copy, mock.patch.object(app, "action_quit") as quit_:
				await pilot.press("ctrl+c")
				await pilot.pause(0.05)
				copy.assert_called_once_with("plain text")
				quit_.assert_not_called()
			assert app.is_running
	_run(body())


def test_ctrl_c_with_input_selection_copies_and_does_not_quit():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			inp = app.query_one("#prompt-input", PromptInput)
			inp.focus()
			inp.text = "typed prompt"
			inp.select_all()
			with mock.patch.object(app, "copy_to_clipboard") as copy, mock.patch.object(app, "action_quit") as quit_:
				await pilot.press("ctrl+c")
				await pilot.pause(0.05)
				copy.assert_called_once_with("typed prompt")
				quit_.assert_not_called()
	_run(body())


def test_ctrl_c_without_selection_quits():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy:
				await pilot.press("ctrl+c")
				await pilot.pause(0.05)
				copy.assert_not_called()
			assert not app.is_running
	_run(body())


def test_ctrl_shift_c_copies_only():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy:
				await pilot.press("ctrl+shift+c")   # nothing selected: no copy, no quit
				await pilot.pause(0.05)
				copy.assert_not_called()
			assert app.is_running
			w = Static(Text("abc def"), classes="ai")
			await app._append(w)
			await pilot.pause(0.05)
			await _drag(pilot, w, (0, 0), (3, 0))
			with mock.patch.object(app, "copy_to_clipboard") as copy:
				await pilot.press("ctrl+shift+c")
				await pilot.pause(0.05)
				copy.assert_called_once_with("abc")
			assert app.is_running
	_run(body())


def test_copied_text_drops_line_padding():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(60, 30)) as pilot:
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy, mock.patch.object(app, "notify"):
				app._copy("line one    \nline two  ")
				copy.assert_called_once_with("line one\nline two")
	_run(body())


def test_click_to_expand_still_works_and_does_not_copy():
	# selection is in-app (no Shift needed): a plain click on a runner header must still
	# toggle it, and must not be taken as a selection.
	from secator.tui.widgets import RunnerPanel

	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			panel = RunnerPanel("task", "Port scan", command="nmap x")
			await app._append(panel)
			await pilot.pause(0.05)
			with mock.patch.object(app, "copy_to_clipboard") as copy:
				await pilot.click(panel.query_one(".runner-head"))
				await pilot.pause(0.05)
				assert not panel._collapsed
				copy.assert_not_called()
	_run(body())


def test_mouse_wheel_still_scrolls_the_conversation():
	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(80, 20)) as pilot:
			await pilot.pause(0.05)
			for i in range(60):
				await app._append(Static(Text(f"line {i}"), classes="ai"))
			await pilot.pause(0.05)
			convo = app._convo()
			convo.scroll_end(animate=False)
			await pilot.pause(0.05)
			end = convo.scroll_y
			assert end > 0
			# mouse capture stays on (that's what makes in-app selection work): the wheel
			# still reaches the conversation. Private pilot helper: no public wheel API.
			from textual import events
			await pilot._post_mouse_events([events.MouseScrollUp], convo, offset=(5, 5), times=3)
			await pilot.pause(0.1)
			assert convo.scroll_y < end
	_run(body())


def test_copy_reaches_terminal_and_native_and_hints_once():
	# the copy writes OSC 52 to the terminal (tmux-wrapped too), keeps the in-app
	# clipboard for in-app paste, tries a native clipboard, and when none is reachable
	# shows a one-time hint (not one per copy)
	from secator.tui import app as app_mod
	from secator.tui import clipboard

	async def body():
		app = AITUI(None, session="ai", mode="chat")
		async with app.run_test(size=(100, 30)) as pilot:
			await pilot.pause(0.05)
			app_mod.TUIApp._clipboard_hint_shown = False
			env = mock.patch.dict("os.environ", {"TMUX": "/tmp/tmux,1,0"})
			native_ = mock.patch.object(clipboard, "copy_native", return_value=False)
			no_hint = mock.patch.object(clipboard, "missing_tool_hint", return_value=None)
			with env, no_hint, mock.patch.object(app._driver, "write") as write, native_ as native, \
				mock.patch.object(app, "notify") as notify:
				app.copy_to_clipboard("abc")
				app.copy_to_clipboard("def")
				for _ in range(20):
					await pilot.pause(0.05)
					if native.call_count == 2 and notify.called:
						break
			assert app.clipboard == "def"
			written = [c.args[0] for c in write.call_args_list]
			assert any(s.startswith("\x1b]52;c;") for s in written)
			assert any(s.startswith("\x1bPtmux;") for s in written)
			assert [c.args[0] for c in native.call_args_list] == ["abc", "def"]
			assert notify.call_count == 1 and "OSC 52" in notify.call_args.args[0]
		app_mod.TUIApp._clipboard_hint_shown = False
	_run(body())

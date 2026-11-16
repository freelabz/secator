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

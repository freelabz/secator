"""`ai --resume` loading state in the TUI.

While a resume lists the saved sessions, nothing can be typed yet: the input must be hidden
and unfocusable, and the status must say sessions are loading (not the generic startup
spinner, which reads like the model answering). The input comes back once a session is
picked, or when the run ends without asking anything (e.g. no session to resume).
"""
import asyncio
import threading

import pytest

pytest.importorskip("textual")

from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.widgets import PromptInput  # noqa: E402


def _run(coro):
	asyncio.run(coro)


def _blocking_builder(release):
	def build():
		release.wait(5)
		if False:  # keep build() a generator, like the real runner builder
			yield
	return build


def _input(app):
	return app.query_one("#prompt-input", PromptInput)


async def _resume_pick_body():
	release = threading.Event()
	app = AITUI(_blocking_builder(release), session="ai", mode="chat", resume=True)
	try:
		async with app.run_test(size=(120, 40)) as pilot:
			await pilot.pause(0.05)
			# loading: a sessions-specific status, the input hidden and not focusable
			assert app._status_text == "Loading sessions…"
			assert not app.query_one("#input-box").display
			assert _input(app).disabled
			assert app.focused is not _input(app)
			_input(app).focus()
			await pilot.pause(0.05)
			assert app.focused is not _input(app)

			# the session picker (solo choice) takes the input slot; Tab can't reveal the input
			ev, holder = threading.Event(), {}
			app._show_prompt("Resume which session?", (ev, holder, ["> a", "> b"], "stopped"), solo=True)
			await pilot.pause(0.05)
			app._choice_to_input("> a")
			await pilot.pause(0.05)
			assert not app.query_one("#input-box").display

			# picking a session gives the input back, shown and focused
			app._resolve_choice("> b")
			await pilot.pause(0.05)
			assert holder["value"] == "> b"
			assert app.query_one("#input-box").display
			assert not _input(app).disabled
			assert app.focused is _input(app)
			release.set()   # let the run end while the app is still up
			await pilot.pause(0.1)
	finally:
		release.set()


def test_resume_hides_input_while_loading_sessions_until_picked():
	_run(_resume_pick_body())


async def _resume_no_sessions_body():
	release = threading.Event()
	app = AITUI(_blocking_builder(release), session="ai", mode="chat", resume=True)
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		assert not app.query_one("#input-box").display
		release.set()   # the run ends without asking (no session to resume)
		await pilot.pause(0.2)
		assert app.query_one("#input-box").display
		assert not _input(app).disabled


def test_resume_input_comes_back_when_run_ends_without_asking():
	_run(_resume_no_sessions_body())


async def _fresh_run_body():
	release = threading.Event()
	app = AITUI(_blocking_builder(release), session="ai", mode="chat")
	try:
		async with app.run_test(size=(120, 40)) as pilot:
			await pilot.pause(0.05)
			# a fresh run keeps the generic startup status and an input ready to type into
			assert app._status_text == "starting…"
			assert app.query_one("#input-box").display
			assert not _input(app).disabled
			assert app.focused is _input(app)
			release.set()
			await pilot.pause(0.1)
	finally:
		release.set()


def test_fresh_run_keeps_input_and_startup_status():
	_run(_fresh_run_body())

"""The conversation view follows the bottom unless the user scrolled away.

Sending a message always jumps to the bottom (so the message is visible) and follows the
reply that streams in after it. Output that arrives while the user has scrolled up to read
earlier messages does not yank the view back down. Expanding a panel keeps its header in
place instead of pushing it up, and a resumed conversation opens at the bottom.
"""
import asyncio
import threading

import pytest

pytest.importorskip("textual")

from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.widgets import PromptInput, RunnerPanel  # noqa: E402


def _at_bottom(view):
	return view.max_scroll_y > 0 and round(view.scroll_y) >= view.max_scroll_y


async def _settle(pilot):
	# layout, then the follow-up scroll that runs after it
	for _ in range(3):
		await pilot.pause()


async def _reply(app, text):
	await app._render({"_type": "ai", "ai_type": "response", "content": text})


async def _fill(app, pilot, n=40):
	for i in range(n):
		await _reply(app, f"answer {i}\n\nmore text")
	await _settle(pilot)


async def _send(app, pilot, text):
	inp = app.query_one("#prompt-input", PromptInput)
	inp.focus()
	inp.text = text
	await pilot.press("enter")
	await _settle(pilot)


async def _send_after_scroll_up_body():
	app = AITUI(None)
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await _fill(app, pilot)
		convo.scroll_home(animate=False)
		await _settle(pilot)
		assert convo.scroll_y == 0
		await _send(app, pilot, "scan example.com")
		assert _at_bottom(convo)
		assert "scan example.com" in str(convo.children[-1].render())
		# the reply that follows the message is followed too, chunk by chunk
		for i in range(5):
			await _reply(app, f"reply chunk {i}\n\n" + "words " * 60)
			await _settle(pilot)
			assert _at_bottom(convo)


def test_send_scrolls_to_bottom_and_follows_reply():
	asyncio.run(_send_after_scroll_up_body())


async def _scrolled_up_not_yanked_body():
	app = AITUI(None)
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await _fill(app, pilot)
		convo.scroll_home(animate=False)
		await _settle(pilot)
		await _reply(app, "a reply that arrives while reading earlier output")
		await _settle(pilot)
		assert convo.scroll_y == 0
		# scrolling back to the bottom follows again
		convo.scroll_end(animate=False)
		await _settle(pilot)
		await _reply(app, "next reply")
		await _settle(pilot)
		assert _at_bottom(convo)


def test_scrolled_up_view_is_not_yanked_down():
	asyncio.run(_scrolled_up_not_yanked_body())


async def _send_after_subagent_item_body():
	app = AITUI(None)
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await _fill(app, pilot)
		# the last item came from a running subagent: it is routed to the subagent's view
		await app._render({"_type": "ai", "ai_type": "response", "content": "inner step",
		                   "_context": {"subagent": True, "session_id": "s1"}})
		convo.scroll_home(animate=False)
		await _settle(pilot)
		await _send(app, pilot, "steer: stop after this")
		assert "steer: stop after this" in str(convo.children[-1].render())
		assert _at_bottom(convo)


def test_send_lands_in_main_conversation_after_subagent_item():
	asyncio.run(_send_after_subagent_item_body())


async def _choice_box_keeps_bottom_body():
	app = AITUI(None)
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await _fill(app, pilot)
		assert _at_bottom(convo)
		# the end-of-turn choice box takes the input slot and is taller: the view shrinks
		app._show_prompt("next?", (threading.Event(), {}, ["Continue", "Stop", "Other"], "follow_up"))
		await _settle(pilot)
		assert _at_bottom(convo)


def test_choice_box_keeps_last_reply_visible():
	asyncio.run(_choice_box_keeps_bottom_body())


async def _expand_holds_position_body():
	app = AITUI(None)
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await _fill(app, pilot)
		await app._render({"_type": "ai", "ai_type": "shell", "content": "ls -la",
		                   "extra_data": {"runner_id": "r1", "description": "list files"}})
		for i in range(40):
			await app._render({"_type": "ai", "ai_type": "shell_output", "content": f"file{i}",
			                   "extra_data": {"runner_id": "r1"}})
		await _reply(app, "Listed the files.")
		await _settle(pilot)
		assert _at_bottom(convo)
		panel = app.query(RunnerPanel).last()
		head_y = panel.region.y
		panel.toggle()   # expand: grows in place, below its header
		await _settle(pilot)
		assert panel.region.y == head_y
		assert not _at_bottom(convo)
		# collapsing it back ends at the bottom again, and the view follows new output
		panel.toggle()
		await _settle(pilot)
		await _reply(app, "more")
		await _settle(pilot)
		assert _at_bottom(convo)
		# sending re-follows even after an expansion left the view above the bottom
		panel.toggle()
		await _settle(pilot)
		await _send(app, pilot, "thanks")
		assert _at_bottom(convo)
		await _reply(app, "you're welcome " * 50)
		await _settle(pilot)
		assert _at_bottom(convo)


def test_expanding_a_panel_holds_position_and_send_refollows():
	asyncio.run(_expand_holds_position_body())


async def _replay_opens_at_bottom_body():
	app = AITUI(None)
	messages = []
	for i in range(30):
		messages.append({"role": "user", "content": f"question {i}"})
		messages.append({"role": "assistant", "content": f"answer {i}\n\nwith details"})
	async with app.run_test(size=(100, 30)) as pilot:
		convo = app._convo()
		await app._replay_history(messages)
		await _settle(pilot)
		assert _at_bottom(convo)
		await _send(app, pilot, "continue")
		assert _at_bottom(convo)
		await _reply(app, "continuing " * 80)
		await _settle(pilot)
		assert _at_bottom(convo)


def test_resumed_conversation_opens_and_stays_at_bottom():
	asyncio.run(_replay_opens_at_bottom_body())

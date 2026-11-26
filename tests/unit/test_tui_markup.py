"""Text from the model, tools and targets is shown literally, never parsed as markup.

Bracketed text that is not markup (code like ``[e.__cause__, e.__context__]``, ``arr[0]``,
a stray ``[/]``) used to be parsed as a style tag: Textual raises on an unknown style when
it lays the widget out, which crashed the whole app.
"""
import asyncio
import html
import re

import pytest

pytest.importorskip("textual")

from secator.output_types import Error, Info, Warning  # noqa: E402
from secator.tui.ai import AITUI  # noqa: E402

CODE = "[e.__cause__, e.__context__, getattr(e, 'reason', None)]"
NOT_MARKUP = [CODE, "a stray [/] tag", "arr[0]", "[1, 2]"]
TEXTS = NOT_MARKUP + ["[bold]not bold", "[link=http://x]y"]
TRACEBACK = f'  File "web.py", line 292, in _is_dns_failure\n    stack.extend({CODE})\nValueError: boom'


def _screen_text(app):
	svg = app.export_screenshot()
	return html.unescape(re.sub(r"<[^>]+>", "", svg)).replace("\xa0", " ")


def _show(feed, texts=TEXTS):
	"""Run ``feed(app, text)`` for each text in its own app; return each screen's text."""
	async def body(text):
		app = AITUI(None, session="ai", mode="scan")
		app._parent_source = "ai"
		async with app.run_test(size=(160, 40)) as pilot:
			await pilot.pause(0.05)
			await feed(app, text)
			for _ in range(3):
				await pilot.pause()
			return _screen_text(app)
	return {text: asyncio.run(body(text)) for text in texts}


def _assert_literal(screens):
	for text, screen in screens.items():
		assert text in screen, f"{text!r} not shown literally"


def _ai(at, content, **extra_data):
	return {"_type": "ai", "ai_type": at, "content": content, "extra_data": extra_data}


def test_chat_messages_literal():
	async def feed(app, text):
		await app._render(_ai("response", text))
		await app._render(_ai("error", f"model error {text}"))
	_assert_literal(_show(feed))


def test_tool_output_literal():
	async def feed(app, text):
		await app._render(_ai("shell", "cat x.py", runner_id="r1"))
		await app._render(_ai("shell_output", text, runner_id="r1"))
		await app._render(_ai("tool_result", "", error=True, tool_name="read_file", reason=text))
	_assert_literal(_show(feed))


def test_info_warning_error_messages_literal():
	# a message's VALID markup is still applied (as on the console); text that is not markup shows as is
	async def feed(app, text):
		await app._render(Info(message=f"read {text}", _source="ai"))
		if "[/]" not in text:   # Warning() itself rejects a stray closing tag
			await app._render(Warning(message=f"careful {text}", _source="ai"))
		await app._render({"_type": "error", "message": f"failed {text}", "_source": "ai"})
	screens = _show(feed, NOT_MARKUP)
	_assert_literal(screens)
	assert all("[INF]" in s for s in screens.values())   # the item's own markup still renders


# rich_escape() turns "]" into a "\\]" that markup keeps, so the closing bracket shows as "\\]"
SHOWN_CODE = CODE[:-1]


def test_error_traceback_literal():
	async def feed(app, text):
		await app._render(Error(message="boom", traceback=TRACEBACK, _source="ai"))
	screens = _show(feed, [CODE])
	assert f"stack.extend({SHOWN_CODE}" in screens[CODE]


def test_error_traceback_escaped_once():
	assert f"stack.extend({SHOWN_CODE}" in Error(message="boom", traceback=TRACEBACK).__repr__()


def test_choices_literal():
	async def feed_single(app, text):
		app._show_choices([text, "other"], multiple=False)

	async def feed_multi(app, text):
		app._show_choices([text, "other"], multiple=True)
	_assert_literal(_show(feed_single))
	_assert_literal(_show(feed_multi))


def test_meta_bar_and_session_name_literal():
	async def feed(app, text):
		app._set_session_name(f"conv {text}"[:30])
		app._meta["mode"] = text
		app._render_meta()
	screens = _show(feed)
	for text, screen in screens.items():
		assert f"conv {text}"[:30] in screen and f"mode:{text}" in screen

"""`/model-view` in the ai TUI: the conversation exactly as the model receives it.

The model-facing history is stored as sent — encrypted with the session encryptor when it
is on — so the view renders it verbatim. Display only: toggling and refreshing it must not
change the history, the encryptor's placeholder map, or anything the runner is sent.
"""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from secator.ai.encryption import SensitiveDataEncryptor, maybe_encrypt  # noqa: E402
from secator.ai.history import ChatHistory  # noqa: E402
from secator.ai.prompts import format_continue  # noqa: E402
from secator.tasks.ai import ai as AiTask  # noqa: E402
from secator.tui.ai import AITUI  # noqa: E402
from secator.tui.app import TUIApp  # noqa: E402
from secator.tui.model_view import (  # noqa: E402
	MODEL_VIEW_ON, PLACEHOLDER_STYLE, highlight_placeholders, message_signature, model_view_entries,
	model_view_summary)
from secator.tui.widgets import (  # noqa: E402
	ModelMessagePanel, PromptInput, SlashCommand, complete_slash, slash_command_help, slash_help)

HOST = "app.example.com"
IP = "10.1.2.3"
EMAIL = "admin@example.com"


def _history(enc):
	"""A short session built like the loop builds it: every message through the encryptor."""
	h = ChatHistory()
	h.set_system(maybe_encrypt(f"You test {HOST} only.", enc))
	h.add_user(maybe_encrypt(f"scan {HOST} and {IP}, report to {EMAIL}", enc))
	h.add_assistant_with_tool_calls(maybe_encrypt("Probing it.", enc), [{
		"id": "c1", "type": "function",
		"function": {"name": "run_task", "arguments": json.dumps({"name": "httpx", "targets": [enc.encrypt(HOST)]})}}])
	h.add_tool_result("run_task", "c1", maybe_encrypt(f"{HOST} [200] title=Login on {IP}", enc))
	h.add_user(maybe_encrypt(format_continue(1, 10, "continue"), enc))
	return h


def _source(h, enc):
	return lambda: AiTask._model_view_snapshot(SimpleNamespace(history=h, encryptor=enc))


def _clear_values_absent(text):
	return HOST not in text and IP not in text and EMAIL not in text


# ---- pure helpers ----

def test_complete_slash():
	cmds = AITUI.SLASH_COMMANDS
	assert complete_slash("/mo", cmds) == ("/model", ["/model", "/model-view"])
	assert complete_slash("/model-", cmds) == ("/model-view", ["/model-view"])
	# a command that takes arguments completes with a trailing space
	assert complete_slash("/na", cmds) == ("/name ", ["/name"])
	assert complete_slash("/zz", cmds) == ("/zz", [])
	both = {"/model-view": ("", ""), "/mode": ("", "")}
	assert complete_slash("/m", both) == ("/mode", ["/mode", "/model-view"])


@pytest.mark.parametrize("app_cls", [TUIApp, AITUI])
def test_help_lists_every_registered_command_and_keys(app_cls):
	listing = slash_help(app_cls.SLASH_COMMANDS, app_cls.KEY_HELP).plain
	for cmd, entry in app_cls.SLASH_COMMANDS.items():
		assert f"{cmd} {entry.args}".strip() in listing and entry.summary in listing
	for key, desc in app_cls.KEY_HELP:
		assert key in listing and desc in listing
	# the generic shell has no model view; the ai frontend adds it
	assert ("/model-view" in listing) == (app_cls is AITUI)


@pytest.mark.parametrize("app_cls", [TUIApp, AITUI])
def test_dispatch_and_registry_cannot_drift(app_cls):
	registered = set(app_cls.SLASH_COMMANDS)
	# every registered command has its handler ...
	for cmd in registered:
		assert callable(getattr(app_cls, app_cls.slash_handler_name(cmd), None)), cmd
	# ... and every handler is registered (so /help and completion list it)
	handlers = {n for n in dir(app_cls) if n.startswith("_slash_")}
	assert handlers == {app_cls.slash_handler_name(c) for c in registered}
	for cmd, entry in app_cls.SLASH_COMMANDS.items():
		assert isinstance(entry, SlashCommand) and entry.summary and entry.details, cmd


def test_help_for_one_command():
	cmds = AITUI.SLASH_COMMANDS
	one = slash_command_help("model-view", cmds).plain
	assert one.startswith("/model-view") and "placeholders" in one
	assert slash_command_help("/name", cmds).plain.startswith("/name <name>")
	assert "unknown command /nope" in slash_command_help("nope", cmds).plain


def test_entries_and_placeholders():
	enc = SensitiveDataEncryptor()
	h = _history(enc)
	entries = model_view_entries(h.messages)
	roles = [e["role"] for e in entries]
	assert roles == ["system", "user", "assistant", "tool_call", "tool", "user"]
	assert entries[0]["collapsed"] and not entries[1]["collapsed"]
	assert entries[3]["label"] == "tool call · run_task · c1"
	assert entries[5]["label"] == "user · loop instruction"
	for e in entries:
		assert _clear_values_absent(e["body"]), e
	# the placeholders shown are exactly the ones the encryptor minted (no new ones)
	host_ph = next(k for k, v in enc.pii_map.items() if v == HOST)
	assert host_ph in entries[1]["body"] and host_ph in entries[3]["body"]
	text = highlight_placeholders(entries[1]["body"])
	styled = {text.plain[s.start:s.end] for s in text.spans if s.style == PLACEHOLDER_STYLE}
	assert host_ph in styled and len(styled) == 3   # host, ip, email
	assert "3 encrypted values" in model_view_summary(h.messages, True)
	assert "encryption is off" in model_view_summary(h.messages, False)


def test_entries_never_mutate_history():
	h = _history(SensitiveDataEncryptor())
	before = copy.deepcopy(h.messages)
	model_view_entries(h.messages)
	[message_signature(m) for m in h.messages]
	assert h.messages == before


def test_long_tool_result_starts_collapsed():
	msgs = [{"role": "tool", "name": "x", "tool_call_id": "c", "content": "\n".join(["l"] * 50)}]
	e = model_view_entries(msgs)[0]
	assert e["collapsed"] and "50 lines" in e["label"]
	one_line = [{"role": "tool", "name": "x", "tool_call_id": "c", "content": "x" * 9000}]
	e = model_view_entries(one_line)[0]
	assert e["collapsed"] and "9,000 chars" in e["label"]


# ---- headless TUI ----

def _panel_bodies(app):
	return [p.body for p in app._model_view().query(ModelMessagePanel)]


async def _type(pilot, app, text):
	app.query_one("#prompt-input", PromptInput).text = text
	await pilot.press("enter")
	await pilot.pause(0.1)


class _Guard:
	"""Snapshot of the history + encryptor maps; ``check()`` asserts the display left them alone."""

	def __init__(self, h, enc):
		self.h, self.enc = h, enc
		self.take()

	def take(self):
		self.msgs = copy.deepcopy(self.h.messages)
		self.pii, self.hashes = dict(self.enc.pii_map), dict(self.enc.hash_map)

	def check(self):
		assert self.h.messages == self.msgs
		assert self.enc.pii_map == self.pii and self.enc.hash_map == self.hashes


async def _toggle_body():
	enc = SensitiveDataEncryptor()
	h = _history(enc)
	guard = _Guard(h, enc)
	app = AITUI(None, session="ai", mode="chat")
	app.tui_set_model_source(_source(h, enc))
	async with app.run_test(size=(120, 50)) as pilot:
		await pilot.pause(0.05)
		meta = app.query_one("#meta-left")
		assert "model view" not in str(meta.render())

		await _type(pilot, app, "/model-view")
		guard.check()
		assert app._model_view_on
		assert app._model_view().display and not app._convo().display
		assert "model view" in str(meta.render())          # visible indicator
		banner = str(app.query_one("#model-banner").render())
		assert MODEL_VIEW_ON in banner and "3 encrypted values" in banner
		bodies = _panel_bodies(app)
		assert len(bodies) == 6 and all(_clear_values_absent(b) for b in bodies)
		# the slash command is a client command: never queued for the runner
		assert app.tui_poll_steers() == []

		# new history is followed (incremental append)
		h.add_assistant(maybe_encrypt(f"{HOST} looks live.", enc))
		guard.take()
		await app._refresh_model_view()
		await app._tick_model_view()
		await pilot.pause(0.05)
		guard.check()
		bodies = _panel_bodies(app)
		assert len(bodies) == 7 and bodies[-1].endswith("looks live.") and HOST not in bodies[-1]

		# /help while the view is on shows in the view the user is looking at
		await _type(pilot, app, "/help")
		assert list(app._model_view().query(".note")), "help note hidden in the convo"

		# ctrl+o folds/unfolds the model-view messages
		panels = list(app._model_view().query(ModelMessagePanel))
		await pilot.press("ctrl+o")
		assert all(not p._collapsed for p in panels)

		# a drill-in and Back return to the model view
		sv = await app._ensure_subview("sub1")
		app._open_subview("sub1")
		assert sv.display and not app._model_view().display
		app._show_main()
		assert app._model_view().display and not app._convo().display

		# a rewritten history (compaction) re-renders from scratch
		saved = h.messages
		h.messages = [saved[0], {"role": "user", "content": "Summary of previous iterations:\n\nall good"}]
		guard.take()
		await app._refresh_model_view()
		await pilot.pause(0.05)
		guard.check()
		labels = [p.label for p in app._model_view().query(ModelMessagePanel)]
		assert labels[1] == "user · summary of earlier turns" and len(labels) == 2

		await _type(pilot, app, "/model-view")
		guard.check()
		assert not app._model_view_on
		assert app._convo().display and not app._model_view().display
		assert "model view" not in str(meta.render())
		assert not list(app._model_view().query(ModelMessagePanel))
		assert "Model view off" in str(list(app._convo().query(".note"))[-1].render())


def test_model_view_toggle_headless():
	asyncio.run(_toggle_body())


async def _help_and_complete_body():
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		inp = app.query_one("#prompt-input", PromptInput)
		inp.text = "/model-"
		inp.move_cursor(inp.document.end)
		await pilot.press("tab")
		await pilot.pause(0.05)
		assert inp.text == "/model-view" and inp.has_focus
		await pilot.press("enter")
		await pilot.pause(0.1)
		# no runner yet: the view still opens, and says so
		assert app._model_view_on
		assert "no conversation with the model yet" in str(app.query_one("#model-banner").render())
		await _type(pilot, app, "/model-view")
		await _type(pilot, app, "/help")
		notes = [str(w.render()) for w in app._convo().query(".note")]
		assert any("/model-view" in n and "/help" in n and "ctrl+t" in n for n in notes)
		await _type(pilot, app, "/help model-view")
		last = str(list(app._convo().query(".note"))[-1].render())
		assert last.startswith("/model-view") and "Display only" in last
		assert any("Model view off" in n for n in notes)
		# a message that only starts with "/" (or with a command word) is still a message
		await _type(pilot, app, "/etc/hosts looks odd")
		assert app.tui_poll_steers() == [] and app._prefill == "/etc/hosts looks odd"
		for msg in ("/help me scan example.com", "/model-view please explain"):
			await _type(pilot, app, msg)
		assert app.tui_poll_steers() == ["/help me scan example.com", "/model-view please explain"]
		assert not app._model_view_on
		# Tab on a prefix with no command keeps the text
		inp = app.query_one("#prompt-input", PromptInput)
		inp.text = "/zz"
		await pilot.press("tab")
		assert inp.text == "/zz"


async def _prompt_leaves_view_body():
	app = AITUI(None, session="ai", mode="chat")
	async with app.run_test(size=(120, 40)) as pilot:
		await pilot.pause(0.05)
		app._awaiting_first_prompt = False
		await app._set_model_view(True)
		# a plain follow-up keeps the view; a choice list leaves it so it isn't answered blind
		app._show_prompt("next?", (None, {}, [], "stopped"))
		await pilot.pause(0.05)
		assert app._model_view_on
		app._show_prompt("pick", (None, {}, ["a", "b"], "stopped"))
		await pilot.pause(0.1)
		assert not app._model_view_on and app._convo().display


def test_choice_prompt_leaves_model_view():
	asyncio.run(_prompt_leaves_view_body())


def test_help_and_completion_headless():
	asyncio.run(_help_and_complete_body())

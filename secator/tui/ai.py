"""AI frontend for the secator TUI.

``AITUI`` subclasses the generic :class:`~secator.tui.app.TUIApp` and adds only the
AI-specific item handling: ``_type:"ai"`` items (responses as Markdown, runner cards,
finding-mutation actions) and the subagent drill-in view. Everything else — panels,
findings, status, input, prompts/steers, the findings side panel — comes from the base.
"""
from __future__ import annotations

import asyncio

from rich.markup import escape
from rich.text import Text
from textual.containers import VerticalScroll
from textual.widgets import Static

from secator.tui.app import TUIApp
from secator.tui.model_view import (
	MODEL_VIEW_OFF, MODEL_VIEW_ON, message_signature, model_view_entries, model_view_summary)
from secator.tui.render import finding_text, markdown_text
from secator.tui.widgets import (
	ActionPanel, ConversationScroll, HandbackPanel, ModelMessagePanel, RunnerPanel, SelectableStatic, SlashCommand,
	SubagentRow, ToolCallPanel)


def _finding_sig(d: dict) -> tuple:
	"""Stable identity of a finding for one-shot dedup before it has a _uuid.

	add_finding renders the finding as an expandable action row AND yields the finding
	itself (which the base renders as a card); this signature lets the base skip that
	duplicate card. Keyed on the type + the fields that locate a finding.
	"""
	return (
		d.get("_type"), d.get("name"), d.get("matched_at"), d.get("url"),
		d.get("ip"), d.get("host"), d.get("port"), d.get("severity"),
	)


# AI finding-action verbs — rendered as an expandable "<Verb> <finding name>" row (no icon).
_ACTION_VERBS = {
	"add_finding": "Added",
	"update_finding": "Updated",
	"add_vuln_poc": "Added PoC",
	"mark_vuln_exploited": "Exploited",
	"mark_vuln_exploit_failed": "Failed to exploit",
	"mark_vuln_false_positive": "Marked false positive",
	"mark_vuln_fixed": "Marked fixed",
}


class AITUI(TUIApp):
	SLASH_COMMANDS = {
		**TUIApp.SLASH_COMMANDS,
		"/model-view": SlashCommand(
			"", "toggle the model view: the conversation as the model receives it",
			"Shows the model-facing history as sent: the system prompt (folded), user turns and "
			"the loop's injected instructions, assistant replies with their raw tool calls, and "
			"every tool result. With sensitive-data encryption on, hosts, IPs and emails appear "
			"as the [TYPE:hash] placeholders the model received. Display only: nothing sent or "
			"saved changes. Run it again to return to the conversation."),
		"/model": SlashCommand(
			"[profile]", "list the AI profiles, or switch the chat to one",
			"Without an argument: the AI profiles (addons.ai.profiles, plus default = the addons.ai "
			"settings) with their model, the one in use marked. With a name: the next model calls use "
			"that profile, the conversation so far is kept. Set the default one with "
			"`secator config set addons.ai.profile <name>`."),
	}
	CSS = TUIApp.CSS + """
	#model-view { display: none; }
	.model-banner { color: #c2a0ff; margin: 0 0 1 0; }
	.model-msg { height: auto; margin: 0 0 1 0; }
	.model-msg-head { height: 1; }
	.model-msg-head:hover { text-style: bold; }
	.model-msg-body { height: auto; margin: 0 0 0 2; padding: 0 0 0 1; border-left: solid #2b3245; }
	"""

	def __init__(self, runner_builder=None, session="ai", mode="chat", initial_prompt="",
	             initial_dangerous=False, session_name="", resume=False):
		# On --resume the run first lists the saved sessions for the user to pick: say so (not
		# a generic "starting…" that reads like the model answering), and keep the input
		# hidden until a session is picked — there is nothing to type into before that.
		super().__init__(
			runner_builder,
			title="secator ai",
			subtitle=f"session: {session} · mode: {mode}",
			initial_prompt=initial_prompt,
			initial_dangerous=initial_dangerous,
			initial_mode=mode or "auto",
			session_name=session_name or str(session),
			startup_status="Loading sessions…" if resume else "starting…",
			lock_input=bool(resume),
		)
		self._in_subagent: str | None = None          # subagent session we're writing into
		# sid -> SubagentRow for every spawned subagent still running. A dict (not a single
		# ref) so PARALLEL subagents each keep their own row — each is marked "Ran" when ITS
		# handback arrives (correlated by subagent_session_id), not when the last one does.
		self._active_subagents: dict = {}
		# Signatures of findings shown via an add_finding action row. _pending holds the
		# finding the handler yields right after (no _uuid yet) so it isn't drawn again as a
		# standalone card; _suppressed keeps that signature until the finding is re-read with a
		# persisted _uuid (e.g. via query_workspace) so that re-read is deduped too — it was
		# already shown once, as the row.
		self._pending_finding_sigs: set = set()
		self._suppressed_finding_sigs: set = set()
		# _uuids of every item the on_item feed (_tui_feed) delivered. A result the runner adds
		# WITHOUT hooks (e.g. a driver hook failure) never reaches the feed; after the run the
		# runner's own errors missing from this set are rendered so a failure is never silent.
		self._fed_uuids: set = set()
		# Every runner this TUI drives that started (the Task wrapper runs with hooks off and
		# builds the real ai runner, which persists through the drivers). Quitting mid-run
		# finalizes the unfinished ones (see _finalize_interrupted_runner).
		self._started_runners: list = []
		# ---- model view (/model-view) ----
		# Display only: a read-only view of the runner's model-facing history (already
		# encrypted when the encryptor is on). ``_model_source`` is a callable the ai task
		# registers (``tui_set_model_source``) returning {"messages": [...], "encrypted": bool}.
		self._model_source = None
		self._model_view_on = False
		self._mv_sigs: list = []   # signature of each history message rendered, for incremental refresh

	# ---- model view ----
	def tui_set_model_source(self, source) -> None:
		"""Register the callable that snapshots the model-facing history (any thread)."""
		self._model_source = source

	def on_mount(self) -> None:
		# Textual already dispatches on_mount along the MRO: calling super() would start the runner twice.
		self._mv_lock = asyncio.Lock()   # one refresh / toggle at a time (they await mounts)
		self.query_one("#views").mount(ConversationScroll(id="model-view", classes="subview"))
		self.set_interval(1.0, self._tick_model_view)   # follow the history while the view is on

	def _model_view(self) -> VerticalScroll:
		return self.query_one("#model-view", VerticalScroll)

	def _model_snapshot(self) -> "tuple[list, bool]":
		source = self._model_source
		if source is None:
			return [], False
		try:
			snap = source() or {}
		except Exception:  # noqa: BLE001 - display only: a racing history must not crash the UI
			return None, False
		msgs = snap.get("messages") or []
		return [m for m in msgs if isinstance(m, dict)], bool(snap.get("encrypted"))

	def _model_banner(self, messages, encrypted) -> Static:
		if self._model_source is None:
			sub = "no conversation with the model yet"
		else:
			sub = model_view_summary(messages, encrypted)
		return Static(Text.assemble(
			(f"◉ {MODEL_VIEW_ON}", "bold #c2a0ff"), "\n",
			(f"{sub} · /model-view to turn off", "#6b7187")), classes="model-banner", id="model-banner")

	async def _refresh_model_view(self, full: bool = False) -> None:
		"""Render the model-facing history into the model view: append the messages added
		since the last refresh, or re-render everything when the history was rewritten
		(compaction, a new system prompt) or ``full`` is set."""
		async with self._mv_lock:
			if self._model_view_on:
				await self._refresh_model_view_locked(full)

	async def _refresh_model_view_locked(self, full: bool) -> None:
		messages, encrypted = self._model_snapshot()
		if messages is None:
			return
		view = self._model_view()
		try:
			sigs = [message_signature(m) for m in messages]
		except Exception:  # noqa: BLE001 - a message mutated mid-read: try again next tick
			return
		n = len(self._mv_sigs)
		at_end = view.max_scroll_y <= 0 or view.scroll_y >= view.max_scroll_y - 1
		if full or sigs[:n] != self._mv_sigs:
			await view.remove_children()
			await view.mount(self._model_banner(messages, encrypted))
			new = messages
		else:
			if len(sigs) == n:
				return
			new = messages[n:]
			try:
				await self.query_one("#model-banner").remove()
			except Exception:  # noqa: BLE001
				pass
			banner = self._model_banner(messages, encrypted)
			if view.children:
				await view.mount(banner, before=0)
			else:
				await view.mount(banner)
		self._mv_sigs = sigs
		panels = [ModelMessagePanel(e["role"], e["label"], e["body"], e["collapsed"]) for e in model_view_entries(new)]
		if panels:
			await view.mount_all(panels)
		if full or at_end:
			view.scroll_end(animate=False)

	async def _tick_model_view(self) -> None:
		if self._model_view_on:
			await self._refresh_model_view()

	async def _slash_model_view(self, text: str) -> None:
		"""`/model-view`: toggle the model view (display only — nothing sent or stored changes)."""
		await self._set_model_view(not self._model_view_on)

	async def _slash_model(self, text: str) -> None:
		"""`/model [profile]`: list the AI profiles, or queue a switch the runner applies before its next model call."""
		from secator.ai.utils import DEFAULT_PROFILE, resolve_ai_profile
		from secator.config import CONFIG
		name = text[len("/model"):].strip()
		names = [name] if name else [DEFAULT_PROFILE, *CONFIG.addons.ai.profiles]
		try:
			models = {n: resolve_ai_profile(n)["model"] for n in names}
		except ValueError as e:
			await self._append_note(Text(str(e), style="#e06c75"))
			return
		if name:
			with self._control_lock:
				self._control["profile"] = name
			await self._append_note(Text.from_markup(
				f"[#6b7187]↻ switching to AI profile [b]{escape(name)}[/] ({escape(models[name] or 'no model')}) "
				"from the next model call[/]"))
			return
		try:
			current = (self._model_source() or {}).get("profile") if self._model_source else None
		except Exception:  # noqa: BLE001 - display only
			current = None
		width = max(len(n) for n in models)
		lines = [Text.assemble(("AI profiles", "bold"), (" · /model <name> to switch", "#6b7187"))]
		for n, model in models.items():
			mark = "●" if n == (current or "") else " "
			lines.append(Text.assemble((f"{mark} ", "#c2a0ff"), (f"{n:<{width}}  ", "bold" if mark != " " else ""),
			                           (model or "no model", "#6b7187")))
		await self._append_note(Text("\n").join(lines))

	async def _set_model_view(self, on: bool) -> None:
		view = self._model_view()
		async with self._mv_lock:
			self._model_view_on = bool(on)
			self._mv_sigs = []
			if self._model_view_on:
				await self._refresh_model_view_locked(full=True)
				self._convo().display = False
				view.display = True
			else:
				view.display = False
				await view.remove_children()
				self._convo().display = True
		self._render_meta()
		if not self._model_view_on:
			await self._append_note(Text(f"◉ {MODEL_VIEW_OFF}", style="#6b7187"))

	def _show_prompt(self, question, pending, multiple=False, command="", solo=False) -> None:
		# A choice list or an approval needs the conversation's context (the reply explaining
		# it renders there): leave the model view so the question isn't answered blind.
		if self._model_view_on and (pending[3] == "permission" or pending[2]):
			self.call_later(self._set_model_view, False)
		super()._show_prompt(question, pending, multiple, command, solo)

	def _meta_extra(self) -> str:
		return "[b #c2a0ff]◉ model view[/] [#5b6070](/model-view)[/]" if self._model_view_on else ""

	def _show_main(self) -> None:
		super()._show_main()
		if self._model_view_on:   # back from a drill-in lands on the model view, not the convo
			self._convo().display = False
			self._model_view().display = True

	def _open_subview(self, sid: str) -> None:
		if sid in self._subviews:
			self._model_view().display = False
		super()._open_subview(sid)

	def _active_view(self) -> VerticalScroll:
		view = self._model_view()
		return view if view.display else super()._active_view()

	def action_expand_all(self) -> None:
		# ctrl+o in the model view folds/unfolds its messages instead of the (hidden) runner cards
		if not self._model_view().display:
			return super().action_expand_all()
		panels = list(self._model_view().query(ModelMessagePanel))
		if panels:
			expand = any(p._collapsed for p in panels)
			for p in panels:
				p.set_collapsed(not expand)

	def _should_skip_finding(self, d: dict) -> bool:
		# Suppress the standalone card for a finding already shown as an add_finding row.
		sig = _finding_sig(d)
		uid = d.get("_uuid")
		if sig in self._pending_finding_sigs:
			self._pending_finding_sigs.discard(sig)
			if uid:
				self._shown_uuids.add(uid)          # persisted already: _uuid dedup covers re-reads
			else:
				self._suppressed_finding_sigs.add(sig)  # no _uuid yet: keep the sig for the re-read
			return True
		if sig in self._suppressed_finding_sigs:
			# Same finding re-read later, now carrying a persisted _uuid: skip it (already shown
			# as the row) and migrate to _uuid dedup so we stop tracking the coarse signature.
			if uid:
				self._shown_uuids.add(uid)
				self._suppressed_finding_sigs.discard(sig)
			return True
		return False

	async def _route_write(self, d: dict) -> VerticalScroll:
		# route subagent-internal items into that subagent's own (hidden) view; the spawn
		# card itself has the marker stripped, so it stays in the main convo
		ctx = d.get("_context") or {}
		if ctx.get("subagent"):
			self._in_subagent = ctx.get("session_id") or "subagent"
			return await self._ensure_subview(self._in_subagent)
		# A main-thread item: a subagent row is marked "Ran" by its own handback (see the
		# `response` branch in _render_ai), not here — a single "control returned" heuristic
		# can't tell WHICH of several parallel subagents just finished.
		self._in_subagent = None
		return self._convo()

	async def _render_domain(self, d: dict) -> bool:
		if d.get("_type") != "ai":
			return False
		await self._render_ai(d)
		return True

	async def _render_ai(self, d: dict) -> None:
		at = d.get("ai_type", "")
		content = d.get("content", "") or ""
		if at in ("prompt", "steer"):
			# user-origin message: already echoed on submit — don't double-render
			# from the item stream
			return
		# Multi-level display hooks (a child runner's own hook + the parent's) can feed the
		# SAME ai item more than once — most visibly a subagent's steps, which fire at both
		# the subagent and parent levels. Findings are _uuid-deduped in the base; dedup ai
		# items the same way (completes the attach_display_hooks "UI dedups by _uuid"
		# contract). Only truthy uuids — unpersisted items (and test fixtures) carry ''.
		uid = d.get("_uuid")
		if uid:
			if uid in self._shown_uuids:
				return
			self._shown_uuids.add(uid)
		if at == "response":
			self._finish_current()
			# A subagent's handback is a `response` stamped (in run_subagent) with its own
			# session id. Mark THAT row "Ran" (parallel subagents hand back independently) and
			# render the verdict at the END of that subagent's view — a red-outlined box with a
			# token/cost line, so it reads as the conclusion. It's model-facing in the main
			# conversation (a tool_result, which the TUI suppresses), so show it ONLY there.
			ed = d.get("extra_data") or {}
			hb_sid = ed.get("subagent_session_id")
			if hb_sid:
				row = self._active_subagents.pop(hb_sid, None)
				if row is not None:
					row.mark_done()
				sv = await self._ensure_subview(hb_sid)
				await sv.mount(HandbackPanel(content, ed.get("usage") or {}))
				sv.scroll_end(animate=False)
				return
			await self._append(SelectableStatic(markdown_text(content), classes="ai"))  # AI text as Markdown
		elif at in ("task", "workflow", "scan", "query", "shell"):
			ed = d.get("extra_data") or {}
			desc = ed.get("description") or ""
			if ed.get("subagent"):
				# subagent spawn: a clickable row in the main convo that opens the
				# subagent's own conversation view
				sid = ed.get("subagent_session_id") or ed.get("runner_id") or "subagent"
				sub = ed.get("subagent")
				label = sub if isinstance(sub, str) else (desc or content or "subagent")
				sv = await self._ensure_subview(sid)
				if not sv.children:
					await sv.mount(Static(
						Text.from_markup(f"[b]Subagent[/] [dim]{escape(label)}[/]"), classes="subview-title"))
				self._finish_current()
				row = SubagentRow(label, sid)
				self._active_subagents[sid] = row
				await self._append(row)
				return
			meta = ""
			result_count = None
			config_name = None
			if at == "shell":
				# LLM-supplied description as the title; the command goes in the box
				kind, rname, command = "shell", desc, content
			elif at == "query":
				# title is the LLM's human description; the result count shows inline in the
				# header ("<desc> (N results)"); the raw query is the command; the meta line
				# carries any skip/limit/group details.
				kind, rname, command = "query", desc or content, content
				result_count = ed.get("results", 0)
				bits = []
				if ed.get("offset"):
					bits.append(f"skip={ed.get('offset')}")
				if ed.get("limit") is not None:
					bits.append(f"limit={ed.get('limit')}")
				if ed.get("group"):
					bits.append("grouped")
				meta = "  ·  ".join(bits)
			else:
				kind, rname, command = at, desc or content or ed.get("name") or "", ""
				# the actual config used (task/workflow/scan name), shown in the header as
				# "(<kind> • <config>)" so it's clear which config ran
				config_name = content or ed.get("name") or ""
			panel = RunnerPanel(kind, rname, command=command, runner_id=ed.get("runner_id", ""),
			                    meta=meta, result_count=result_count, config_name=config_name)
			# the card's content is the runner name (== _source of its items). Used to
			# route a task's live output + buffered output (parallel batch), and to tell a
			# workflow's OWN notes (_source == workflow name) from its child tasks' items.
			# shell items carry _source = the command task's unique_name ("command"); set
			# it so a shell's error routes to its panel. Runners use the runner name.
			panel.source = "command" if at == "shell" else (content if at in ("task", "workflow", "scan") else "")
			await self._append(panel)
			# finish the prior leaf + register this panel; workflows/scans become nesting
			# containers (their interleaved children route to them by id in a parallel batch)
			self._start_runner(panel, is_container=at in ("workflow", "scan"))
			self._flush_buffer(panel)
			self._set_status(f"running {kind} {rname or command}".strip())
		elif at == "shell_output":
			# a shell's stdout IS its result (no secator findings) — show it directly,
			# not hidden behind the command-click like a task's raw output. Route to the
			# command's OWN panel by runner id (the shell_output item carries the same id as
			# its `shell` item): in a PARALLEL batch several actions stream at once, so
			# `self._current` may point at a sibling task's panel — appending there would
			# wire the shell's stdout into the wrong card. Fall back to `self._current` only
			# when the item has no id (older items) / the panel isn't registered.
			rid = (d.get("extra_data") or {}).get("runner_id") or ""
			panel = self._leaf_panels.get(rid) if rid else None
			if panel is None:
				panel = self._current
			if panel is not None:
				panel.add_output(content)
		elif at in _ACTION_VERBS:
			# AI action on a finding: a neutral "<Verb> <name>" row (same tone as a runner
			# header), no icon — icons are for secator findings, not AI actions. Expand the
			# row to see the referenced finding rendered richly (its own __rich__).
			fd = (d.get("extra_data") or {}).get("finding") or {}
			name = fd.get("name") or fd.get("id") or fd.get("matched_at") or content
			verb = _ACTION_VERBS[at]
			renderable = finding_text(None, fd) if fd else None
			if at == "add_finding":
				# add_finding ALSO yields the full finding right after (for persistence +
				# non-TUI frontends); it would otherwise render as a 2nd standalone card. We
				# show it here (expandable) instead, so suppress that duplicate. The finding
				# has no _uuid yet (assigned on persist), so match on a field signature.
				self._pending_finding_sigs.add(_finding_sig(fd))
			await self._append(ActionPanel(verb, name, renderable))
		elif at == "error":
			await self._append(Static(Text.from_markup(f"[red]✖ {escape(content)}[/]"), classes="err"))
		elif at == "tool_result":
			# A plain tool_result is model-facing only (its findings render as cards). But a
			# REJECTED tool call (malformed/empty args, denied) carries extra_data.error — surface
			# it so a failing tool isn't silently retried behind a frozen-looking screen. A
			# guardrail denial (blocked) already renders a "Blocked <desc>" panel, so skip the
			# redundant "tool call failed" line for those.
			ed = d.get("extra_data") or {}
			if ed.get("error") and not ed.get("blocked"):
				reason = ed.get("reason") or content
				tool = ed.get("tool_name") or ""
				label = f"{tool}: {reason}" if tool else reason
				await self._append(Static(Text.from_markup(f"[red]✖ tool call failed — {escape(str(label))}[/]"), classes="err"))
		elif at == "mode_changed":
			# content is the new mode name; show the same "Switched to <mode> mode" notice the
			# console path prints (suppressed under the TUI, which owns the display).
			await self._append(Static(
				Text.from_markup(f"[dim]↻ Switched to [b]{escape(content)}[/] mode[/]"), classes="note"))
		elif at == "token_usage":
			# a subagent reports its running token count each turn — feed the read-only meta bar
			# shown while drilled into that subagent's view (compute % of usable context)
			ed = d.get("extra_data") or {}
			sid = self._in_subagent
			if sid:
				tokens = ed.get("tokens") or 0
				ctx_window = ed.get("context_window") or 0
				pct = None
				try:
					from secator.ai.history import OUTPUT_TOKEN_RESERVATION
					usable = ctx_window - OUTPUT_TOKEN_RESERVATION
					pct = (tokens / usable * 100) if usable > 0 else None
				except Exception:  # noqa: BLE001
					pct = None
				self._set_meta(None, None, None, pct, True, sid)
		elif at == "stopped":
			# End-of-turn stop: show the reason (summary / blocker) as markdown, then go
			# idle. The ask_user prompt (choices / input box) renders the next-step UI.
			self._finish_current()
			if content:
				await self._append(SelectableStatic(markdown_text(content), classes="ai"))
			self._set_status("stopped", False)
		elif at and at == (d.get("_context") or {}).get("tool_call_name"):
			# A tool's own display item (its ai_type is the tool name, e.g. web_search, fetch_url)
			# with no dedicated card above: show it as the finished tool card the resume replay
			# uses, so the call is not silently dropped. A short content (a search query) titles
			# the card. Loop-internal items a subagent emits carry the subagent's call name, never
			# their own ai_type, so they stay hidden.
			ed = {k: v for k, v in (d.get("extra_data") or {}).items() if k != "ai_query_result"}
			if content and len(content) <= 80 and "\n" not in content:
				ed = {"description": content, **ed}
			await self._append(ToolCallPanel(at, ed, content))


def _tui_feed(self, item):
	"""on_item hook: marshal each yielded item onto the active TUI.

	MUST be a module-level function, NOT a closure: runners pickle their hooks by
	qualified name (secator#1267), and a local closure (`run_ai_tui.<locals>._feed`)
	has no importable qualname — so serializing a runner that carries it (e.g. a task
	whose result Celery stores) raises `Can't pickle local object`. Looking the TUI up
	via `get_tui()` instead of closing over `app` keeps it picklable, and makes it a
	no-op on a worker (where no TUI is set), which is exactly what we want.

	`self` is the parent ai runner — remember its source so the display can tell the
	parent task's OWN notes/errors (shown top-level) from a child runner's (buffered
	under its card). Cheap + idempotent on every item.
	"""
	from secator.rich import get_tui
	app = get_tui()
	if app is None:
		return item
	app._parent_source = getattr(self, "unique_name", "") or app._parent_source
	uid = getattr(item, "_uuid", None)
	if uid and hasattr(app, "_fed_uuids"):
		app._fed_uuids.add(uid)
	app.tui_render(item)
	return item


def _tui_track(self):
	"""on_start hook: remember each runner the active TUI drives, so quitting can finalize it.

	Module-level for the same pickling reason as ``_tui_feed``; a no-op without a TUI.
	"""
	from secator.rich import get_tui
	app = get_tui()
	tracked = getattr(app, "_started_runners", None)
	if tracked is not None and self not in tracked:
		tracked.append(self)


def _surface_unrendered_errors(app, runner):
	"""Render the runner's own errors that never went through the on_item feed.

	A driver hook that fails (e.g. the api driver cannot create the runner) records its
	Error with ``hooks=False``, so ``_tui_feed`` never sees it; the runner then stops before
	the AI loop starts (``__iter__`` exits early on errors). The TUI owns the display and
	the runner's console printing is off, so without this the user saw a TUI that never
	answered and no reason why.
	"""
	if app is None or runner is None:
		return
	fed = getattr(app, "_fed_uuids", set())
	try:
		errors = list(runner.self_errors)
	except Exception:  # noqa: BLE001 - surfacing errors must never crash the TUI
		return
	for error in errors:
		uid = getattr(error, "_uuid", None)
		if uid and uid in fed:
			continue
		if uid:
			fed.add(uid)
		app.tui_render(error)


def _finalize_interrupted_runner(runner):
	"""Close a runner the user left by quitting the TUI (Ctrl+C) before it finished.

	The runner is driven on a daemon thread, so quitting the app ends the process without
	the runner ever leaving its loop: no ``on_end`` hook ran and every driver kept it
	``RUNNING`` forever. Mirror the core interrupt path in ``Runner.__iter__`` (a
	``KeyboardInterrupt`` marks the runner revoked, records the error, then completes it):
	mark it revoked, record the interruption, run ``on_end`` through its drivers, then turn
	hooks off so the abandoned thread cannot overwrite the final status.
	"""
	if runner is None or getattr(runner, "done", True):
		return
	from secator.output_types import Error
	try:
		runner.revoked = True
		runner.add_result(Error(message="Interrupted by user", _source=runner.unique_name), print=False)
		runner.mark_completed()
	except Exception as e:  # noqa: BLE001 - quitting must never crash
		runner.debug(f"failed to finalize interrupted runner: {e}", sub="end")
	finally:
		runner.enable_hooks = False


def run_ai_tui(runner_cls, config, inputs, opts, hooks, context):
	"""Entry used by the CLI: set this app as the active TUI (so the ai task selects the
	TUIBackend + suppresses console output), then run it.

	The ai task is wrapped in a Task runner, which prints items internally but yields
	NOTHING to the iterator — so we tap the item stream via an on_item hook (merged into
	the runner's hooks) that marshals each item onto the UI thread. The runner is BUILT
	inside the worker (after set_tui) so the backend resolves with the TUI active."""
	from secator.rich import set_tui

	# The TUI drives the ai task IN-PROCESS and is a local interactive frontend — the
	# interactivity bridge (ask_user/steers) and display hooks only work when the task
	# runs locally. So force sync: with sync=False the task would dispatch to a worker,
	# where get_tui() is None, and the TUI would never get a prompt or a response.
	opts = {**opts, "sync": True}

	# `-p <file>`: if the prompt is a path to an existing file, use its contents (the task
	# does the same for the LLM message; resolve here too so the TUI echoes/sessions the
	# actual prompt, not the literal filename).
	from pathlib import Path
	prompt_val = opts.get("prompt", "") or ""
	if prompt_val:
		try:
			if Path(prompt_val).is_file():
				opts = {**opts, "prompt": Path(prompt_val).read_text(encoding="utf-8").strip()}
		except OSError:
			pass

	session = opts.get("workspace") or opts.get("prompt", "ai") or "ai"
	# mode="" / "auto" means auto-detect — show "auto" on the meta bar until the runner reports
	_mode = opts.get("mode") or "auto"
	app = AITUI(
		None, session=str(session)[:30], mode=_mode,
		initial_prompt=opts.get("prompt", ""), initial_dangerous=bool(opts.get("dangerous")),
		session_name=opts.get("session_name") or "", resume=bool(opts.get("resume")))

	# Tap the item stream via a module-level on_item hook (see `_tui_feed` — it must not be
	# a local closure or the runner can't pickle its hooks). It renders onto this `app`
	# because `set_tui(app)` below makes it the active TUI that `get_tui()` returns.
	merged = dict(hooks or {})
	cls_hooks = dict(merged.get(runner_cls, {}))
	cls_hooks["on_item"] = list(cls_hooks.get("on_item", [])) + [_tui_feed]
	# Track first: a driver on_start hook can block on a network update, and a quit during it
	# must still find (and finalize) the runner. The driver's create runs earlier, in on_init.
	cls_hooks["on_start"] = [_tui_track] + list(cls_hooks.get("on_start", []))
	merged[runner_cls] = cls_hooks

	state = {}

	def build():
		runner = runner_cls(config, inputs, run_opts=opts, hooks=merged, context=context)
		state["runner"] = runner
		for _ in runner:
			pass
		# If nothing was fed (the run failed before its first item), the TUI does not know the
		# parent source yet and would buffer these errors under a card that never renders.
		app._parent_source = app._parent_source or getattr(runner, "unique_name", "")
		# the Task wrapper builds the real ai runner, which owns the errors
		for started in [*app._started_runners, runner]:
			_surface_unrendered_errors(app, started)
		if False:  # keep build() a generator (driven by _consume) while yielding nothing
			yield

	app._runner_builder = build
	set_tui(app)
	try:
		app.run()
	finally:
		set_tui(None)
		# Quitting the TUI (Ctrl+C) while the runner is still going abandons its thread:
		# finalize every unfinished runner (latest first, the outer wrapper last) so the
		# drivers record a final (revoked) status instead of RUNNING forever.
		runners = list(reversed(app._started_runners))
		if state.get("runner") is not None and state["runner"] not in runners:
			runners.append(state["runner"])
		for runner in runners:
			_finalize_interrupted_runner(runner)

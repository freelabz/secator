"""AI frontend for the secator TUI.

``AITUI`` subclasses the generic :class:`~secator.tui.app.TUIApp` and adds only the
AI-specific item handling: ``_type:"ai"`` items (responses as Markdown, runner cards,
finding-mutation actions) and the subagent drill-in view. Everything else — panels,
findings, status, input, prompts/steers, the findings side panel — comes from the base.
"""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.containers import VerticalScroll
from textual.widgets import Static

from secator.tui.app import TUIApp
from secator.tui.render import finding_text, markdown_text
from secator.tui.widgets import ActionPanel, HandbackPanel, RunnerPanel, SubagentRow


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
}


class AITUI(TUIApp):
	def __init__(self, runner_builder=None, session="ai", mode="chat", initial_prompt=""):
		super().__init__(
			runner_builder,
			title="secator ai",
			subtitle=f"session: {session} · mode: {mode}",
			initial_prompt=initial_prompt,
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
			await self._append(Static(markdown_text(content), classes="ai"))  # AI text as Markdown
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
			if at == "shell":
				# LLM-supplied description as the title; the command goes in the box
				kind, rname, command = "shell", desc, content
			elif at == "query":
				# title is the LLM's human description ("Querying/Queried <desc>"); the raw
				# query is the command; a meta line carries the result count + skip/limit/group
				kind, rname, command = "query", desc or content, content
				bits = [f"{ed.get('results', 0)} results"]
				if ed.get("offset"):
					bits.append(f"skip={ed.get('offset')}")
				if ed.get("limit") is not None:
					bits.append(f"limit={ed.get('limit')}")
				if ed.get("group"):
					bits.append("grouped")
				meta = "  ·  ".join(bits)
			else:
				kind, rname, command = at, desc or content or ed.get("name") or "", ""
			panel = RunnerPanel(kind, rname, command=command, runner_id=ed.get("runner_id", ""), meta=meta)
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
			# not hidden behind the command-click like a task's raw output
			if self._current is not None:
				self._current.add_output(content)
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
			# it so a failing tool isn't silently retried behind a frozen-looking screen.
			ed = d.get("extra_data") or {}
			if ed.get("error"):
				reason = ed.get("reason") or content
				tool = ed.get("tool_name") or ""
				label = f"{tool}: {reason}" if tool else reason
				await self._append(Static(Text.from_markup(f"[red]✖ tool call failed — {escape(str(label))}[/]"), classes="err"))
		elif at == "mode_changed":
			# content is the new mode name; show the same "Switched to <mode> mode" notice the
			# console path prints (suppressed under the TUI, which owns the display).
			await self._append(Static(
				Text.from_markup(f"[dim]↻ Switched to [b]{escape(content)}[/] mode[/]"), classes="note"))
		elif at == "stopped":
			# End-of-turn stop: show the reason (summary / blocker) as markdown, then go
			# idle. The ask_user prompt (choices / input box) renders the next-step UI.
			self._finish_current()
			if content:
				await self._append(Static(markdown_text(content), classes="ai"))
			self._set_status("stopped", False)


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
	app = AITUI(
		None, session=str(session)[:30], mode=opts.get("mode", "chat"),
		initial_prompt=opts.get("prompt", ""))

	def _feed(self, item):  # on_item hook: runs in the worker thread
		# `self` is the parent ai runner — remember its source so the display can tell the
		# parent task's OWN notes/errors (shown top-level) from a child runner's (buffered
		# under its card). Cheap + idempotent on every item.
		app._parent_source = getattr(self, "unique_name", "") or app._parent_source
		app.tui_render(item)
		return item

	merged = dict(hooks or {})
	cls_hooks = dict(merged.get(runner_cls, {}))
	cls_hooks["on_item"] = list(cls_hooks.get("on_item", [])) + [_feed]
	merged[runner_cls] = cls_hooks

	def build():
		runner = runner_cls(config, inputs, run_opts=opts, hooks=merged, context=context)
		for _ in runner:
			pass
		if False:  # keep build() a generator (driven by _consume) while yielding nothing
			yield

	app._runner_builder = build
	set_tui(app)
	try:
		app.run()
	finally:
		set_tui(None)

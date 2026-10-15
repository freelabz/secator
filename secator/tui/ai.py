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
from textual.widgets import Markdown, Static

from secator.tui.app import TUIApp
from secator.tui.render import finding_text
from secator.tui.widgets import ActionPanel, RunnerPanel, SubagentRow


# AI finding-action verbs — rendered as a plain "<Verb> <finding name>" line (no icon).
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
		self._active_subagent: SubagentRow | None = None

	async def _route_write(self, d: dict) -> VerticalScroll:
		# route subagent-internal items into that subagent's own (hidden) view; the spawn
		# card itself has the marker stripped, so it stays in the main convo
		ctx = d.get("_context") or {}
		if ctx.get("subagent"):
			self._in_subagent = ctx.get("session_id") or "subagent"
			return await self._ensure_subview(self._in_subagent)
		# control returned to the main thread: the active subagent is done
		if self._in_subagent is not None and self._active_subagent is not None:
			self._active_subagent.mark_done()
			self._active_subagent = None
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
		if at in ("prompt", "steer", "follow_up"):
			# user-origin / end-of-turn question: already echoed on submit or shown by
			# the ask_user prompt — don't double-render from the item stream
			return
		if at == "response":
			self._finish_current()
			await self._append(Markdown(content, classes="ai"))  # AI text as Markdown
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
				self._active_subagent = row
				await self._append(row)
				return
			# Same runner card can arrive more than once — reuse its panel, don't duplicate it.
			rid = ed.get("runner_id") or ""
			if rid and rid in self._card_panels:
				existing = self._card_panels[rid]
				self._current = existing
				self._container = existing if at in ("workflow", "scan") else None
				return
			self._finish_current()
			if at == "shell":
				# LLM-supplied description as the title; the command goes in the box
				kind, rname, command = "shell", desc, content
			elif at == "query":
				kind, rname, command = "query", desc or content, content
			else:
				kind, rname, command = at, desc or content or ed.get("name") or "", ""
			panel = RunnerPanel(kind, rname, command=command, runner_id=ed.get("runner_id", ""))
			if rid:
				self._card_panels[rid] = panel
			# the card's content is the runner name (== _source of its items). Used to
			# route a task's live output + buffered output (parallel batch), and to tell a
			# workflow's OWN notes (_source == workflow name) from its child tasks' items.
			# shell items carry _source = the command task's unique_name ("command"); set
			# it so a shell's error routes to its panel. Runners use the runner name.
			panel.source = "command" if at == "shell" else (content if at in ("task", "workflow", "scan") else "")
			await self._append(panel)
			self._current = panel
			# workflows/scans contain child tasks: nest their findings/output by source
			self._container = panel if at in ("workflow", "scan") else None
			self._flush_buffer(panel)
			self._set_status(f"running {kind} {rname or command}".strip())
		elif at == "shell_output":
			# a shell's stdout IS its result (no secator findings) — show it directly,
			# not hidden behind the command-click like a task's raw output
			if self._current is not None:
				self._current.add_output(content)
		elif at in _ACTION_VERBS:
			# AI action on a finding: a neutral "<Verb> <name>" row (same tone as a runner
			# header), no icon — icons are for secator findings, not AI actions.
			fd = (d.get("extra_data") or {}).get("finding") or {}
			name = fd.get("name") or fd.get("id") or fd.get("matched_at") or content
			verb = _ACTION_VERBS[at]
			if at == "add_finding":
				# the full finding is yielded right after and renders richly on its own,
				# so keep this a plain line (no duplicate)
				line = Text()
				line.append(f"{verb} ", style="bold #9aa3b8")
				line.append(str(name), style="#8a8fa3")
				await self._append(Static(line, classes="action"))
			else:
				# Exploited / Failed to exploit / Updated / … reference an existing finding
				# not shown elsewhere — make the row expandable to the vuln's rich output.
				renderable = finding_text(None, fd) if fd else None
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
			self._finish_current()
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

	session = opts.get("workspace") or opts.get("prompt", "ai") or "ai"
	app = AITUI(
		None, session=str(session)[:30], mode=opts.get("mode", "chat"),
		initial_prompt=opts.get("prompt", ""))

	def _feed(self, item):  # on_item hook: runs in the worker thread
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

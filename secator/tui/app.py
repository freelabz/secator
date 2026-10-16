"""Generic Textual app shell for secator TUIs.

``TUIApp`` is a reusable, frontend-agnostic base: it drives a runner's item stream
into collapsible runner panels, renders findings/info lines via each OutputType's own
``__rich__``, and provides the shared chrome — status spinner, input, prompts/steers,
subviews, and the lazy findings side panel. Domain frontends subclass it and override
two seams: ``_route_write`` (where an item is mounted) and ``_render_domain`` (handle
domain-specific item types). The AI frontend lives in ``secator.tui.ai``.

Textual is an OPTIONAL dependency — this module is only imported on the TUI path.
"""
from __future__ import annotations

import threading

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from secator.tui.render import finding_text, message_text
from secator.tui.widgets import (
	BackBar, BlockPanel, ChoicePrompt, Grip, PermissionPrompt, PromptInput, RunnerPanel)


class TUIApp(App):
	# No window chrome: transparent backgrounds so the user's terminal shows through,
	# no outer box, and the input has no side borders — just a top rule to separate it.
	CSS = """
	Screen {
		background: transparent;
		scrollbar-background: transparent; scrollbar-background-hover: transparent;
		scrollbar-background-active: transparent; scrollbar-color: #20262f;
		scrollbar-color-hover: #2b3245; scrollbar-color-active: #2b3245; scrollbar-size-vertical: 1;
	}
	#views { height: 1fr; }
	#convo, .subview { background: transparent; padding: 0 1; height: 1fr; }
	#backbar { height: 1; padding: 0 1; }
	#backbar:hover { text-style: bold; }
	.subview-title { color: #c2a0ff; margin: 0 0 1 0; }
	.subagent-row { height: 1; margin: 1 0; }
	.subagent-row:hover { text-style: bold; }
	/* the subagent's verdict/handback at the end of its view: red-outlined conclusion box */
	.handback-panel { border: round #c0392b; margin: 1 0; padding: 0 1; height: auto; background: transparent; }
	.handback-title { margin: 0 0 1 0; }
	.handback-usage { color: #6b7187; margin: 1 0 0 0; }
	.ai { color: #cdd6e4; }
	.user { color: #7fd1e0; margin: 1 0; }
	.err { color: #ff6b6b; }
	.action { margin: 1 0; }
	.note { margin: 1 0; }

	/* Claude-like runner entry: dim one-line header, arrow right after the text */
	.runner-panel { margin: 1 0; height: auto; }
	.runner-head { height: 1; width: auto; }
	.runner-head:hover { text-style: bold; }
	/* expanded content: a left rule (indent), not a box — stays integrated.
	   a little vertical breathing room above/below so it reads as relaxed, not cramped. */
	.runner-box {
		height: auto; margin: 1 0 1 1; padding: 0 0 0 1;
		border-left: solid #2b3245; background: transparent;
	}
	.runner-cmdwrap { height: auto; }
	.runner-cmd { color: #7b8296; margin: 0 0 1 0; }   /* command: dim text, no background */
	.runner-meta { margin: 0 0 1 0; }                  /* a query's result count + skip/limit/group */
	.runner-cmd:hover { text-style: bold; }            /* click to reveal the raw output */
	.runner-raw { height: auto; margin: 0 0 1 0; }     /* raw command output (hidden by default) */
	.runner-out { height: auto; }
	.out-line { color: #cdd6e4; }
	.out-raw { color: #9aa3b8; }

	/* follow-up / permission suggestion list */
	.choice { height: auto; margin: 1 0; }
	.choice-q { color: #e6c15a; margin: 0 0 1 0; }
	.choice-list { height: auto; max-height: 12; border: none; background: transparent; }
	/* multi-select dot (see ToggleButton glyph override in widgets.py): dim when off, cyan on */
	.choice-list > .selection-list--button { color: #3a4150; background: transparent; }
	.choice-list > .selection-list--button-highlighted { color: #556070; background: transparent; }
	.choice-list > .selection-list--button-selected { color: #7fd1e0; background: transparent; }
	.choice-list > .selection-list--button-selected-highlighted { color: #7fd1e0; background: transparent; }
	/* subtle highlight on the focused choice row (the default is too bright) */
	.choice-list > .option-list--option-highlighted { background: #1b2130; color: #cdd6e4; }
	.choice-list:focus > .option-list--option-highlighted { background: #20283a; color: #e6ecf5; }

	/* lazy findings side panel (ctrl+f); 1/3 width by default, drag the grip to resize */
	#findings-panel { dock: right; width: 34%; display: none; background: transparent; }
	#findings-grip { width: 1; height: 1fr; background: #2b3245; color: #6b7187; }
	#findings-grip:hover { background: #3d6fb4; }
	#findings-body { width: 1fr; padding: 0 1; }
	#findings-title { height: 1; color: #c2a0ff; margin: 0 0 1 0; }
	#findings-list { height: 1fr; background: transparent; border: none; padding: 0; }
	#findings-list > .option-list--option-highlighted { background: #171a24; }

	/* background-tasks side panel (ctrl+r): this session's runners grouped running/finished */
	#bgtasks-panel { dock: right; width: 36%; display: none; background: transparent; }
	#bgtasks-grip { width: 1; height: 1fr; background: #2b3245; color: #6b7187; }
	#bgtasks-grip:hover { background: #3d6fb4; }
	#bgtasks-body { width: 1fr; padding: 0 1; }
	#bgtasks-title { height: 1; color: #c2a0ff; margin: 0 0 1 0; }
	#bgtasks-list { height: 1fr; background: transparent; }
	.bg-section { color: #6b7187; margin: 1 0 0 0; }
	.bg-row { height: auto; }
	.bg-empty { color: #6b7187; }

	Markdown { background: transparent; margin: 0; padding: 0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	/* neutral, no background — just a lighter top rule to set off the chat box. grows with
	   the multi-line input (1 line by default, up to a few). */
	#input-box {
		border: none; border-top: solid #47516b; background: transparent; height: auto; padding: 1 0;
		border-title-align: right; border-title-color: #6b7187; border-title-background: transparent;
	}
	/* the choice box takes the input box's place while a choice ask is active — same top rule
	   so the delimiter doesn't move (hidden otherwise) */
	#choice-host {
		border: none; border-top: solid #47516b; background: transparent;
		height: auto; display: none; padding: 1 1 0 1;
		border-title-align: right; border-title-color: #6b7187; border-title-background: transparent;
	}
	.choice-box { height: auto; }
	.choice-hint { color: #6b7187; }
	/* the command/target a permission ask is about, shown above the Approve/Deny list */
	.perm-cmd { color: #7b8296; margin: 0 0 1 0; height: auto; }
	#input-caret { width: 3; height: 1; color: #7fd1e0; text-style: bold; content-align: center top; }
	/* layered field: the input and the placeholder occupy the same space; placeholder on top */
	#input-field { width: 1fr; height: auto; layers: field hint; }
	#prompt-input {
		layer: field; width: 1fr; height: auto; max-height: 8;
		border: none; background: transparent; color: #e6ecf5; padding: 0 1;
	}
	#prompt-input:focus { border: none; background: transparent; }
	/* TextArea paints the cursor's line + gutter with $boost (a dark bar) once you start
	   typing — keep them transparent so the input blends into the terminal background. */
	#prompt-input .text-area--cursor-line { background: transparent; }
	#prompt-input .text-area--cursor-gutter { background: transparent; }
	/* light cursor block (dark glyph under it) so the caret is visible on a dark terminal.
	   text-style: none kills the theme's default `reverse`, which would otherwise swap these
	   and render a near-black block (what made the cursor look black). */
	#prompt-input .text-area--cursor { background: #e6ecf5; color: #11141b; text-style: none; }
	#input-placeholder { layer: hint; width: 1fr; height: 1; padding: 0 1; }
	/* meta bar under the input: dangerous + mode on the left, context % on the right.
	   a top rule separates it from the input/choice box above (the "bottom delimiter"). */
	#meta-bar { height: auto; padding: 1 1 0 1; background: transparent;
		border: none; border-top: solid #47516b; }
	#meta-left { width: 1fr; height: 1; }
	#meta-right { width: auto; height: 1; content-align: right top; color: #6b7187; }
	"""
	BINDINGS = [
		("ctrl+c", "quit", "Quit"),
		# jump to the latest messages (a focused choice/permission list consumes `down`
		# first for navigation, so this only fires when not selecting)
		("down", "scroll_latest", "Scroll to latest"),
		("ctrl+o", "expand_all", "Expand/collapse all"),
		("ctrl+f", "toggle_findings", "Findings panel"),
		("ctrl+r", "toggle_bgtasks", "Background tasks"),
	]
	# full-screen, integrated: use the terminal's own background/palette, no command
	# palette, no footer chrome
	ansi_color = True
	ENABLE_COMMAND_PALETTE = False

	# AI modes the mode-cycle steps through (auto = let the runner detect/keep its mode).
	_MODE_CYCLE = ("auto", "scan", "chat", "exploit")

	def __init__(self, runner_builder=None, title="secator", subtitle="", initial_prompt="",
	             initial_dangerous=False, initial_mode="auto", session_name=""):
		super().__init__()
		self._runner_builder = runner_builder
		self._title = title
		self._subtitle = subtitle
		self._session_name = session_name or ""   # shown on the top delimiter; renamed via /name
		self._initial_prompt = initial_prompt or ""
		self._current: RunnerPanel | None = None
		self._container: RunnerPanel | None = None   # most-recent workflow/scan nesting parent
		self._containers: dict = {}   # runner_id -> live workflow/scan panel (parallel batch:
		#                               several stream at once, routed by item _context id)
		self._leaf_panels: dict = {}  # runner_id -> live leaf task/shell panel. A parallel batch
		#                               of same-tool tasks shares a _source, so items are routed
		#                               by their OWNING runner id (task_chunk_id) to avoid
		#                               cross-wiring both tasks' output into one panel.
		self._subviews: dict = {}   # secondary-view id -> VerticalScroll (hidden)
		self._write: VerticalScroll | None = None   # where incoming items are mounted
		self._steers: list[str] = []
		self._steers_lock = threading.Lock()
		self._pending_ask = None
		self._active_choice = None   # the live ChoicePrompt, so an input-box submit collapses it
		self._active_permission = None   # the live PermissionPrompt (Approve/Deny), in the input slot
		self._status_text = ""
		self._status_spinning = False
		self._spin_frame = 0
		self._findings_src = None   # (workspace_id, context, session_id) for lazy querying
		self._findings_loading = False
		self._findings_seen: set = set()   # finding _uuids already shown (incremental refresh)
		self._line_buffers: dict = {}      # source -> {cmd, lines} buffered until its card renders
		self._parent_source: str = ""      # the top-level runner's source (set by the item feed);
		#                                    its OWN notes/errors render top-level, not buffered
		self._shown_uuids: set = set()     # findings already rendered inline (skip dups, e.g. a
		#                                    live-streamed finding later re-read via query_workspace)
		# Startup race: the runner takes a few seconds to build (LLM/driver/system-prompt setup)
		# before it asks for the first prompt. Input typed in that window is held here and handed
		# to the first ask_user instead of being dropped into _steers. `-p` supplies the prompt,
		# so there's nothing to await.
		self._prefill: str = ""
		self._awaiting_first_prompt: bool = not bool(self._initial_prompt)
		# ---- meta bar (guardrail setting / mode / context %) ----
		# Live state the runner reports via tui_set_meta each turn; seeded from the CLI opts so
		# the bar is correct before the first LLM turn reports back.
		self._meta: dict = {
			"dangerous": bool(initial_dangerous),
			"mode": initial_mode or "auto",
			"ctx_pct": None,
		}
		# Pending user-requested control changes (Shift+Tab / Ctrl+T), drained by the
		# runner via tui_poll_control at its loop boundary and applied to the live run.
		self._control: dict = {}
		self._control_lock = threading.Lock()
		# Per-subagent latest {mode, ctx_pct} (from its token_usage items), for the read-only
		# meta bar shown while drilled into that subagent's view.
		self._subagent_meta: dict = {}
		self._viewing_subagent: str | None = None   # sid of the open subagent view, else None

	def compose(self) -> ComposeResult:
		# no top header — the bottom meta bar carries the session/mode state now
		yield BackBar(Text.from_markup("[#7fd1e0]← Back to conversation[/]"), id="backbar")
		yield Vertical(VerticalScroll(id="convo"), id="views")
		yield Static("", id="status")
		yield Horizontal(
			Grip("│", id="findings-grip"),
			Vertical(
				Static("Findings", id="findings-title"),
				OptionList(id="findings-list"),
				id="findings-body",
			),
			id="findings-panel",
		)
		# background-tasks overview (ctrl+r): the session's runners grouped running/finished
		yield Horizontal(
			Grip("│", id="bgtasks-grip"),
			Vertical(
				Static("Background tasks", id="bgtasks-title"),
				VerticalScroll(id="bgtasks-list"),
				id="bgtasks-body",
			),
			id="bgtasks-panel",
		)
		# While a choice ask is active the choice box REPLACES the input box in the same slot
		# (both carry the same top rule, so the delimiter stays put); Tab swaps the selection
		# into the input to add details. Only one of the two is ever visible.
		yield Vertical(id="choice-host")
		yield Horizontal(
			Static("❯", id="input-caret"),
			# a layered field: the multi-line input, with the placeholder overlaid on top of it
			# (shown only while empty — TextArea has no native placeholder)
			Vertical(
				PromptInput(id="prompt-input"),
				Static(
					Text.from_markup(
						"[#5b6070]Message, or steer a running runner…  (Enter to send · Alt+Enter: newline)[/]"),
					id="input-placeholder",
				),
				id="input-field",
			),
			id="input-box",
		)
		# meta bar: left = guardrail setting + current mode (cyclable via Shift+Tab /
		# Ctrl+T on the main conversation; read-only in a subagent drill-in);
		# right = % of the model context window used.
		yield Horizontal(
			Static("", id="meta-left"),
			Static("", id="meta-right"),
			id="meta-bar",
		)

	def on_mount(self) -> None:
		self.title = self._title
		self.sub_title = self._subtitle
		self.query_one("#backbar").display = False
		self._write = self.query_one("#convo", VerticalScroll)
		self.query_one("#prompt-input", PromptInput).focus()
		self._render_meta()
		self._set_session_name(self._session_name)
		self.set_interval(0.1, self._tick_spinner)    # animate the status spinner
		self.set_interval(3.0, self._tick_findings)   # auto-update the findings panel
		self.set_interval(1.0, self._tick_bgtasks)    # refresh the background-tasks panel
		if self._initial_prompt:
			# the -p prompt isn't typed into the input, so echo it once up front
			self.call_later(self._append, Static(
				Text.from_markup(f"[bold cyan]›[/] {escape(self._initial_prompt)}"), classes="user"))
		if self._runner_builder is not None:
			# The runner build (LLM/driver/system-prompt setup) blocks for a few seconds before
			# it produces anything or asks for the first prompt — show a spinner so the input
			# doesn't look dead. The runner's own status / first prompt replaces it.
			self._set_status("starting…")
			threading.Thread(target=self._consume, daemon=True).start()

	# worker: build + drive the runner. Items are rendered via the on_item hook the
	# builder wires in (the Task runner yields nothing to the iterator), so this loop
	# just pumps the generator to completion.
	def _consume(self) -> None:
		try:
			for _ in self._runner_builder():
				pass
		except Exception as e:  # noqa: BLE001
			self.call_from_thread(self._set_status, f"error: {e}", False)
		else:
			self.call_from_thread(self._set_status, "done", False)

	# ---- thread-safe entries called from the worker thread ----
	def tui_render(self, item) -> None:
		self.call_from_thread(self._render, item)

	# the child-runner on_line hook feeds the task's command + raw stdout (display-only)
	def tui_set_command(self, cmd: str, source: str = "", rid: str = "") -> None:
		self.call_from_thread(self._set_command, cmd, source, rid)

	def tui_render_line(self, line: str, source: str = "", rid: str = "") -> None:
		self.call_from_thread(self._render_line, line, source, rid)

	# a guardrail-denied action — shown as a collapsible "Blocked <desc>" entry
	def tui_render_block(self, description: str, reason: str = "", command: str = "", subagent=None) -> None:
		self.call_from_thread(self._render_block, description, reason, command, subagent)

	async def _render_block(self, description, reason="", command="", subagent=None) -> None:
		# route to the subagent's own view when the block happened inside a subagent,
		# else the main conversation (independent of the live write target)
		target = await self._ensure_subview(subagent) if subagent else self._convo()
		await target.mount(BlockPanel(description, reason, command))
		target.scroll_end(animate=False)

	# ---- runner output routing (by source so a parallel batch doesn't cross-wire) ----
	def _container_for(self, d: dict) -> "RunnerPanel | None":
		# Pick the workflow/scan panel a nested item belongs to by its context id. When a
		# batch runs two workflows/scans in parallel their item streams INTERLEAVE, so a
		# single "most-recent container" global would funnel the first runner's late notes/
		# findings into the second's panel. Each item carries its owning runner's id in
		# _context.workflow_id / _context.scan_id — route on that; fall back to the most
		# recent container for items with no matching id (single-container case, leaf notes).
		ctx = d.get("_context") or {}
		for key in ("workflow_id", "scan_id"):
			cid = ctx.get(key)
			if cid and cid in self._containers:
				return self._containers[cid]
		return self._container

	def _owning_id(self, d: dict) -> str:
		"""The id of the runner that produced this item (task_chunk_id, else task_id). Matches
		a leaf/container panel's runner_id so a batch of same-_source tasks routes correctly."""
		ctx = d.get("_context") or {}
		return ctx.get("task_chunk_id") or ctx.get("task_id") or ""

	def _leaf_for_item(self, d: dict) -> "RunnerPanel | None":
		"""The batch leaf task/shell panel this item belongs to, matched by owning runner id.
		Parallel tasks that share a tool name (_source) would otherwise cross-wire via the
		source/_current heuristic — the id disambiguates them."""
		rid = self._owning_id(d)
		return self._leaf_panels.get(rid) if rid else None

	async def _sink_for_source(self, source: str) -> "RunnerPanel | None":
		# Where a command runner's output lands. In a workflow/scan it's the child's
		# sub-panel. For a leaf it's the current panel ONLY if its source matches — in a
		# PARALLEL batch several tasks stream at once while the global _current points at
		# whichever finished first, so matching by source (tool name) avoids cross-wiring.
		if self._container is not None:
			return await self._container.subpanel(source)
		cur = self._current
		if cur is not None and (getattr(cur, "source", "") == source or getattr(cur, "kind", "") == "query"):
			# a leaf whose source matches, or a query panel (its results have task
			# sources, not the query's — they still belong to the query panel)
			return cur
		return None   # no panel yet (batch card renders on completion) -> buffer

	def _buffer(self, source: str) -> dict:
		return self._line_buffers.setdefault(
			source, {"cmd": "", "lines": [], "findings": [], "notes": [], "failed": False})

	async def _set_command(self, cmd: str, source: str = "", rid: str = "") -> None:
		if not cmd:
			return
		# an item that knows its owning runner id goes ONLY to that panel — or its OWN id
		# buffer until the card renders. Never fall through to source routing: a same-tool
		# sibling's card would otherwise capture it. Source routing is for id-less items.
		if rid:
			panel = self._leaf_panels.get(rid)
			if panel is not None:
				panel.set_command(cmd)
			else:
				self._buffer(rid)["cmd"] = cmd
			return
		sink = await self._sink_for_source(source)
		if sink is not None:
			sink.set_command(cmd)
		else:
			self._buffer(source)["cmd"] = cmd

	async def _render_line(self, line: str, source: str = "", rid: str = "") -> None:
		if not (isinstance(line, str) and line.strip()):
			return
		if rid:
			panel = self._leaf_panels.get(rid)
			if panel is not None:
				panel.add_raw(line)
			else:
				self._buffer(rid)["lines"].append(line)
			return
		sink = await self._sink_for_source(source)
		if sink is not None:
			sink.add_raw(line)
		else:
			self._buffer(source)["lines"].append(line)

	def _flush_buffer(self, panel: RunnerPanel) -> None:
		# attach command/output/findings/notes that streamed before this panel's card
		# rendered (parallel batch: items arrive during execution, cards on completion).
		# Items are keyed by owning runner id (same-tool tasks share a source); drain BOTH
		# the id buffer AND the source buffer, since id-less items for the same card (if any)
		# land in the source buffer.
		bufs = []
		if panel.runner_id:
			b = self._line_buffers.pop(panel.runner_id, None)
			if b:
				bufs.append(b)
		if panel.source:
			b = self._line_buffers.pop(panel.source, None)
			if b:
				bufs.append(b)
		for buf in bufs:
			if buf["cmd"]:
				panel.set_command(buf["cmd"])
			for ln in buf["lines"]:
				panel.add_raw(ln)
			for f in buf["findings"]:
				panel.add_finding(f)
			for n in buf["notes"]:
				panel.add_note(n)
			if buf.get("failed"):
				panel.mark_failed()   # a buffered error -> red cross once the card renders

	# ---- mounting + views ----
	def _convo(self) -> VerticalScroll:
		# the main conversation (prompts/questions always go here)
		return self.query_one("#convo", VerticalScroll)

	async def _append(self, widget) -> None:
		target = self._write or self._convo()
		await target.mount(widget)
		target.scroll_end(animate=False)

	async def _ensure_subview(self, sid: str) -> VerticalScroll:
		sv = self._subviews.get(sid)
		if sv is None:
			sv = VerticalScroll(classes="subview")
			sv.display = False
			self._subviews[sid] = sv
			await self.query_one("#views", Vertical).mount(sv)
		return sv

	def _open_subview(self, sid: str) -> None:
		sv = self._subviews.get(sid)
		if sv is None:
			return
		self._convo().display = False
		for s in self._subviews.values():
			s.display = False
		sv.display = True
		self.query_one("#backbar").display = True
		# A subview is a read-only drill-in (e.g. a subagent's own conversation) — there is
		# nothing to steer or answer there, so hide the input box to avoid implying otherwise.
		self.query_one("#input-box").display = False
		# the status line reflects the PARENT's live activity (e.g. "running task …") — hide it
		# here so a subagent's historical transcript doesn't look like it's still thinking.
		self.query_one("#status").display = False
		# the meta bar follows: show the subagent's read-only guardrail/mode/context
		self._viewing_subagent = sid
		self._render_meta()

	def _show_main(self) -> None:
		for s in self._subviews.values():
			s.display = False
		self._convo().display = True
		self.query_one("#backbar").display = False
		# Back on the main conversation: restore the input box and refocus it.
		self.query_one("#input-box").display = True
		self.query_one("#status").display = True   # the live status belongs to the main convo
		self.query_one("#prompt-input", PromptInput).focus()
		# restore the interactive (main-conversation) meta bar
		self._viewing_subagent = None
		self._render_meta()

	def _active_view(self) -> VerticalScroll:
		# the currently visible scroll (an open secondary view, else the main convo)
		for sv in self._subviews.values():
			if sv.display:
				return sv
		return self._convo()

	def action_scroll_latest(self) -> None:
		self._active_view().scroll_end(animate=False)

	def action_expand_all(self) -> None:
		# ctrl+o: expand every runner panel; if all are already expanded, collapse them
		panels = list(self.query(RunnerPanel))
		if not panels:
			return
		expand = any(p._collapsed for p in panels)
		for p in panels:
			p.set_collapsed(not expand)

	# ---- background-tasks panel (ctrl+r): live overview of this session's runners ----
	_BG_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

	def action_toggle_bgtasks(self) -> None:
		panel = self.query_one("#bgtasks-panel")
		panel.display = not panel.display
		if panel.display:
			# both side panels dock right — only show one at a time
			self.query_one("#findings-panel").display = False
			self._bg_sig = None   # force a rebuild on open
			self.call_later(self._render_bgtasks)

	@staticmethod
	def _bg_structure_sig(panels) -> tuple:
		# the set + lifecycle states (NOT the spinner frame) — a rebuild is only needed when
		# a runner is added/removed or flips done/failed; the spinner animates in place.
		return tuple((id(p), p.done, getattr(p, "failed", False)) for p in panels)

	def _bg_row_text(self, glyph, color, rname, kind, config) -> Text:
		t = Text()
		t.append(f"{glyph} ", style=f"bold {color}")
		t.append(rname or kind, style="#cdd6e4")
		t.append(f" ({kind}" + (f" • {config}" if config else "") + ")", style="#6b7187")
		return t

	def _tick_bgtasks(self) -> None:
		# Called ~1s. If the runner set/states changed, schedule a rebuild; otherwise just
		# advance the spinner glyph on the running rows IN PLACE (no remove/mount, no scroll
		# thrash — addresses the "rebuild every tick" + "remove_children isn't synchronous" bits).
		try:
			if not self.query_one("#bgtasks-panel").display:
				return
		except Exception:  # noqa: BLE001 - panel gone during teardown
			return
		if self._bg_structure_sig(self._bg_rows()) != getattr(self, "_bg_sig", None):
			self.call_later(self._render_bgtasks)
			return
		self._bg_frame = getattr(self, "_bg_frame", 0) + 1
		spin = self._BG_SPIN[self._bg_frame % len(self._BG_SPIN)]
		for st, rname, kind, config in getattr(self, "_bg_running_rows", []):
			try:
				st.update(self._bg_row_text(spin, "#e0882e", rname, kind, config))
			except Exception:  # noqa: BLE001 - row removed
				pass

	def _bg_rows(self) -> list:
		"""Top-level runner cards in the conversation (the dispatched actions), in order."""
		return [w for w in self._convo().children if isinstance(w, RunnerPanel)]

	async def _render_bgtasks(self) -> None:
		# Full rebuild — only when the structure changed (see _bg_structure_sig). Async so the
		# old rows are AWAITED out before mounting the new ones (remove_children is not sync).
		panels = self._bg_rows()
		sig = self._bg_structure_sig(panels)
		if sig == getattr(self, "_bg_sig", None):
			return
		self._bg_sig = sig
		self._bg_running_rows = []   # (Static, rname, kind, config) for in-place spinner ticks
		body = self.query_one("#bgtasks-list", VerticalScroll)
		await body.remove_children()
		if not panels:
			await body.mount(Static(
				Text.from_markup("[#6b7187]No background tasks yet.[/]"), classes="bg-empty"))
			return
		spin = self._BG_SPIN[getattr(self, "_bg_frame", 0) % len(self._BG_SPIN)]
		for label, group in (("Running", [p for p in panels if not p.done]),
		                     ("Finished", [p for p in panels if p.done])):
			if not group:
				continue
			await body.mount(Static(
				Text.from_markup(f"[#8a8fa3 b]{label}[/] [#4a5163]({len(group)})[/]"), classes="bg-section"))
			for p in group:
				config = getattr(p, "config_name", None)
				if not p.done:
					row = Static(self._bg_row_text(spin, "#e0882e", p.rname, p.kind, config), classes="bg-row")
					self._bg_running_rows.append((row, p.rname, p.kind, config))
				else:
					glyph, color = ("✗", "#ff6b6b") if getattr(p, "failed", False) else ("✓", "#3fb950")
					row = Static(self._bg_row_text(glyph, color, p.rname, p.kind, config), classes="bg-row")
				await body.mount(row)

	# ---- findings side panel (lazy, queried by _context.session_id) ----
	def set_findings_source(self, workspace_id, context, session_id) -> None:
		# called from the worker thread when the runner resolves its session
		self._findings_src = (workspace_id, dict(context or {}), session_id)

	def action_toggle_findings(self) -> None:
		panel = self.query_one("#findings-panel")
		panel.display = not panel.display
		if panel.display:
			self.query_one("#bgtasks-panel").display = False   # only one right-docked panel
			if self._findings_src is None:
				self._set_findings_title(None, note="no findings source yet")
			else:
				self._refresh_findings()

	def _refresh_findings(self) -> None:
		# kick an incremental load (adds only unseen findings) off the UI thread
		if self._findings_src is None or self._findings_loading:
			return
		self._findings_loading = True
		threading.Thread(target=self._load_findings, daemon=True).start()

	def _tick_findings(self) -> None:
		# auto-update while the panel is open (new findings appear as tasks run)
		try:
			if self.query_one("#findings-panel").display:
				self._refresh_findings()
		except Exception:  # noqa: BLE001
			pass

	def _set_findings_title(self, total, note: str = "") -> None:
		label = "Findings" if total is None else f"Findings ({total})"
		if note:
			label += f"  [dim]{note}[/]"
		self.query_one("#findings-title", Static).update(Text.from_markup(label))

	def _add_finding_options(self, options) -> None:
		self.query_one("#findings-list", OptionList).add_options(options)

	def _load_findings(self) -> None:
		# runs off the UI thread: build a workspace-scoped engine and stream findings
		# for this session in batches (never materializes all N at once).
		wsid, context, sid = self._findings_src
		try:
			from secator.query import QueryEngine
			from secator.output_types import FINDING_TYPES
			engine = QueryEngine(wsid or "", context=dict(context))
			# only real findings: exclude the ai/conversation type (targets, info/warning/
			# error, stat and other execution types aren't findings and never match)
			types = [c.get_name() for c in FINDING_TYPES if c.get_name() != "ai"]
			query = {"_context.session_id": sid, "_type": {"$in": types}}
			total = engine.count(query)
			self.call_from_thread(self._set_findings_title, total)
			n = len(self._findings_seen)
			for batch in engine.iterate(query, batch_size=200):
				opts = []
				for d in batch:
					uid = d.get("_uuid")
					if uid is not None and uid in self._findings_seen:
						continue   # incremental: only add findings we haven't shown yet
					if uid is not None:
						self._findings_seen.add(uid)
					opts.append(Option(finding_text(None, d)))
					n += 1
				if opts:
					self.call_from_thread(self._add_finding_options, opts)
				if n >= 5000:   # safety cap on mounted rows
					self.call_from_thread(self._set_findings_title, total, note=f"showing first {n}")
					break
		except Exception as e:  # noqa: BLE001
			self.call_from_thread(self._set_findings_title, None, note=f"error: {e}")
		finally:
			self._findings_loading = False

	# ---- status spinner ----
	_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

	def _set_status(self, text: str, spinning: bool = True) -> None:
		self._status_text = text or ""
		self._status_spinning = bool(spinning) and bool(text)
		s = self.query_one("#status", Static)
		if not text:
			s.update("")
		elif not spinning:
			s.update(Text.from_markup(f"[green]✓[/] [gold3]{escape(text)}[/]"))
		else:
			# the interval timer animates the glyph; render the first frame now
			s.update(Text.from_markup(f"[gold3]{self._SPIN[self._spin_frame]} {escape(text)}[/]"))

	def _tick_spinner(self) -> None:
		if not self._status_spinning or not self._status_text:
			return
		self._spin_frame = (self._spin_frame + 1) % len(self._SPIN)
		try:
			self.query_one("#status", Static).update(
				Text.from_markup(f"[gold3]{self._SPIN[self._spin_frame]} {escape(self._status_text)}[/]"))
		except Exception:  # noqa: BLE001 - the status node may be gone during teardown
			pass

	# ---- session name (shown on the top delimiter, renamed via /name) ----
	def _set_session_name(self, name: str) -> None:
		"""Show the (cropped) conversation name on the far right of the top delimiter."""
		self._session_name = name or ""
		label = self._session_name
		if len(label) > 32:
			label = label[:31] + "…"
		for wid in ("#input-box", "#choice-host"):
			try:
				self.query_one(wid).border_title = label
			except Exception:  # noqa: BLE001 - not composed yet
				pass

	def tui_set_session_name(self, name: str) -> None:
		"""Thread-safe: the runner reports the resolved session name (e.g. after it loads)."""
		self.call_from_thread(self._set_session_name, name)

	# ---- meta bar (guardrail setting / mode / context %) ----
	@staticmethod
	def _pct_text(pct) -> str:
		if pct is None:
			return "[#6b7187]— context[/]"
		pct = max(0, min(999, int(round(pct))))
		# color-code fullness: dim under half, amber past half, red when nearly full
		color = "#6b7187" if pct < 50 else ("#d7a93b" if pct < 85 else "#ff6b6b")
		return f"[{color}]{pct}% context[/]"

	def _render_meta(self) -> None:
		"""Redraw the meta bar. Interactive (cyclable) on the main conversation; read-only
		while drilled into a subagent view (its mode/guardrails can't be changed)."""
		try:
			left = self.query_one("#meta-left", Static)
			right = self.query_one("#meta-right", Static)
		except Exception:  # noqa: BLE001 - not composed yet
			return
		sid = self._viewing_subagent
		if sid is not None:
			# read-only subagent view: a spawned runner is never dangerous (defense in depth),
			# and its mode/context come from its own token_usage reports.
			sm = self._subagent_meta.get(sid, {})
			mode = sm.get("mode") or self._meta.get("mode") or "auto"
			danger = "[#e0b050]▶▶ guardrails enforced[/]"
			mode_seg = f"[#6b7187]mode:[/] [#7fd1e0]{escape(mode)}[/]"
			left.update(Text.from_markup(f"{danger}   [#3a4150]·[/]   {mode_seg}"))
			right.update(Text.from_markup(self._pct_text(sm.get("ctx_pct"))))
			return
		m = self._meta
		if m.get("dangerous"):
			danger = "[#ff6b6b]▶▶ bypass guardrails[/] [#5b6070](shift+tab)[/]"
		else:
			danger = "[#e0b050]▶▶ guardrails enforced[/] [#5b6070](shift+tab)[/]"
		mode = m.get("mode") or "auto"
		mode_seg = f"[#6b7187]mode:[/] [#7fd1e0]{escape(mode)}[/] [#5b6070](ctrl+t)[/]"
		left.update(Text.from_markup(f"{danger}   [#3a4150]·[/]   {mode_seg}"))
		right.update(Text.from_markup(self._pct_text(m.get("ctx_pct"))))

	def tui_set_meta(self, dangerous=None, mode=None, mode_is_auto=None, ctx_pct=None,
	                 is_subagent=False, sid=None) -> None:
		"""Thread-safe: the runner reports its live guardrail/mode/context state each turn."""
		self.call_from_thread(self._set_meta, dangerous, mode, mode_is_auto, ctx_pct, is_subagent, sid)

	def _set_meta(self, dangerous, mode, mode_is_auto, ctx_pct, is_subagent, sid) -> None:
		if is_subagent and sid:
			sm = self._subagent_meta.setdefault(sid, {})
			if mode is not None:
				sm["mode"] = "auto" if mode_is_auto else mode
			if ctx_pct is not None:
				sm["ctx_pct"] = ctx_pct
		else:
			# Don't clobber an optimistic value the user just set that's still queued in
			# _control (the runner polls control, THEN reports meta a line later — reporting
			# the pre-toggle state would flip the bar back until the next turn).
			with self._control_lock:
				pending = dict(self._control)
			if dangerous is not None and "dangerous" not in pending:
				self._meta["dangerous"] = bool(dangerous)
			if mode is not None and "mode" not in pending:
				self._meta["mode"] = "auto" if mode_is_auto else (mode or "auto")
			if ctx_pct is not None:
				self._meta["ctx_pct"] = ctx_pct
		self._render_meta()

	def tui_poll_control(self) -> dict:
		"""Called by the runner at its loop boundary: drain pending user control changes
		(guardrail toggle / mode switch) so it can apply them to the live run."""
		with self._control_lock:
			out, self._control = self._control, {}
		return out

	def on_prompt_input_cycle_dangerous(self, event) -> None:
		# Shift+Tab: flip the guardrail setting. Optimistic UI + a queued control change the
		# runner applies at its next loop boundary (and confirms via tui_set_meta).
		new = not self._meta.get("dangerous")
		self._meta["dangerous"] = new
		with self._control_lock:
			self._control["dangerous"] = new
		self._render_meta()

	def on_prompt_input_cycle_mode(self, event) -> None:
		# Ctrl+T: step through auto -> scan -> chat -> exploit -> auto.
		cur = self._meta.get("mode") or "auto"
		try:
			nxt = self._MODE_CYCLE[(self._MODE_CYCLE.index(cur) + 1) % len(self._MODE_CYCLE)]
		except ValueError:
			nxt = self._MODE_CYCLE[0]
		self._meta["mode"] = nxt
		with self._control_lock:
			self._control["mode"] = nxt
		self._render_meta()

	# ---- item rendering (generic) ----
	async def _route_write(self, d: dict) -> VerticalScroll:
		"""Return the scroll an item should mount into. Base: the main convo. A frontend
		can override to route items to a secondary view (e.g. a subagent transcript)."""
		return self._convo()

	async def _render_domain(self, d: dict) -> bool:
		"""Handle a frontend-specific item type. Return True if handled (base: no)."""
		return False

	def _should_skip_finding(self, d: dict) -> bool:
		"""Frontend hook: True to suppress rendering this finding (base: never)."""
		return False

	async def _render(self, item) -> None:
		d = item.toDict() if hasattr(item, "toDict") else dict(item)
		self._write = await self._route_write(d)
		if await self._render_domain(d):
			return
		t = d.get("_type")
		if t in ("info", "warning", "error"):
			renderable = message_text(item, d)
			src = d.get("_source") or ""
			# The parent (ai) task's OWN note/error must show in the conversation — checked
			# FIRST, before any container/sink route. No card ever renders with the parent's
			# source, so routing it to a sink (e.g. a query panel, which _sink_for_source
			# matches for ANY source) or buffering it would hide it forever (e.g. a model
			# NotFoundError showing nothing).
			if src and src == self._parent_source:
				await self._append(Static(renderable, classes="err" if t == "error" else "ai"))
				return
			is_err = t == "error"   # an error flips the runner's status icon to a red cross
			container = self._container_for(d)
			if container is not None:
				# child-task note (e.g. "XML results saved") nests in that task's sub-panel;
				# a workflow-level note (_source == the workflow) stays on the container.
				if src and src != container.source:
					panel = await container.subpanel(src)
				else:
					panel = container
				panel.add_note(renderable)
				if is_err:
					panel.mark_failed()
				return
			# A leaf note/error: route by the OWNING runner id FIRST (parallel same-tool batch
			# tasks share a _source, so source routing alone would mark the WRONG panel failed).
			# Mirrors the finding routing below. Id-less items fall through to source routing.
			oid = self._owning_id(d)
			if oid:
				leaf = self._leaf_panels.get(oid)
				if leaf is not None:
					leaf.add_note(renderable)
					if is_err:
						leaf.mark_failed()
				else:
					buf = self._buffer(oid)
					buf["notes"].append(renderable)   # batch: card not yet rendered
					if is_err:
						buf["failed"] = True
				return
			sink = await self._sink_for_source(src)
			if sink is not None:
				sink.add_note(renderable)
				if is_err:
					sink.mark_failed()
			elif src:
				buf = self._buffer(src)
				buf["notes"].append(renderable)   # batch: card not yet rendered
				if is_err:
					buf["failed"] = True
			elif self._current is not None:
				self._current.add_note(renderable)              # source-less leaf note/error
				if is_err:
					self._current.mark_failed()
			else:
				await self._append(Static(renderable, classes="ai"))
			return
		if t in ("progress", "stat", "state", "target"):  # execution / plumbing types
			return
		# frontend hook: a finding already surfaced another way (e.g. an AI add_finding row
		# that renders it expandable) is suppressed here so it isn't shown twice.
		if self._should_skip_finding(d):
			return
		# dedup: a finding can arrive live (child on_item display hook) and again when the
		# AI re-reads it via query_workspace — only render it once. Guard on a TRUTHY uuid
		# (an unpersisted finding has _uuid="" — never treat those as the same finding).
		uid = d.get("_uuid")
		if uid:
			if uid in self._shown_uuids:
				return
			self._shown_uuids.add(uid)
		# a finding → render with its own __rich__ (secator-identical). Inside a workflow/
		# scan it nests under the child task's sub-panel (by _source); a single task /
		# query panel gets it directly; in a parallel batch it's buffered by _source until
		# that task's card renders (otherwise it would cross-wire to a stale _current).
		renderable = finding_text(item, d)
		src = d.get("_source") or ""
		container = self._container_for(d)
		if container is not None:
			sp = await container.subpanel(src or "results")
			sp.add_finding(renderable)
			container.bump()
			return
		# a parallel batch of same-tool tasks shares a _source — route by the OWNING runner id
		# so each task's findings land on its own card. An item that knows its id goes ONLY to
		# that panel (or its id buffer until the card renders); it must NOT fall through to
		# source routing, where a same-tool sibling's card would capture it.
		oid = self._owning_id(d)
		if oid:
			leaf = self._leaf_panels.get(oid)
			if leaf is not None:
				leaf.add_finding(renderable)
			else:
				self._buffer(oid)["findings"].append(renderable)
			return
		sink = await self._sink_for_source(src)
		if sink is not None:
			sink.add_finding(renderable)
		elif src:
			self._buffer(src)["findings"].append(renderable)
		else:
			await self._append(Static(renderable, classes="out-line"))

	def _start_runner(self, panel: RunnerPanel, is_container: bool) -> None:
		# A new runner card is rendering. Finish the previous LEAF so sequential tasks still
		# flip "Running"->"Ran" as the next starts — but DON'T finish live containers: in a
		# parallel batch several workflows/scans stream at once and are finished together at
		# the turn boundary (_finish_current). Register a container so its interleaved child
		# items route to it by id (see _container_for).
		cur = self._current
		if cur is not None and cur not in self._containers.values():
			cur.finish()
		self._current = panel
		if is_container:
			self._container = panel
			self._containers[panel.runner_id or str(id(panel))] = panel
		else:
			self._container = None
			if panel.runner_id:
				self._leaf_panels[panel.runner_id] = panel

	def _finish_current(self) -> None:
		# turn boundary (response/stopped/subagent spawn): finish the current leaf AND every
		# live container, then clear the registry for the next turn.
		if self._current is not None:
			self._current.finish()
		for c in self._containers.values():
			c.finish()
		self._current = None
		self._container = None
		self._containers = {}

	# ---- input / prompts / steers ----
	def _update_placeholder(self) -> None:
		# the overlaid placeholder is shown only while the input is empty AND unfocused — so it
		# doesn't sit on top of (and hide) the cursor once the input itself is focused. Driven by
		# the PromptInput's own focus/blur/change (NOT app-wide descendant-focus events, which
		# fired on every focus change in the app and interfered with click-to-expand on runners).
		try:
			ta = self.query_one("#prompt-input", PromptInput)
			self.query_one("#input-placeholder").display = (not ta.text) and (not ta.has_focus)
		except Exception:  # noqa: BLE001
			pass

	def on_text_area_changed(self, event) -> None:
		self._update_placeholder()

	def on_click(self, event) -> None:
		# A click anywhere in the input box focuses the input. Needed because the placeholder
		# overlay (on the `hint` layer, above the input) swallows the click while the box is
		# empty, so the click never reaches the TextArea. Scoped to #input-box, so clicks on
		# runner lines / choices are unaffected.
		node = getattr(event, "widget", None)
		while node is not None:
			if getattr(node, "id", None) == "input-box":
				try:
					self.query_one("#prompt-input", PromptInput).focus()
				except Exception:  # noqa: BLE001
					pass
				return
			node = node.parent

	async def on_prompt_input_submitted(self, event: PromptInput.Submitted) -> None:
		text = event.value.strip()
		try:
			self.query_one("#prompt-input", PromptInput).text = ""
		except Exception:  # noqa: BLE001
			pass
		if not text:
			return
		# `/name <name>` renames the conversation (shown on the top delimiter) instead of being
		# sent to the agent. It's a client command — don't echo it as a prompt or steer.
		if text.startswith("/name ") or text == "/name":
			await self._handle_name_command(text)
			return
		await self._append(Static(Text.from_markup(f"[bold cyan]›[/] {escape(text)}"), classes="user"))
		pend = self._pending_ask
		if pend is not None:
			ev, holder, choices, ptype = pend
			cp = self._active_choice
			# a value an active choice list put in the input is LITERAL — don't reinterpret a
			# numeric choice (e.g. choices=["2","1"], input "2") as a 1-based index into choices
			answer = text if (cp is not None and text in choices) else self._resolve_answer(text, choices, ptype)
			if cp is not None:   # restore the normal input row (the choice box took its slot)
				self._restore_input()
			self._resolve_pending(answer)
			return
		# Typed before the runner finished starting up and asked for the first prompt — hold it
		# (the first ask_user consumes it). Without this it would leak into _steers and be lost
		# as the initial prompt, forcing the user to type it again.
		if self._awaiting_first_prompt and not self._prefill:
			self._prefill = text
			return
		with self._steers_lock:
			self._steers.append(text)

	async def _handle_name_command(self, text: str) -> None:
		"""`/name <name>`: rename the conversation. Updates the top-delimiter label now and
		queues the rename for the runner to persist (it stamps every item with the name)."""
		name = text[len("/name "):].strip() if text != "/name" else ""
		if not name:
			await self._append(Static(
				Text.from_markup("[#6b7187]usage: /name <conversation name>[/]"), classes="note"))
			return
		self._set_session_name(name)
		with self._control_lock:
			self._control["session_name"] = name
		await self._append(Static(
			Text.from_markup(f"[#6b7187]↻ renamed conversation to [b]{escape(name)}[/][/]"), classes="note"))

	# ---- choice box (lives in the input slot while a choice ask is active) ----
	def _show_choices(self, choices, multiple) -> None:
		"""Replace the input row with a choice box (same slot) until the user acts on it."""
		host = self.query_one("#choice-host", Vertical)
		host.remove_children()
		self._active_choice = ChoicePrompt(choices, multiple, self._resolve_choice, self._choice_to_input)
		host.mount(self._active_choice)
		self.query_one("#input-box").display = False
		host.display = True
		# focus the list once the box is laid out, so the keyboard drives it immediately
		self.call_after_refresh(self._active_choice.focus_list)

	def _resolve_choice(self, value) -> None:
		"""A choice sent directly (Enter on an option / multi-confirm): echo, restore, resolve."""
		if self._pending_ask is None:
			return
		self._echo_user(value)
		self._restore_input()
		self._resolve_pending(value)

	def _show_permission(self, question, command) -> None:
		"""Replace the input row with an Approve/Deny box (same slot as the choice box)."""
		host = self.query_one("#choice-host", Vertical)
		host.remove_children()
		self._active_permission = PermissionPrompt(question, self._resolve_permission, command=command)
		host.mount(self._active_permission)
		self.query_one("#input-box").display = False
		host.display = True

	def _resolve_permission(self, value) -> None:
		"""An Approve/Approve all/Deny selection: restore the input row and unblock the worker."""
		if self._pending_ask is None:
			return
		self._active_permission = None
		self._restore_input()
		self._resolve_pending(value)

	def _choice_to_input(self, text) -> None:
		"""Tab: hand the current selection to the input box so the user can add more details."""
		try:
			inp = self.query_one("#prompt-input", PromptInput)
		except Exception:  # noqa: BLE001
			return
		inp.text = text
		inp.move_cursor(inp.document.end)
		self.query_one("#choice-host").display = False
		self.query_one("#input-box").display = True
		inp.focus()

	def _back_to_choices(self) -> None:
		"""Esc from the input box (while a choice ask is active): return to the choice box."""
		if self._active_choice is None:
			return
		self.query_one("#input-box").display = False
		self.query_one("#choice-host").display = True
		self._active_choice.focus_list()

	def _restore_input(self) -> None:
		self.query_one("#choice-host", Vertical).remove_children()
		self.query_one("#choice-host").display = False
		self.query_one("#input-box").display = True

	def _echo_user(self, text) -> None:
		self._convo().mount(Static(Text.from_markup(f"[bold cyan]›[/] {escape(text)}"), classes="user"))
		self._convo().scroll_end(animate=False)

	def on_key(self, event) -> None:
		# Esc in the input box while a choice ask is active returns to the choice box (the input
		# row is only visible in that state after the user pressed Tab).
		if event.key == "escape" and self._active_choice is not None:
			try:
				if not self.query_one("#choice-host").display:
					event.stop()
					event.prevent_default()
					self._back_to_choices()
			except Exception:  # noqa: BLE001
				pass

	def _resolve_pending(self, value) -> None:
		"""Unblock the worker waiting in tui_ask_user with `value`."""
		pend = self._pending_ask
		if pend is None:
			return
		ev, holder, choices, ptype = pend
		holder["value"] = value
		self._pending_ask = None
		self._active_choice = None
		self._set_status("", False)
		ev.set()
		try:
			self.query_one("#prompt-input", PromptInput).focus()
		except Exception:  # noqa: BLE001
			pass

	@staticmethod
	def _resolve_answer(text, choices, ptype):
		if ptype == "permission":
			t = text.strip().lower()
			if t in ("a", "allow", "y", "yes"):
				return "allow"
			if t in ("aa", "allow_all", "all"):
				return "allow_all"
			return "deny"
		if choices and text.isdigit():
			i = int(text) - 1
			if 0 <= i < len(choices):
				return choices[i]
		return text

	# thread-safe hooks called by the interactivity backend / maybe_status
	def tui_set_status(self, text: str) -> None:
		self.call_from_thread(self._set_status, text, True)

	def tui_clear_status(self) -> None:
		self.call_from_thread(self._set_status, "", False)

	def tui_poll_steers(self):
		with self._steers_lock:
			out, self._steers = self._steers, []
		return out

	def tui_ask_user(self, question, choices, prompt_type="stopped", multiple=False, command="", **context):
		ev = threading.Event()
		holder: dict = {}
		self.call_from_thread(
			self._show_prompt, question, (ev, holder, list(choices or []), prompt_type), bool(multiple),
			command or "")
		ev.wait()
		return {"answer": holder.get("value")}

	def _show_prompt(self, question, pending, multiple=False, command="") -> None:
		self._pending_ask = pending
		self._set_status("", False)   # nothing is running while we wait for the user
		choices, ptype = pending[2], pending[3]
		# First ask after startup: if the user already typed a prompt while the runner was
		# building, answer with it immediately instead of waiting (and stop holding prefill).
		if self._awaiting_first_prompt:
			self._awaiting_first_prompt = False
			if self._prefill:
				prefill, self._prefill = self._prefill, ""
				self._resolve_pending(self._resolve_answer(prefill, choices, ptype))
				return
		if ptype == "permission":
			# Approve / Approve all / Deny — REPLACES the input box (same slot as the choice
			# box), showing the command/target that needs approval so it isn't decided blind.
			self._show_permission(question, command)
		elif choices:
			# the choice box REPLACES the input row (same slot) until the user acts on it
			self._show_choices(choices, multiple)
		else:
			# a plain end-of-turn follow-up: no "What's next?" / "waiting" noise — the
			# focused input is enough. Just make sure it's focused.
			try:
				self.query_one("#prompt-input", PromptInput).focus()
			except Exception:  # noqa: BLE001
				pass

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
from textual.widgets import Header, Input, OptionList, Static
from textual.widgets.option_list import Option

from secator.tui.render import finding_text, message_text
from secator.tui.widgets import BackBar, BlockPanel, ChoicePrompt, Grip, PermissionPrompt, RunnerPanel


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
	.subagent-row { height: 1; }
	.subagent-row:hover { text-style: bold; }
	.ai { color: #cdd6e4; }
	.user { color: #7fd1e0; margin: 1 0; }
	.err { color: #ff6b6b; }
	.action { margin: 1 0; }

	/* Claude-like runner entry: dim one-line header, arrow right after the text */
	.runner-panel { margin: 1 0; height: auto; }
	.runner-head { height: 1; width: auto; }
	.runner-head:hover { text-style: bold; }
	/* expanded content: a left rule (indent), not a box — stays integrated */
	.runner-box {
		height: auto; margin: 0 0 0 1; padding: 0 0 0 1;
		border-left: solid #2b3245; background: transparent;
	}
	.runner-cmdwrap { height: auto; }
	.runner-cmd { color: #7b8296; margin: 0 0 1 0; }   /* command: dim text, no background */
	.runner-cmd:hover { text-style: bold; }            /* click to reveal the raw output */
	.runner-raw { height: auto; margin: 0 0 1 0; }     /* raw command output (hidden by default) */
	.runner-out { height: auto; }
	.out-line { color: #cdd6e4; }
	.out-raw { color: #9aa3b8; }

	/* follow-up / permission suggestion list */
	.choice { height: auto; margin: 1 0; }
	.choice-q { color: #e6c15a; margin: 0 0 1 0; }
	.choice-list { height: auto; max-height: 12; border: none; background: transparent; }
	.choice-summary { height: 1; }
	.choice-summary:hover { text-style: bold; }
	.choice-body { height: auto; }

	/* lazy findings side panel (ctrl+f); 1/3 width by default, drag the grip to resize */
	#findings-panel { dock: right; width: 34%; display: none; background: transparent; }
	#findings-grip { width: 1; height: 1fr; background: #2b3245; color: #6b7187; }
	#findings-grip:hover { background: #3d6fb4; }
	#findings-body { width: 1fr; padding: 0 1; }
	#findings-title { height: 1; color: #c2a0ff; margin: 0 0 1 0; }
	#findings-list { height: 1fr; background: transparent; border: none; padding: 0; }
	#findings-list > .option-list--option-highlighted { background: #171a24; }

	Markdown { background: transparent; margin: 0; padding: 0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	/* neutral, no background — just a lighter top rule to set off the chat box */
	#input-box {
		border: none; border-top: solid #47516b; background: transparent; height: 3; padding: 0;
	}
	#input-caret { width: 3; height: 1fr; color: #7fd1e0; text-style: bold; content-align: center middle; }
	#input-box Input { width: 1fr; border: none; background: transparent; color: #e6ecf5; padding: 0 1; height: 1fr; }
	#input-box Input:focus { border: none; background: transparent; }
	#input-box Input > .input--cursor { color: #0b0e14; background: #e6ecf5; }
	Header { background: transparent; color: #cdd6e4; }
	"""
	BINDINGS = [
		("ctrl+c", "quit", "Quit"),
		# jump to the latest messages (a focused choice/permission list consumes `down`
		# first for navigation, so this only fires when not selecting)
		("down", "scroll_latest", "Scroll to latest"),
		("ctrl+o", "expand_all", "Expand/collapse all"),
		("ctrl+f", "toggle_findings", "Findings panel"),
	]
	# full-screen, integrated: use the terminal's own background/palette, no command
	# palette, no footer chrome
	ansi_color = True
	ENABLE_COMMAND_PALETTE = False

	def __init__(self, runner_builder=None, title="secator", subtitle="", initial_prompt=""):
		super().__init__()
		self._runner_builder = runner_builder
		self._title = title
		self._subtitle = subtitle
		self._initial_prompt = initial_prompt or ""
		self._current: RunnerPanel | None = None
		self._container: RunnerPanel | None = None   # active workflow/scan nesting parent
		self._subviews: dict = {}   # secondary-view id -> VerticalScroll (hidden)
		self._write: VerticalScroll | None = None   # where incoming items are mounted
		self._steers: list[str] = []
		self._steers_lock = threading.Lock()
		self._pending_ask = None
		self._status_text = ""
		self._status_spinning = False
		self._spin_frame = 0
		self._findings_src = None   # (workspace_id, context, session_id) for lazy querying
		self._findings_loading = False
		self._findings_seen: set = set()   # finding _uuids already shown (incremental refresh)
		self._line_buffers: dict = {}      # source -> {cmd, lines} buffered until its card renders
		self._shown_uuids: set = set()     # findings already rendered inline (skip dups, e.g. a
		#                                    live-streamed finding later re-read via query_workspace)

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
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
		yield Horizontal(
			Static("❯", id="input-caret"),
			Input(placeholder="Message, or steer a running runner…  (Enter to send)"),
			id="input-box",
		)

	def on_mount(self) -> None:
		self.title = self._title
		self.sub_title = self._subtitle
		self.query_one("#backbar").display = False
		self._write = self.query_one("#convo", VerticalScroll)
		self.query_one("#input-box Input", Input).focus()
		self.set_interval(0.1, self._tick_spinner)    # animate the status spinner
		self.set_interval(3.0, self._tick_findings)   # auto-update the findings panel
		if self._initial_prompt:
			# the -p prompt isn't typed into the input, so echo it once up front
			self.call_later(self._append, Static(
				Text.from_markup(f"[bold cyan]›[/] {escape(self._initial_prompt)}"), classes="user"))
		if self._runner_builder is not None:
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
	def tui_set_command(self, cmd: str, source: str = "") -> None:
		self.call_from_thread(self._set_command, cmd, source)

	def tui_render_line(self, line: str, source: str = "") -> None:
		self.call_from_thread(self._render_line, line, source)

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
	async def _sink_for_source(self, source: str) -> "RunnerPanel | None":
		# Where a command runner's output lands. In a workflow/scan it's the child's
		# sub-panel. For a leaf it's the current panel ONLY if its source matches — in a
		# PARALLEL batch several tasks stream at once while the global _current points at
		# whichever finished first, so matching by source (tool name) avoids cross-wiring.
		if self._container is not None:
			return await self._container.subpanel(source)
		if self._current is not None and getattr(self._current, "source", "") == source:
			return self._current
		return None   # no panel yet (batch card renders on completion) -> buffer

	def _buffer(self, source: str) -> dict:
		return self._line_buffers.setdefault(source, {"cmd": "", "lines": []})

	async def _set_command(self, cmd: str, source: str = "") -> None:
		if not cmd:
			return
		sink = await self._sink_for_source(source)
		if sink is not None:
			sink.set_command(cmd)
		else:
			self._buffer(source)["cmd"] = cmd

	async def _render_line(self, line: str, source: str = "") -> None:
		if not (isinstance(line, str) and line.strip()):
			return
		sink = await self._sink_for_source(source)
		if sink is not None:
			sink.add_raw(line)
		else:
			self._buffer(source)["lines"].append(line)

	def _flush_buffer(self, panel: RunnerPanel) -> None:
		# attach output that streamed before this panel's card rendered (parallel batch)
		if not panel.source:
			return
		buf = self._line_buffers.pop(panel.source, None)
		if not buf:
			return
		if buf["cmd"]:
			panel.set_command(buf["cmd"])
		for ln in buf["lines"]:
			panel.add_raw(ln)

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

	def _show_main(self) -> None:
		for s in self._subviews.values():
			s.display = False
		self._convo().display = True
		self.query_one("#backbar").display = False

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

	# ---- findings side panel (lazy, queried by _context.session_id) ----
	def set_findings_source(self, workspace_id, context, session_id) -> None:
		# called from the worker thread when the runner resolves its session
		self._findings_src = (workspace_id, dict(context or {}), session_id)

	def action_toggle_findings(self) -> None:
		panel = self.query_one("#findings-panel")
		panel.display = not panel.display
		if panel.display:
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
		self.query_one("#status", Static).update(
			Text.from_markup(f"[gold3]{self._SPIN[self._spin_frame]} {escape(self._status_text)}[/]"))

	# ---- item rendering (generic) ----
	async def _route_write(self, d: dict) -> VerticalScroll:
		"""Return the scroll an item should mount into. Base: the main convo. A frontend
		can override to route items to a secondary view (e.g. a subagent transcript)."""
		return self._convo()

	async def _render_domain(self, d: dict) -> bool:
		"""Handle a frontend-specific item type. Return True if handled (base: no)."""
		return False

	async def _render(self, item) -> None:
		d = item.toDict() if hasattr(item, "toDict") else dict(item)
		self._write = await self._route_write(d)
		if await self._render_domain(d):
			return
		t = d.get("_type")
		if t in ("info", "warning", "error"):
			renderable = message_text(item, d)
			if self._container is not None:
				# a note emitted by a child task (e.g. "XML results saved", "N exploits
				# found") belongs IN that task's sub-panel; a workflow-level note (e.g.
				# "Skipped task …", whose _source is the workflow itself) stays on the
				# container.
				src = d.get("_source") or ""
				if src and src != self._container.source:
					sp = await self._container.subpanel(src)
					sp.add_note(renderable)
				else:
					self._container.add_note(renderable)
			else:
				await self._append(Static(renderable, classes="ai"))
			return
		if t in ("progress", "stat", "state", "target"):  # execution / plumbing types
			return
		# dedup: a finding can arrive live (child on_item display hook) and again when the
		# AI re-reads it via query_workspace — only render it once. Guard on a TRUTHY uuid
		# (an unpersisted finding has _uuid="" — never treat those as the same finding).
		uid = d.get("_uuid")
		if uid:
			if uid in self._shown_uuids:
				return
			self._shown_uuids.add(uid)
		# a finding → render with its own __rich__ (secator-identical). Inside a
		# workflow/scan it nests under the child task's sub-panel; a single task goes
		# straight in; otherwise it lands at top level.
		renderable = finding_text(item, d)
		if self._container is not None:
			sp = await self._container.subpanel(d.get("_source") or "results")
			sp.add_finding(renderable)
			self._container.bump()
		elif self._current is not None:
			self._current.add_finding(renderable)
		else:
			await self._append(Static(renderable, classes="out-line"))

	def _finish_current(self) -> None:
		if self._current is not None:
			self._current.finish()
		self._current = None
		self._container = None

	# ---- input / prompts / steers ----
	async def on_input_submitted(self, event: Input.Submitted) -> None:
		text = event.value.strip()
		event.input.value = ""
		if not text:
			return
		await self._append(Static(Text.from_markup(f"[bold cyan]›[/] {escape(text)}"), classes="user"))
		pend = self._pending_ask
		if pend is not None:
			ev, holder, choices, ptype = pend
			self._resolve_pending(self._resolve_answer(text, choices, ptype))
			return
		with self._steers_lock:
			self._steers.append(text)

	def _resolve_pending(self, value) -> None:
		"""Unblock the worker waiting in tui_ask_user with `value`."""
		pend = self._pending_ask
		if pend is None:
			return
		ev, holder, choices, ptype = pend
		holder["value"] = value
		self._pending_ask = None
		self._set_status("", False)
		ev.set()
		try:
			self.query_one("#input-box Input", Input).focus()
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

	def tui_ask_user(self, question, choices, prompt_type="follow_up", multiple=False, **context):
		ev = threading.Event()
		holder: dict = {}
		self.call_from_thread(
			self._show_prompt, question, (ev, holder, list(choices or []), prompt_type), bool(multiple))
		ev.wait()
		return {"answer": holder.get("value")}

	def _show_prompt(self, question, pending, multiple=False) -> None:
		self._pending_ask = pending
		self._set_status("", False)   # nothing is running while we wait for the user
		choices, ptype = pending[2], pending[3]
		if ptype == "permission":
			# neutral Approve / Approve all / Deny list (typing a/aa/d still works)
			self._convo().mount(PermissionPrompt(question, self._resolve_pending))
			self._convo().scroll_end(animate=False)
		elif choices:
			# navigable suggestion list (↑/↓/space + enter); no generic question header
			self._convo().mount(ChoicePrompt("", choices, multiple, self._resolve_pending))
			self._convo().scroll_end(animate=False)
		else:
			# a plain end-of-turn follow-up: no "What's next?" / "waiting" noise — the
			# focused input is enough. Just make sure it's focused.
			try:
				self.query_one("#input-box Input", Input).focus()
			except Exception:  # noqa: BLE001
				pass

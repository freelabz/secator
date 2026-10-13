"""Textual TUI frontend for the secator `ai` task (experiment).

Launched from the CLI when `secator x ai --tui` is used on a TTY. It owns the
screen and drives the ai runner's item stream into an interactive UI: runner
events (task/workflow/scan/shell) are collapsible dropdowns, findings land inside
the current runner, AI responses render as Markdown, raw output stays plain text,
and target-controlled finding values are markup-escaped.

Textual is an OPTIONAL dependency — `import secator.ai.tui` is only done lazily by
the CLI, which falls back to the normal console run when textual is missing.
"""
from __future__ import annotations

import threading

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import (
	Header, Input, Markdown, OptionList, SelectionList, Static)


def _rehydrate(d: dict):
	"""Rebuild an OutputType from a plain dict (query results arrive as dicts) so we
	can use its own __rich__ rendering."""
	from secator.output_types import FINDING_TYPES
	t = d.get("_type")
	for cls in FINDING_TYPES:
		try:
			if cls.get_name() == t:
				return cls.load(d)
		except Exception:  # noqa: BLE001
			return None
	return None


def _finding_text(item, d: dict) -> Text:
	"""Render a finding EXACTLY like secator's console: use the OutputType's own
	__rich__ (icons, fields, colors). Falls back to a compact line if that fails."""
	obj = item if hasattr(item, "__rich__") else _rehydrate(d)
	if obj is not None:
		try:
			s = obj.__rich__()
			if isinstance(s, str):
				try:
					return Text.from_markup(s)
				except Exception:  # noqa: BLE001 - stray markup in target-controlled fields
					return Text(s)
			return s
		except Exception:  # noqa: BLE001
			pass
	return Text.from_markup(_finding_markup(d))


def _msg_text(item, d: dict):
	"""Render an info/warning/error line via its OutputType __rich__ (secator-identical,
	keeps the [INF]/[WRN]/[ERR] tag + message markup)."""
	r = getattr(item, "__rich__", None)
	if callable(r):
		try:
			s = item.__rich__()
			if isinstance(s, str):
				try:
					return Text.from_markup(s)
				except Exception:  # noqa: BLE001
					return Text(s)
			return s
		except Exception:  # noqa: BLE001
			pass
	msg = str(d.get("message", ""))
	try:
		return Text.from_markup(msg)
	except Exception:  # noqa: BLE001
		return Text(msg)


def _finding_markup(d: dict) -> str:
	t = d.get("_type", "")
	src = escape(str(d.get("_source", "")))

	def e(k):
		return escape(str(d.get(k, "")))

	if t == "vulnerability":
		sev = (d.get("severity") or "unknown").lower()
		c = {"critical": "red", "high": "red", "medium": "yellow",
		     "low": "yellow", "info": "cyan"}.get(sev, "dim")
		return f"[{c}]●[/] [{c}]VULN[/]  ·  {e('name')}  ·  [{c}]{sev}[/]  ·  {e('matched_at')}  [dim]({src})[/]"
	if t == "port":
		return f"[green]●[/] [green]PORT[/]  ·  {e('port')}/tcp  ·  {e('state')}  ·  {e('host')}  [dim]({src})[/]"
	if t == "url":
		return f"[green]●[/] [green]URL[/]   ·  {e('status_code')}  ·  {e('url')}  [dim]({src})[/]"
	if t == "tag":
		return f"[cyan]●[/] [cyan]TAG[/]   ·  {e('name')}  ·  {e('match')}  [dim]({src})[/]"
	return f"[dim]● {escape(t)}[/]  {escape(str(d))[:100]}"


class _Head(Static):
	"""Clickable one-line header that toggles its parent RunnerPanel."""
	def on_click(self) -> None:
		panel = self.parent
		if isinstance(panel, RunnerPanel):
			panel.toggle()


class RunnerPanel(Vertical):
	"""A Claude-like collapsible runner entry: a dim one-line header ("Running …" /
	"Ran …") with the disclosure arrow immediately after the text (ellipsised if it
	doesn't fit), and a bordered box (hidden until expanded) holding the command and
	its output/findings."""

	def __init__(self, kind: str, rname: str, command: str = "", runner_id: str = ""):
		super().__init__(classes="runner-panel")
		self.kind = kind
		self.rname = rname
		self.command = command
		self.runner_id = runner_id
		self.count = 0
		self.lines = 0
		self.done = False
		self._collapsed = True
		self.subpanels: dict = {}   # source -> nested RunnerPanel (workflow/scan children)

	def compose(self) -> ComposeResult:
		yield _Head(self._header(), classes="runner-head")
		box = Vertical(classes="runner-box")
		box.display = False
		with box:
			if self.command:
				yield Static(Text.from_markup(f"[dim]$ {escape(self.command)}[/]"), classes="runner-cmd")
			yield Vertical(classes="runner-out")
		yield box

	def _desc(self) -> str:
		return self.rname or self.command or self.kind

	def _header(self) -> Text:
		verb = "Ran" if self.done else "Running"
		arrow = "▼" if not self._collapsed else "▶"
		kind = f" ({self.kind})"   # runner type, so a task/workflow/scan/query/shell is distinguishable
		tail = f"  ·  {self.count} findings" if self.count else ""
		desc = self._desc()
		# ellipsise only the description so the type + arrow stay on one line
		width = self.app.size.width if self.app else 100
		budget = max(12, width - len(verb) - len(kind) - len(tail) - 8)
		if len(desc) > budget:
			desc = desc[: budget - 1] + "…"
		t = Text()
		t.append(f"{verb} ", style="bold #9aa3b8")
		t.append(desc, style="#8a8fa3")
		t.append(kind, style="#5b6070")
		t.append(tail, style="#6b7187")
		t.append(f"  {arrow}", style="#6b7187")
		return t

	def _refresh_head(self) -> None:
		self.query_one(".runner-head", _Head).update(self._header())

	def toggle(self) -> None:
		self._collapsed = not self._collapsed
		self.query_one(".runner-box", Vertical).display = not self._collapsed
		self._refresh_head()

	def add_finding(self, renderable) -> None:
		self.count += 1
		self.query_one(".runner-out", Vertical).mount(Static(renderable, classes="out-line"))
		self._refresh_head()

	def bump(self) -> None:
		# count a finding that landed in a nested sub-panel (container total)
		self.count += 1
		self._refresh_head()

	def add_note(self, renderable) -> None:
		# a workflow/scan-level line (e.g. "Skipped task …") — keeps the box non-empty
		self.lines += 1
		self.query_one(".runner-out", Vertical).mount(Static(renderable, classes="out-line"))

	async def subpanel(self, source: str) -> "RunnerPanel":
		# get/create a nested task panel for a workflow/scan child, keyed by task name.
		# await the mount so the sub-panel is composed before we write into it.
		source = source or "results"
		sp = self.subpanels.get(source)
		if sp is None:
			sp = RunnerPanel("task", source)
			sp.done = self.done
			self.subpanels[source] = sp
			await self.query_one(".runner-out", Vertical).mount(sp)
		return sp

	def set_command(self, cmd: str) -> None:
		# add/replace the dim `$ command` line at the top of the box (once)
		if self.command or not cmd:
			return
		self.command = cmd
		box = self.query_one(".runner-box", Vertical)
		out = self.query_one(".runner-out", Vertical)
		box.mount(Static(Text.from_markup(f"[dim]$ {escape(cmd)}[/]"), classes="runner-cmd"), before=out)

	def add_raw(self, text: str) -> None:
		# raw output: plain Text, never markup-parsed (target-controlled). Cap the
		# number of rendered lines so a chatty task can't flood the UI.
		if self.lines >= 500:
			return
		self.lines += 1
		if self.lines == 500:
			text = "… (output truncated)"
		self.query_one(".runner-out", Vertical).mount(Static(Text(text), classes="out-raw"))

	def finish(self) -> None:
		self.done = True
		for sp in self.subpanels.values():
			sp.finish()
		if not self.count and not self.lines and not self.command and not self.subpanels:
			self.query_one(".runner-out", Vertical).mount(
				Static(Text.from_markup("[dim i](no output)[/]"), classes="out-line"))
		self._refresh_head()


class ChoicePrompt(Vertical):
	"""Navigable suggestion list for a follow-up ask. Single-choice uses an OptionList
	(↑/↓ then Enter); multi-choice uses a SelectionList (Space toggles, Enter confirms).
	Typing in the main input still works as a free-form answer."""

	def __init__(self, question: str, choices: list, multiple: bool, resolve):
		super().__init__(classes="choice")
		self._question = question
		self._choices = list(choices)
		self._multiple = multiple
		self._resolve = resolve

	def compose(self) -> ComposeResult:
		if self._question:
			yield Static(Text.from_markup(f"[b yellow]?[/] {escape(self._question)}"), classes="choice-q")
		if self._multiple:
			yield SelectionList(*[(c, i) for i, c in enumerate(self._choices)], classes="choice-list")
			yield Static(Text.from_markup("[dim]space to toggle · enter to confirm · or type your own[/]"))
		else:
			yield OptionList(*self._choices, classes="choice-list")
			yield Static(Text.from_markup("[dim]↑/↓ to move · enter to select · or type your own[/]"))

	def on_mount(self) -> None:
		self.query_one(".choice-list").focus()

	def _done(self, value: str) -> None:
		for w in self.query(".choice-list"):
			w.disabled = True
		for q in self.query(".choice-q"):
			q.update(Text.from_markup(f"[dim]✓ {escape(value)}[/]"))
		self._resolve(value)

	def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
		self._done(str(event.option.prompt))

	def on_key(self, event) -> None:
		if self._multiple and event.key == "enter":
			sel = self.query_one(SelectionList)
			picked = [self._choices[i] for i in sel.selected]
			if picked:
				event.stop()
				self._done(", ".join(picked))


class SubagentRow(Static):
	"""A clickable 'Running/Ran subagent <label>' row in the main conversation that
	opens the subagent's own conversation view — clickable the moment it appears."""
	def __init__(self, label: str, sid: str):
		super().__init__(classes="subagent-row")
		self.label = label
		self.sid = sid
		self.done = False
		self.update(self._text())

	def _text(self) -> Text:
		verb = "Ran" if self.done else "Running"
		return Text.from_markup(
			f"[b #9aa3b8]{verb} subagent[/] [#8a8fa3]{escape(self.label)}[/]  [#6b7187]▸ open[/]")

	def mark_done(self) -> None:
		self.done = True
		self.update(self._text())

	def on_click(self) -> None:
		self.app._open_subview(self.sid)


class _BackBar(Static):
	"""Clickable bar shown while viewing a subagent conversation; returns to main."""
	def on_click(self) -> None:
		self.app._show_main()


class PermissionPrompt(Vertical):
	"""Neutral, vertically-stacked Approve / Approve all / Deny list for a permission
	ask (↑/↓ + Enter). Selecting resolves the blocked worker. Typing a/aa/d works too."""

	_OPTIONS = [("Approve", "allow"), ("Approve all", "allow_all"), ("Deny", "deny")]

	def __init__(self, question: str, resolve):
		super().__init__(classes="choice")
		self._question = question
		self._resolve = resolve

	def compose(self) -> ComposeResult:
		yield Static(Text.from_markup(f"[b yellow]?[/] {escape(self._question)}"), classes="choice-q")
		yield OptionList(*[label for label, _ in self._OPTIONS], classes="choice-list")
		yield Static(Text.from_markup("[dim]↑/↓ to move · enter to select[/]"))

	def on_mount(self) -> None:
		self.query_one(".choice-list").focus()

	def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
		label, value = self._OPTIONS[event.option_index]
		for w in self.query(".choice-list"):
			w.disabled = True
		self.query_one(".choice-q", Static).update(Text.from_markup(f"[dim]✓ {escape(label)}[/]"))
		self._resolve(value)


class AITUI(App):
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

	/* Claude-like runner entry: dim one-line header, arrow right after the text */
	.runner-panel { margin: 1 0; height: auto; }
	.runner-head { height: 1; width: auto; }
	.runner-head:hover { text-style: bold; }
	/* expanded content: a left rule (indent), not a box — stays integrated */
	.runner-box {
		height: auto; margin: 0 0 0 1; padding: 0 0 0 1;
		border-left: solid #2b3245; background: transparent;
	}
	.runner-cmd { color: #7b8296; margin: 0 0 1 0; }   /* command: dim text, no background */
	.runner-out { height: auto; }
	.out-line { color: #cdd6e4; }
	.out-raw { color: #9aa3b8; }

	/* follow-up / permission suggestion list */
	.choice { height: auto; margin: 1 0; }
	.choice-q { color: #e6c15a; margin: 0 0 1 0; }
	.choice-list { height: auto; max-height: 12; border: none; background: transparent; }

	Markdown { background: transparent; margin: 0; padding: 0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	#input-box {
		border: none; border-top: solid #2b3245; background: transparent; height: 3; padding: 0;
	}
	#input-box Input { border: none; background: transparent; color: #e6ecf5; padding: 0 1; height: 1fr; }
	#input-box Input:focus { border: none; background: transparent; }
	#input-box Input > .input--cursor { color: #0b0e14; background: #e6ecf5; }
	Header { background: transparent; color: #cdd6e4; }
	"""
	BINDINGS = [
		("ctrl+c", "quit", "Quit"),
		# jump to the latest messages (a focused choice/permission list consumes `down`
		# first for navigation, so this only fires when not selecting)
		("down", "scroll_latest", "Scroll to latest"),
	]
	# full-screen, integrated: use the terminal's own background/palette, no command
	# palette, no footer chrome
	ansi_color = True
	ENABLE_COMMAND_PALETTE = False

	def __init__(self, runner_builder, session="ai", mode="chat", initial_prompt=""):
		super().__init__()
		self._runner_builder = runner_builder
		self._session = session
		self._mode = mode
		self._initial_prompt = initial_prompt or ""
		self._current: RunnerPanel | None = None
		self._container: RunnerPanel | None = None   # active workflow/scan nesting parent
		self._subviews: dict = {}   # subagent session_id -> VerticalScroll (hidden)
		self._write: VerticalScroll | None = None   # where incoming items are mounted
		self._in_subagent: str | None = None        # session_id we're currently writing into
		self._active_subagent: SubagentRow | None = None
		self._steers: list[str] = []
		self._steers_lock = threading.Lock()
		self._pending_ask = None
		self._status_text = ""
		self._status_spinning = False
		self._spin_frame = 0

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		yield _BackBar(Text.from_markup("[#7fd1e0]← Back to conversation[/]"), id="backbar")
		yield Vertical(VerticalScroll(id="convo"), id="views")
		yield Static("", id="status")
		with Vertical(id="input-box"):
			yield Input(placeholder="Message, or steer a running runner…  (Enter to send)")

	def on_mount(self) -> None:
		self.title = "secator ai"
		self.sub_title = f"session: {self._session} · mode: {self._mode}"
		self.query_one("#backbar").display = False
		self._write = self.query_one("#convo", VerticalScroll)
		self.query_one("#input-box Input", Input).focus()
		self.set_interval(0.1, self._tick_spinner)   # animate the status spinner
		if self._initial_prompt:
			# the -p prompt isn't typed into the input, so echo it once up front
			self.call_later(self._append, Static(
				Text.from_markup(f"[bold cyan]›[/] {escape(self._initial_prompt)}"), classes="user"))
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

	# thread-safe entry the on_item hook calls from the worker thread
	def tui_render(self, item) -> None:
		self.call_from_thread(self._render, item)

	# thread-safe entries the child-runner on_line hook calls (TUI-only, not in the
	# LLM stream): the task's command and its raw stdout, routed to the active panel
	def tui_set_command(self, cmd: str, source: str = "") -> None:
		self.call_from_thread(self._set_command, cmd, source)

	def tui_render_line(self, line: str, source: str = "") -> None:
		self.call_from_thread(self._render_line, line, source)

	async def _sink(self, source: str) -> "RunnerPanel | None":
		# where command/output/findings land: a workflow/scan child's sub-panel, else
		# the current leaf panel
		if self._container is not None:
			return await self._container.subpanel(source)
		return self._current

	async def _set_command(self, cmd: str, source: str = "") -> None:
		sink = await self._sink(source)
		if sink is not None and cmd:
			sink.set_command(cmd)

	async def _render_line(self, line: str, source: str = "") -> None:
		sink = await self._sink(source)
		if sink is not None and isinstance(line, str) and line.strip():
			sink.add_raw(line)

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
		# the currently visible scroll (an open subagent view, else the main convo)
		for sv in self._subviews.values():
			if sv.display:
				return sv
		return self._convo()

	def action_scroll_latest(self) -> None:
		self._active_view().scroll_end(animate=False)

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

	async def _render(self, item) -> None:
		d = item.toDict() if hasattr(item, "toDict") else dict(item)
		# route subagent-internal items into that subagent's own (hidden) view; the
		# spawn card itself has the marker stripped, so it stays in the main convo
		ctx = d.get("_context") or {}
		if ctx.get("subagent"):
			self._write = await self._ensure_subview(ctx.get("session_id") or "subagent")
			self._in_subagent = ctx.get("session_id") or "subagent"
		else:
			# control returned to the main thread: the active subagent is done
			if self._in_subagent is not None and self._active_subagent is not None:
				self._active_subagent.mark_done()
				self._active_subagent = None
			self._in_subagent = None
			self._write = self._convo()
		t = d.get("_type")
		if t == "ai":
			await self._render_ai(d)
			return
		if t in ("info", "warning", "error"):
			renderable = _msg_text(item, d)
			# inside a workflow/scan these are its own notes (e.g. "Skipped task …") —
			# nest them so expanding the workflow shows them instead of "(no output)"
			if self._container is not None:
				self._container.add_note(renderable)
			else:
				await self._append(Static(renderable, classes="ai"))
			return
		if t in ("progress", "stat", "state", "target"):  # execution / plumbing types
			return
		# a finding → render with its own __rich__ (secator-identical). Inside a
		# workflow/scan it nests under the child task's sub-panel; a single task goes
		# straight in; otherwise it lands at top level.
		renderable = _finding_text(item, d)
		if self._container is not None:
			sp = await self._container.subpanel(d.get("_source") or "results")
			sp.add_finding(renderable)
			self._container.bump()
		elif self._current is not None:
			self._current.add_finding(renderable)
		else:
			await self._append(Static(renderable, classes="out-line"))

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
			self._finish_current()
			if at == "shell":
				# LLM-supplied description as the title; the command goes in the box
				kind, rname, command = "shell", desc, content
			elif at == "query":
				kind, rname, command = "query", desc or content, content
			else:
				kind, rname, command = at, desc or content or ed.get("name") or "", ""
			panel = RunnerPanel(kind, rname, command=command, runner_id=ed.get("runner_id", ""))
			await self._append(panel)
			self._current = panel
			# workflows/scans contain child tasks: nest their findings/output by source
			self._container = panel if at in ("workflow", "scan") else None
			self._set_status(f"running {kind} {rname or command}".strip())
		elif at == "shell_output":
			if self._current is not None:
				self._current.add_raw(content)
		elif at in ("mark_vuln_exploited", "add_vuln_poc"):
			await self._append(Static(Text.from_markup(f"[red]💥 {escape(content)}[/]"), classes="ai"))
		elif at in ("mark_vuln_false_positive", "mark_vuln_exploit_failed"):
			await self._append(Static(Text.from_markup(f"[yellow]{escape(content)}[/]"), classes="ai"))
		elif at == "error":
			await self._append(Static(Text.from_markup(f"[red]✖ {escape(content)}[/]"), classes="err"))
		elif at == "stopped":
			self._finish_current()
			self._set_status("stopped", False)

	def _finish_current(self) -> None:
		if self._current is not None:
			self._current.finish()
		self._current = None
		self._container = None

	# input: resolves an open prompt, else becomes a steer
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

	# thread-safe hooks called by TUIBackend / maybe_status from the worker thread
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


def run_ai_tui(runner_cls, config, inputs, opts, hooks, context):
	"""Entry used by the CLI: set this app as the active TUI (so the ai task
	auto-selects the TUIBackend + suppresses console output), then run it.

	The ai task is wrapped in a Task runner, which prints items internally but
	yields NOTHING to the iterator — so we tap the item stream via an on_item hook
	(merged into the runner's hooks) that marshals each item onto the UI thread. The
	runner is BUILT inside the worker (after set_tui) so the backend resolves with
	the TUI active."""
	from secator.rich import set_tui

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

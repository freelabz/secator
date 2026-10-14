"""Reusable Textual widgets for the secator TUI.

Generic building blocks (collapsible runner panel, navigable prompt lists, resize
grip, …) shared by any TUI frontend. They talk back to the app only through small,
stable hooks (``app._open_subview`` / ``app._show_main``) so they stay frontend-agnostic.
"""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import OptionList, SelectionList, Static


class Head(Static):
	"""Clickable one-line header that toggles its parent RunnerPanel."""
	def on_click(self) -> None:
		panel = self.parent
		if isinstance(panel, RunnerPanel):
			panel.toggle()


class RunnerPanel(Vertical):
	"""A Claude-like collapsible runner entry: a dim one-line header ("Running …" /
	"Ran …") with the disclosure arrow immediately after the text (ellipsised if it
	doesn't fit), and a bordered box (hidden until expanded) holding the command and
	its output/findings. Workflow/scan panels nest child task panels in ``subpanels``."""

	def __init__(self, kind: str, rname: str, command: str = "", runner_id: str = ""):
		super().__init__(classes="runner-panel")
		self.kind = kind
		self.rname = rname
		self.command = command
		self.runner_id = runner_id
		self.source = ""   # the child command's tool name, for routing on_line output
		self.count = 0
		self.lines = 0
		self.done = False
		self._collapsed = True
		self.subpanels: dict = {}   # source -> nested RunnerPanel (workflow/scan children)

	def compose(self) -> ComposeResult:
		yield Head(self._header(), classes="runner-head")
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
		self.query_one(".runner-head", Head).update(self._header())

	def toggle(self) -> None:
		self._collapsed = not self._collapsed
		self.query_one(".runner-box", Vertical).display = not self._collapsed
		self._refresh_head()

	def set_collapsed(self, collapsed: bool) -> None:
		if self._collapsed != collapsed:
			self.toggle()

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


class SubagentRow(Static):
	"""A clickable 'Running/Ran subagent <label>' row that opens the subagent's own
	conversation view — clickable the moment it appears."""
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


class BackBar(Static):
	"""Clickable bar shown while viewing a secondary (subagent) view; returns to main."""
	def on_click(self) -> None:
		self.app._show_main()


class Grip(Static):
	"""Draggable left edge of the findings panel — drag to resize its width."""
	_dragging = False

	def on_mouse_down(self, event) -> None:
		self._dragging = True
		self.capture_mouse()
		event.stop()

	def on_mouse_up(self, event) -> None:
		self._dragging = False
		self.release_mouse()
		event.stop()

	def on_mouse_move(self, event) -> None:
		if not self._dragging:
			return
		total = self.app.size.width
		width = max(24, min(total - 20, total - event.screen_x))
		self.app.query_one("#findings-panel").styles.width = int(width)

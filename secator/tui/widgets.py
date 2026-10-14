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

from secator.tui.render import command_text


def _runner_ancestor(node):
	while node is not None and not isinstance(node, RunnerPanel):
		node = node.parent
	return node


class Head(Static):
	"""Clickable one-line header that toggles its parent RunnerPanel."""
	def on_click(self) -> None:
		panel = self.parent
		if isinstance(panel, RunnerPanel):
			panel.toggle()


class _CmdLine(Static):
	"""Clickable '$ <command>' line — reveals/hides the runner's RAW output."""
	def on_click(self) -> None:
		panel = _runner_ancestor(self.parent)
		if isinstance(panel, RunnerPanel):
			panel.toggle_raw()


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
		self._raw_collapsed = True   # raw command output hidden until the command is clicked
		self.subpanels: dict = {}   # source -> nested RunnerPanel (workflow/scan children)

	def compose(self) -> ComposeResult:
		# Level 1: the header (click to expand). Level 2 (box): the command + secator
		# findings. Level 3: click the command to reveal the RAW command output.
		yield Head(self._header(), classes="runner-head")
		box = Vertical(classes="runner-box")
		box.display = False
		with box:
			with Vertical(classes="runner-cmdwrap"):
				if self.command:
					yield _CmdLine(self._cmd_render(), classes="runner-cmd")
			raw = Vertical(classes="runner-raw")
			raw.display = False
			yield raw
			yield Vertical(classes="runner-out")
		yield box

	def _cmd_render(self) -> Text:
		t = command_text(self.command)   # '$ <bash-highlighted command>'
		arrow = "▼" if not self._raw_collapsed else "▶"
		t.append(f"  {arrow}", style="#6b7187")   # reveals the raw output
		return t

	def toggle_raw(self) -> None:
		self._raw_collapsed = not self._raw_collapsed
		self.query_one(".runner-raw", Vertical).display = not self._raw_collapsed
		for cl in self.query(".runner-cmd"):
			cl.update(self._cmd_render())

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

	def add_output(self, text: str) -> None:
		# VISIBLE output (e.g. a shell command's stdout — it IS the result, not hidden
		# behind the command-click like a task's raw stdout). Line-capped, plain text.
		if self.lines >= 500:
			return
		self.lines += 1
		if self.lines == 500:
			text = "… (output truncated)"
		self.query_one(".runner-out", Vertical).mount(Static(Text(text), classes="out-raw"))

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
		# add the clickable '$ command' line (once); click it to reveal the raw output
		if self.command or not cmd:
			return
		self.command = cmd
		self.query_one(".runner-cmdwrap", Vertical).mount(_CmdLine(self._cmd_render(), classes="runner-cmd"))

	def add_raw(self, text: str) -> None:
		# RAW command output: plain Text, never markup-parsed (target-controlled), kept
		# hidden under the command line (click the command to reveal). Line-capped.
		if self.lines >= 500:
			return
		self.lines += 1
		if self.lines == 500:
			text = "… (output truncated)"
		self.query_one(".runner-raw", Vertical).mount(Static(Text(text), classes="out-raw"))

	def finish(self) -> None:
		self.done = True
		for sp in self.subpanels.values():
			sp.finish()
		if not self.count and not self.lines and not self.command and not self.subpanels:
			self.query_one(".runner-out", Vertical).mount(
				Static(Text.from_markup("[dim i](no output)[/]"), classes="out-line"))
		self._refresh_head()


class _ChoiceSummary(Static):
	"""Clickable collapsed summary of a resolved ChoicePrompt; toggles the questionnaire."""
	def on_click(self) -> None:
		parent = self.parent
		if isinstance(parent, ChoicePrompt):
			parent.toggle_body()


class _BlockHead(Static):
	"""Clickable header that toggles its parent BlockPanel."""
	def on_click(self) -> None:
		panel = self.parent
		if isinstance(panel, BlockPanel):
			panel.toggle()


class BlockPanel(Vertical):
	"""A collapsible 'Blocked <description>' entry for a guardrail-denied action —
	expand to reveal which command/runner was blocked and the reason."""

	def __init__(self, description: str, reason: str = "", command: str = ""):
		super().__init__(classes="runner-panel")
		self.description = description or "action"
		self.reason = reason or ""
		self.command = command or ""
		self._collapsed = True

	def compose(self) -> ComposeResult:
		yield _BlockHead(self._header(), classes="runner-head")
		box = Vertical(classes="runner-box")
		box.display = False
		with box:
			if self.command:
				yield Static(command_text(self.command), classes="runner-cmd")
			if self.reason:
				yield Static(Text.from_markup(f"[#d98a7a]{escape(self.reason)}[/]"), classes="out-line")
		yield box

	def _header(self) -> Text:
		arrow = "▼" if not self._collapsed else "▶"
		desc = self.description
		width = self.app.size.width if self.app else 100
		budget = max(12, width - 20)
		if len(desc) > budget:
			desc = desc[: budget - 1] + "…"
		t = Text()
		t.append("Blocked ", style="bold red")
		t.append(desc, style="#8a8fa3")
		t.append(f"  {arrow}", style="#6b7187")
		return t

	def toggle(self) -> None:
		self._collapsed = not self._collapsed
		self.query_one(".runner-box", Vertical).display = not self._collapsed
		self.query_one(".runner-head", _BlockHead).update(self._header())


class _ActionHead(Static):
	"""Clickable header that toggles its parent ActionPanel."""
	def on_click(self) -> None:
		panel = self.parent
		if isinstance(panel, ActionPanel):
			panel.toggle()


class ActionPanel(Vertical):
	"""A collapsible AI finding-action row: '<Verb> <name>' (neutral), expand to see the
	referenced finding rendered richly (its __rich__). Non-collapsible if no finding."""

	def __init__(self, verb: str, name: str, finding_renderable=None):
		super().__init__(classes="runner-panel")
		self.verb = verb
		self.aname = name
		self.finding = finding_renderable   # a Rich renderable (Text) or None
		self._collapsed = True

	def compose(self) -> ComposeResult:
		yield _ActionHead(self._header(), classes="runner-head")
		box = Vertical(classes="runner-box")
		box.display = False
		with box:
			if self.finding is not None:
				yield Static(self.finding, classes="out-line")
		yield box

	def _header(self) -> Text:
		t = Text()
		t.append(f"{self.verb} ", style="bold #9aa3b8")
		t.append(str(self.aname), style="#8a8fa3")
		if self.finding is not None:
			arrow = "▼" if not self._collapsed else "▶"
			t.append(f"  {arrow}", style="#6b7187")
		return t

	def toggle(self) -> None:
		if self.finding is None:
			return
		self._collapsed = not self._collapsed
		self.query_one(".runner-box", Vertical).display = not self._collapsed
		self.query_one(".runner-head", _ActionHead).update(self._header())


class ChoicePrompt(Vertical):
	"""Navigable suggestion list for a follow-up ask. Single-choice uses an OptionList
	(↑/↓ then Enter); multi-choice uses a SelectionList (Space toggles, Enter confirms).
	Typing in the main input still works as a free-form answer. Once answered it collapses
	to just the picked value — click it to expand the original questionnaire again."""

	def __init__(self, question: str, choices: list, multiple: bool, resolve):
		super().__init__(classes="choice")
		self._question = question
		self._choices = list(choices)
		self._multiple = multiple
		self._resolve = resolve
		self._value = ""
		self._collapsed = False

	def compose(self) -> ComposeResult:
		yield _ChoiceSummary("", classes="choice-summary")   # hidden until answered
		body = Vertical(classes="choice-body")
		with body:
			if self._question:
				yield Static(Text.from_markup(f"[b yellow]?[/] {escape(self._question)}"), classes="choice-q")
			if self._multiple:
				yield SelectionList(*[(c, i) for i, c in enumerate(self._choices)], classes="choice-list")
				yield Static(Text.from_markup("[dim]space to toggle · enter to confirm · or type your own[/]"))
			else:
				yield OptionList(*self._choices, classes="choice-list")
				yield Static(Text.from_markup("[dim]↑/↓ to move · enter to select · or type your own[/]"))
		yield body

	def on_mount(self) -> None:
		self.query_one(".choice-summary").display = False
		self.query_one(".choice-list").focus()

	def _summary_text(self) -> Text:
		arrow = "▶" if self._collapsed else "▼"
		t = Text()
		t.append("✓ ", style="green")
		t.append(self._value or "(none)", style="#8a8fa3")
		t.append(f"  {arrow}", style="#6b7187")
		return t

	def _done(self, value: str) -> None:
		self._value = value
		for w in self.query(".choice-list"):
			w.disabled = True
		# collapse to the picked value; click the summary to re-open the questionnaire
		self._collapsed = True
		summary = self.query_one(".choice-summary", _ChoiceSummary)
		summary.update(self._summary_text())
		summary.display = True
		self.query_one(".choice-body").display = False
		self._resolve(value)

	def toggle_body(self) -> None:
		if not self._value:
			return
		self._collapsed = not self._collapsed
		self.query_one(".choice-body").display = not self._collapsed
		self.query_one(".choice-summary", _ChoiceSummary).update(self._summary_text())

	def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
		if not self._value:   # ignore re-selection after answered
			self._done(str(event.option.prompt))

	def on_key(self, event) -> None:
		if self._multiple and event.key == "enter" and not self._value:
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

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
from textual.message import Message
from textual.widgets import Markdown, OptionList, SelectionList, Static, TextArea
from textual.widgets._toggle_button import ToggleButton

from secator.tui.render import command_text

# Refine the multi-select checkbox: drop Textual's heavy "▐X▌" bars for a single dot that
# reads empty/filled purely by colour (styled via the .selection-list--button* classes).
# SelectionList references ToggleButton.BUTTON_* directly, so this is set on the class; it's
# only reached on the (optional) TUI import path, where SelectionList is our only toggle.
ToggleButton.BUTTON_LEFT = ""
ToggleButton.BUTTON_INNER = "●"
ToggleButton.BUTTON_RIGHT = ""


class PromptInput(TextArea):
	"""Multi-line chat input (grows with content). Enter SENDS the text; Alt+Enter (also
	Shift+Enter / Ctrl+J, for terminals that don't deliver Alt) inserts a newline.

	Textual's TextArea inserts a newline on Enter by default — we remap Enter to a Submitted
	message and route newlines to the modifier combos instead.
	"""

	class Submitted(Message):
		"""Posted when the user presses Enter — carries the current text."""
		def __init__(self, value: str):
			self.value = value
			super().__init__()

	def __init__(self, **kwargs):
		super().__init__(soft_wrap=True, tab_behavior="focus", show_line_numbers=False, **kwargs)

	async def _on_key(self, event) -> None:
		if event.key == "enter":
			event.stop()
			event.prevent_default()
			self.post_message(self.Submitted(self.text))
			return
		if event.key in ("alt+enter", "shift+enter", "ctrl+j"):
			event.stop()
			event.prevent_default()
			self.insert("\n")
			return
		await super()._on_key(event)


def _usage_line(usage: dict) -> "Text | None":
	"""A compact 'subagent usage: N tokens · $cost' line, or None if nothing was billed."""
	usage = usage or {}
	try:
		tokens = int(usage.get("tokens") or 0)
	except (TypeError, ValueError):
		tokens = 0
	try:
		cost = float(usage.get("cost") or 0.0)
	except (TypeError, ValueError):
		cost = 0.0
	if not tokens and not cost:
		return None
	parts = []
	if tokens:
		parts.append(f"{tokens:,} tokens")
	if cost:
		parts.append(f"${cost:.4f}")
	return Text.from_markup(f"[#6b7187]subagent usage: {escape(' · '.join(parts))}[/]")


class HandbackPanel(Vertical):
	"""A subagent's verdict/handback, shown at the END of its drill-in view: a red-outlined
	box with the summary (markdown) and a token/cost line, so it reads as the conclusion."""

	def __init__(self, content: str, usage: dict = None):
		super().__init__(classes="handback-panel")
		self._content = content or ""
		self._usage = usage or {}

	def compose(self) -> ComposeResult:
		yield Static(Text.from_markup("[b #d98a7a]Verdict — subagent complete[/]"), classes="handback-title")
		yield Markdown(self._content)
		line = _usage_line(self._usage)
		if line is not None:
			yield Static(line, classes="handback-usage")


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

	# per-kind header verbs: (running, done). Default is Running/Ran.
	_VERBS = {"query": ("Querying", "Queried")}

	def __init__(self, kind: str, rname: str, command: str = "", runner_id: str = "", meta: str = ""):
		super().__init__(classes="runner-panel")
		self.kind = kind
		self.rname = rname
		self.command = command
		self.meta = meta   # optional dim details line (e.g. a query's result count + skip/limit/group)
		self.runner_id = runner_id
		self.source = ""   # the child command's tool name, for routing on_line output
		self.count = 0
		self.lines = 0
		self.raw_lines = 0           # hidden raw-output lines (the reveal arrow only shows if > 0)
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
			if self.meta:
				yield Static(Text.from_markup(f"[#6b7187]{escape(self.meta)}[/]"), classes="runner-meta")
			raw = Vertical(classes="runner-raw")
			raw.display = False
			yield raw
			yield Vertical(classes="runner-out")
		yield box

	def _cmd_render(self) -> Text:
		t = command_text(self.command)   # '$ <bash-highlighted command>'
		if self.raw_lines:               # only offer the reveal arrow if there IS raw output
			arrow = "▼" if not self._raw_collapsed else "▶"
			t.append(f"  {arrow}", style="#6b7187")
		return t

	def _refresh_cmd(self) -> None:
		for cl in self.query(".runner-cmd"):
			cl.update(self._cmd_render())

	def toggle_raw(self) -> None:
		if not self.raw_lines:           # nothing hidden to reveal (e.g. a shell: output is visible)
			return
		self._raw_collapsed = not self._raw_collapsed
		self.query_one(".runner-raw", Vertical).display = not self._raw_collapsed
		self._refresh_cmd()

	def _desc(self) -> str:
		return self.rname or self.command or self.kind

	def _header(self) -> Text:
		running, done = self._VERBS.get(self.kind, ("Running", "Ran"))
		verb = done if self.done else running
		arrow = "▼" if not self._collapsed else "▶"
		# runner type suffix so task/workflow/scan/shell are distinguishable; omitted when the
		# verb already names the action (e.g. "Queried …" needs no "(query)").
		kind = "" if self.kind in self._VERBS else f" ({self.kind})"
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
		if self.raw_lines >= 500:
			return
		self.raw_lines += 1
		self.lines += 1
		if self.raw_lines == 1:
			self._refresh_cmd()         # now there's raw output -> show the reveal arrow
		if self.raw_lines == 500:
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
	"""A follow-up choice box that REPLACES the input box while active (it lives in the input
	slot, keeping the top rule), so the user must act on it.

	↑/↓ move; Enter sends the highlighted choice directly. Tab hands the current selection to
	the input box to ADD MORE DETAILS (the app prefills + focuses it; the user edits and
	Enter sends that). Esc there returns to this choice box to change the selection.
	Multi-choice uses a SelectionList (space toggles)."""

	def __init__(self, choices: list, multiple: bool, resolve, to_input):
		super().__init__(classes="choice-box")
		self._choices = list(choices)
		self._multiple = multiple
		self._resolve = resolve        # called with the final answer string
		self._to_input = to_input      # called with the current selection to switch to input mode
		self._answered = False

	def compose(self) -> ComposeResult:
		if self._multiple:
			yield SelectionList(*[(c, i) for i, c in enumerate(self._choices)], classes="choice-list")
			yield Static(Text.from_markup(
				"[dim]space to toggle · enter to send · tab to add more details[/]"), classes="choice-hint")
		else:
			yield OptionList(*self._choices, classes="choice-list")
			yield Static(Text.from_markup(
				"[dim]↑/↓ to move · enter to send · tab to add more details[/]"), classes="choice-hint")

	def on_mount(self) -> None:
		self.call_after_refresh(self.focus_list)

	def focus_list(self) -> None:
		try:
			self.query_one(".choice-list").focus()
		except Exception:  # noqa: BLE001 - widget may be gone
			pass

	def selection_text(self) -> str:
		"""The toggled choices joined (multi) or the currently highlighted choice (single).

		In multi-choice with nothing toggled yet, fall back to the HIGHLIGHTED row — pressing
		Enter (or Tab) on a row the user is sitting on should send that row, not an empty answer.
		"""
		try:
			if self._multiple:
				sel = self.query_one(SelectionList)
				if sel.selected:
					return ", ".join(self._choices[i] for i in sel.selected)
				h = sel.highlighted
				return self._choices[h] if h is not None and 0 <= h < len(self._choices) else ""
			ol = self.query_one(OptionList)
			i = ol.highlighted if ol.highlighted is not None else 0
			return self._choices[i] if 0 <= i < len(self._choices) else ""
		except Exception:  # noqa: BLE001
			return ""

	def submit(self, value: str = None) -> None:
		if self._answered:
			return
		self._answered = True
		self._resolve(value if value is not None else self.selection_text())

	def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
		# single-choice: Enter (or click) on an option sends it directly
		self.submit(str(event.option.prompt))

	def on_key(self, event) -> None:
		if self._answered:
			return
		if event.key == "tab":
			event.stop()
			event.prevent_default()
			self._to_input(self.selection_text())
		elif self._multiple and event.key == "enter":
			event.stop()
			self.submit()


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
		# focus after the first refresh so it reliably takes focus from the input box (no mouse)
		self.call_after_refresh(self._focus_list)

	def _focus_list(self) -> None:
		try:
			self.query_one(".choice-list").focus()
		except Exception:  # noqa: BLE001 - widget may be gone
			pass

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

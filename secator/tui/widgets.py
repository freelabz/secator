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
from textual.widgets import Markdown, OptionList, SelectionList, Static

from secator.tui.render import command_text


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

	# status icons replace the old "Running"/"Ran" verbs: an animated orange spinner while
	# running/pending, a green check on success, a red cross on failure.
	_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
	_RUN_COLOR = "#e0882e"
	_OK_COLOR = "#3fb950"
	_FAIL_COLOR = "#ff6b6b"

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
		self.failed = False          # an error was routed to this runner -> red cross on finish
		self._spin_frame = 0
		self._spin_timer = None
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

	def _status_icon(self):
		"""(glyph, style) for the current state: animated orange spinner while running,
		green check on success, red cross on failure."""
		if not self.done:
			return self._SPIN[self._spin_frame % len(self._SPIN)], f"bold {self._RUN_COLOR}"
		if self.failed:
			return "✗", f"bold {self._FAIL_COLOR}"
		return "✓", f"bold {self._OK_COLOR}"

	def _header(self) -> Text:
		glyph, gstyle = self._status_icon()
		arrow = "▼" if not self._collapsed else "▶"
		# runner type suffix so task/workflow/scan/shell/query are distinguishable
		kind = f" ({self.kind})"
		tail = f"  ·  {self.count} findings" if self.count else ""
		desc = self._desc()
		# ellipsise only the description so the icon + type + arrow stay on one line
		width = self.app.size.width if self.app else 100
		budget = max(12, width - len(kind) - len(tail) - 10)
		if len(desc) > budget:
			desc = desc[: budget - 1] + "…"
		t = Text()
		t.append(f"{glyph} ", style=gstyle)
		t.append(desc, style="#8a8fa3")
		t.append(kind, style="#5b6070")
		t.append(tail, style="#6b7187")
		t.append(f"  {arrow}", style="#6b7187")
		return t

	def on_mount(self) -> None:
		# animate the spinner while the runner is pending/running; stops at finish()
		self._spin_timer = self.set_interval(0.12, self._tick_spin)

	def _tick_spin(self) -> None:
		if self.done:
			return
		self._spin_frame = (self._spin_frame + 1) % len(self._SPIN)
		try:
			self._refresh_head()
		except Exception:  # noqa: BLE001 - head may be gone during teardown
			pass

	def mark_failed(self) -> None:
		"""An error was routed to this runner — show a red cross (on finish / now if done)."""
		self.failed = True
		try:
			self._refresh_head()
		except Exception:  # noqa: BLE001
			pass

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
		if self._spin_timer is not None:
			self._spin_timer.stop()   # stop animating: the icon is now a check/cross
			self._spin_timer = None
		for sp in self.subpanels.values():
			sp.finish()
		# a container is failed if any child failed (its own error may have landed on a child)
		if self.subpanels and any(sp.failed for sp in self.subpanels.values()):
			self.failed = True
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
	"""Navigable suggestion list for a follow-up ask, wired to the main input box.

	Single-choice: an OptionList (focused on appear — no mouse needed) plus a trailing
	"Something else" row. ↑/↓/Tab move the highlight and LIVE-COPY the focused option into
	the input box (empty for "Something else"), so the user can extend it; Tab past the last
	option focuses the input box to edit; Enter submits the input value. Multi-choice keeps a
	SelectionList (space toggles, enter confirms). Once answered it collapses to the picked
	value — click the summary to re-open."""

	_SOMETHING_ELSE = "✎ Something else (type your own)"

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
				yield OptionList(*self._choices, self._SOMETHING_ELSE, classes="choice-list")
				yield Static(Text.from_markup(
					"[dim]↑/↓/tab to move · the choice fills the input below (edit it) · enter to send[/]"))
		yield body

	def on_mount(self) -> None:
		self.query_one(".choice-summary").display = False
		# focus the list AFTER the first refresh so it reliably takes focus from the input
		# box (fixes needing a mouse click to interact with the choices)
		self.call_after_refresh(self._focus_list)

	def _focus_list(self) -> None:
		try:
			self.query_one(".choice-list").focus()
		except Exception:  # noqa: BLE001 - widget may be gone
			pass

	def _input(self):
		try:
			return self.app.query_one("#input-box Input")
		except Exception:  # noqa: BLE001
			return None

	def _set_input(self, text: str) -> None:
		inp = self._input()
		if inp is not None:
			inp.value = text

	def _is_something_else(self, index: int) -> bool:
		return not self._multiple and index == len(self._choices)

	def _summary_text(self) -> Text:
		arrow = "▶" if self._collapsed else "▼"
		t = Text()
		t.append("✓ ", style="green")
		t.append(self._value or "(none)", style="#8a8fa3")
		t.append(f"  {arrow}", style="#6b7187")
		return t

	def collapse_with(self, value: str) -> None:
		"""Collapse to the given answer WITHOUT re-resolving (used when the answer was
		submitted via the input box, which already resolved the pending ask)."""
		if self._value:
			return
		self._value = value
		for w in self.query(".choice-list"):
			w.disabled = True
		self._collapsed = True
		summary = self.query_one(".choice-summary", _ChoiceSummary)
		summary.update(self._summary_text())
		summary.display = True
		self.query_one(".choice-body").display = False

	def _done(self, value: str) -> None:
		# clear the shared input box so the NEXT ask doesn't inherit this answer (a plain
		# follow-up with no choices focuses the input — a stale value would be re-submittable)
		self._set_input("")
		self.collapse_with(value)
		self._resolve(value)

	def toggle_body(self) -> None:
		if not self._value:
			return
		self._collapsed = not self._collapsed
		self.query_one(".choice-body").display = not self._collapsed
		self.query_one(".choice-summary", _ChoiceSummary).update(self._summary_text())

	def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
		# live-copy the focused option into the input box so the user can extend it
		if self._value or self._multiple:
			return
		self._set_input("" if self._is_something_else(event.option_index) else self._choices[event.option_index])

	def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
		if self._value:   # ignore re-selection after answered
			return
		if self._is_something_else(event.option_index):
			# hand off to the input box for free typing (don't submit an empty answer)
			self._set_input("")
			inp = self._input()
			if inp is not None:
				inp.focus()
			return
		# submit the current input value (honors any edits the user typed in)
		inp = self._input()
		value = inp.value.strip() if inp is not None and inp.value.strip() else str(event.option.prompt)
		self._done(value)

	def on_key(self, event) -> None:
		if self._value:
			return
		if self._multiple and event.key == "enter":
			sel = self.query_one(SelectionList)
			picked = [self._choices[i] for i in sel.selected]
			if picked:
				event.stop()
				self._done(", ".join(picked))
			return
		# Tab moves the highlight down; past the last option it focuses the input box to edit.
		if not self._multiple and event.key == "tab":
			ol = self.query_one(OptionList)
			cur = ol.highlighted if ol.highlighted is not None else -1
			if cur < ol.option_count - 1:
				ol.highlighted = cur + 1
			else:
				inp = self._input()
				if inp is not None:
					inp.focus()
			event.stop()
			event.prevent_default()


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

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
from textual.widgets import Collapsible, Footer, Header, Input, Markdown, Static


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


class RunnerDrop:
	_ICON = {"task": "⚙", "workflow": "❖", "scan": "✦", "shell": "$", "query": "🔎"}

	def __init__(self, kind: str, name: str, runner_id: str = ""):
		self.kind = kind
		self.name = name
		self.runner_id = runner_id
		self.count = 0
		self.body = Vertical(classes="drop-body")
		self.collapsible = Collapsible(self.body, title=self._title(), collapsed=True, classes="runner")

	def _title(self, status: str = "running") -> str:
		icon = self._ICON.get(self.kind, "•")
		tail = f"{self.count} findings · {status}" if self.count or status != "running" else status
		return f"{icon} {self.kind}  {self.name}  ·  {tail}"

	def add_finding(self, d: dict) -> Static:
		self.count += 1
		self.collapsible.title = self._title()
		return Static(Text.from_markup(_finding_markup(d)), classes="drop-line")

	def add_raw(self, text: str) -> Static:
		return Static(Text(text), classes="drop-line")  # raw output: plain, never markup


class AITUI(App):
	CSS = """
	Screen { background: #0b0e14; }
	#convo { background: #0b0e14; border: round #2b3245; padding: 0 1; height: 1fr; }
	#convo:focus-within { border: round #3d6fb4; }
	.ai { color: #cdd6e4; }
	.user { color: #7fd1e0; margin: 1 0; }
	.err { color: #ff6b6b; }
	.runner { margin: 0 0 1 0; }
	.runner > CollapsibleTitle { color: #c2a0ff; background: #171a24; }
	.runner.-collapsed > CollapsibleTitle { color: #8a8fa3; }
	.drop-body { background: #10131b; border-left: thick #2b3245; padding: 0 1; }
	.drop-line { color: #cdd6e4; }
	Markdown { background: #0b0e14; margin: 0; padding: 0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	#input-box { border: round #3d6fb4; background: #10141c; height: 3; }
	Header { background: #141a26; color: #cdd6e4; }
	"""
	BINDINGS = [("ctrl+c", "quit", "Quit")]

	def __init__(self, runner_builder, session="ai", mode="chat", initial_prompt=""):
		super().__init__()
		self._runner_builder = runner_builder
		self._session = session
		self._mode = mode
		self._initial_prompt = initial_prompt or ""
		self._current: RunnerDrop | None = None
		self._steers: list[str] = []
		self._steers_lock = threading.Lock()
		self._pending_ask = None

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		yield VerticalScroll(id="convo")
		yield Static("", id="status")
		with Vertical(id="input-box"):
			yield Input(placeholder="Message, or steer a running runner…  (Enter to send)")
		yield Footer()

	def on_mount(self) -> None:
		self.title = "secator ai"
		self.sub_title = f"session: {self._session} · mode: {self._mode}"
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

	def _convo(self) -> VerticalScroll:
		return self.query_one("#convo", VerticalScroll)

	async def _append(self, widget) -> None:
		await self._convo().mount(widget)
		self._convo().scroll_end(animate=False)

	def _set_status(self, text: str, spinning: bool = True) -> None:
		s = self.query_one("#status", Static)
		if not text:
			s.update("")
			return
		dot = "[gold3]⠋[/] " if spinning else "[green]✓[/] "
		s.update(Text.from_markup(f"{dot}[gold3]{escape(text)}[/]"))

	async def _render(self, item) -> None:
		d = item.toDict() if hasattr(item, "toDict") else dict(item)
		t = d.get("_type")
		if t == "ai":
			await self._render_ai(d)
			return
		if t in ("info", "warning", "error"):
			color = {"info": "dim", "warning": "yellow", "error": "red"}[t]
			await self._append(Static(
				Text.from_markup(f"[{color}]{escape(str(d.get('message', '')))}[/]"), classes="ai"))
			return
		if t in ("progress", "stat", "state", "target"):  # execution / plumbing types
			return
		# a finding → into the current runner's dropdown (or top-level if none)
		if self._current is not None:
			await self._current.body.mount(self._current.add_finding(d))
		else:
			await self._append(Static(Text.from_markup(_finding_markup(d)), classes="drop-line"))

	async def _render_ai(self, d: dict) -> None:
		at = d.get("ai_type", "")
		content = d.get("content", "") or ""
		if at in ("prompt", "steer", "follow_up"):
			# user-origin / end-of-turn question: already echoed on submit or shown by
			# the ask_user prompt — don't double-render from the item stream
			return
		if at == "response":
			await self._append(Markdown(content, classes="ai"))  # AI text as Markdown
		elif at in ("task", "workflow", "scan", "query", "shell"):
			ed = d.get("extra_data") or {}
			kind = "shell" if at == "shell" else at
			name = content or ed.get("name") or ""
			self._current = RunnerDrop(kind, name, ed.get("runner_id", ""))
			await self._append(self._current.collapsible)
			self._set_status(f"running {kind} {name}")
		elif at == "shell_output":
			if self._current is not None:
				await self._current.body.mount(self._current.add_raw(content))
		elif at in ("mark_vuln_exploited", "add_vuln_poc"):
			await self._append(Static(Text.from_markup(f"[red]💥 {escape(content)}[/]"), classes="ai"))
		elif at in ("mark_vuln_false_positive", "mark_vuln_exploit_failed"):
			await self._append(Static(Text.from_markup(f"[yellow]{escape(content)}[/]"), classes="ai"))
		elif at == "error":
			await self._append(Static(Text.from_markup(f"[red]✖ {escape(content)}[/]"), classes="err"))
		elif at == "stopped":
			self._current = None
			self._set_status("stopped", False)

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
			holder["value"] = self._resolve_answer(text, choices, ptype)
			self._pending_ask = None
			ev.set()
			return
		with self._steers_lock:
			self._steers.append(text)

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

	def tui_ask_user(self, question, choices, prompt_type="follow_up", **context):
		ev = threading.Event()
		holder: dict = {}
		if prompt_type == "permission":
			hint = "[a]llow · [aa] allow-all · [d]eny"
		else:
			hint = "  ·  ".join(f"[{i + 1}] {c}" for i, c in enumerate(choices or []))
		self.call_from_thread(self._show_prompt, question, hint, (ev, holder, list(choices or []), prompt_type))
		ev.wait()
		return {"answer": holder.get("value")}

	def _show_prompt(self, question, hint, pending) -> None:
		self._pending_ask = pending
		self._convo().mount(
			Static(Text.from_markup(f"[b yellow]? {escape(question)}[/]\n[dim]{escape(hint)}[/]"), classes="ai"))
		self._convo().scroll_end(animate=False)
		self._set_status("waiting for your answer…")


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

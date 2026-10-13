"""Secator AI chat — Textual TUI driver (wiring experiment).

This is the DRIVER: it consumes the ai runner's real item stream
(``OutputType`` findings + ``Ai`` events) and renders each into the collapsible
TUI from ``ai_tui_draft``. Runner events (task/workflow/scan/shell) become
clickable dropdowns; findings land inside the current runner's dropdown; raw
shell output is plain text; target-controlled finding fields are markup-escaped.

Status: the RENDERER + item protocol are wired. The stream here is a synthetic
feed of REAL secator OutputType objects so it runs and screenshots without a
model. The live hookup is one line (see ``run_live`` at the bottom): iterate the
real ``ai`` runner instead of the demo stream — it needs an API key + a TTY.

    pip install textual
    python experiments/ai_tui_app.py            # demo (real OutputTypes, timed)
    python experiments/ai_tui_app.py --shot x.svg
"""
from __future__ import annotations

import sys
import threading
import time

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Collapsible, Footer, Header, Input, Static


# --- item -> markup --------------------------------------------------------

def _finding_markup(d: dict) -> str:
	"""One finding line. VALUES are markup-escaped — a finding field is
	target-controlled, so it must never inject markup (see #1513)."""
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
	"""A runner's collapsible dropdown + a body we can fill as findings stream in."""

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
		rid = f"  [dim]#{self.runner_id[:8]}[/]" if self.runner_id else ""
		return f"{icon} {self.kind}  {self.name}  ·  {tail}{rid}"

	def add_finding(self, d: dict) -> Static:
		self.count += 1
		self.collapsible.title = self._title()
		return Static(Text.from_markup(_finding_markup(d)), classes="drop-line")

	def add_raw(self, text: str) -> Static:
		# RAW runner/shell output — plain Text, never markup-parsed.
		return Static(Text(text), classes="drop-line")

	def done(self, status: str = "done") -> None:
		self.collapsible.title = self._title(status)


class AITUI(App):
	CSS = """
	Screen { background: #0b0e14; }
	#convo { background: #0b0e14; border: round #2b3245; padding: 0 1; height: 1fr; }
	#convo:focus-within { border: round #3d6fb4; }
	.ai { color: #cdd6e4; }
	.user { color: #7fd1e0; margin: 1 0; }
	.runner { margin: 0 0 1 0; }
	.runner > CollapsibleTitle { color: #c2a0ff; background: #171a24; }
	.runner.-collapsed > CollapsibleTitle { color: #8a8fa3; }
	.drop-body { background: #10131b; border-left: thick #2b3245; padding: 0 1; }
	.drop-line { color: #cdd6e4; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	#input-box { border: round #3d6fb4; background: #10141c; height: 3; }
	Header { background: #141a26; color: #cdd6e4; }
	"""
	BINDINGS = [("ctrl+c", "quit", "Quit")]

	def __init__(self, stream_factory, session="ai", mode="chat", delay=0.0, threaded=True):
		super().__init__()
		self._stream_factory = stream_factory
		self._session = session
		self._mode = mode
		self._delay = delay
		self._threaded = threaded
		self._current: RunnerDrop | None = None
		self._steers: "list[str]" = []

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		yield VerticalScroll(id="convo")
		yield Static("", id="status")
		with Vertical(id="input-box"):
			yield Input(placeholder="Message, or steer a running runner…  (Enter to send)")
		yield Footer()

	async def on_mount(self) -> None:
		self.title = "secator ai"
		self.sub_title = f"session: {self._session} · mode: {self._mode.upper()}"
		if self._threaded:
			threading.Thread(target=self._consume, daemon=True).start()
		else:
			# Headless screenshot: render on the UI thread, awaiting each mount.
			for item in self._stream_factory():
				await self._render(item)
			self._set_status("", False)

	# --- worker: drive the item stream, render each item on the UI thread ---
	def _consume(self) -> None:
		try:
			for item in self._stream_factory():
				self.call_from_thread(self._render, item)
				if self._delay:
					time.sleep(self._delay)
			self.call_from_thread(self._set_status, "", False)
		except Exception as e:  # noqa: BLE001
			self.call_from_thread(self._set_status, f"stream error: {e}", False)

	# --- rendering (UI thread) ----------------------------------------------
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
		# a finding → into the current runner's dropdown (or top-level if none)
		if self._current is not None:
			await self._current.body.mount(self._current.add_finding(d))
		else:
			await self._append(Static(Text.from_markup(_finding_markup(d)), classes="drop-line"))
		self._set_status(f"{self._current.name if self._current else 'workspace'} · {(self._current.count if self._current else 0)} findings")

	async def _render_ai(self, d: dict) -> None:
		at = d.get("ai_type", "")
		content = d.get("content", "") or ""
		if at == "response":
			await self._append(Static(Text.from_markup(f"[dim]ai ·[/] {escape(content)}"), classes="ai"))
		elif at == "steer":
			# the user's own mid-flight message — spaced, plain (no label, per feedback)
			await self._append(Static(Text.from_markup(f"[bold cyan]›[/] {escape(content)}"), classes="user"))
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
		elif at == "stopped":
			self._current = None
			self._set_status("done", False)

	# --- input → steer queue (a real backend drains this) -------------------
	def on_input_submitted(self, event: Input.Submitted) -> None:
		text = event.value.strip()
		event.input.value = ""
		if not text:
			return
		self._steers.append(text)
		self._append(Static(Text.from_markup(f"[bold cyan]›[/] {escape(text)}"), classes="user"))

	def poll_steers(self):
		out, self._steers = self._steers, []
		return out


# --- demo stream of REAL OutputType objects --------------------------------

def _demo_stream():
	from secator.output_types import Ai, Vulnerability, Port, Url, Tag
	wid = "a1b2c3d4e5"
	yield Ai(content="scan acme.com for web vulns and open ports", ai_type="steer")
	yield Ai(content="Running a web-vuln + port workflow on acme.com — expand a step to see its output.", ai_type="response")
	yield Ai(content="url_vuln", ai_type="workflow", extra_data={"runner_id": wid, "name": "url_vuln"})
	yield Vulnerability(name="CVE-2021-41773", severity="critical", matched_at="http://acme.com/cgi-bin/", _source="nuclei")
	yield Vulnerability(name="Missing HSTS", severity="low", matched_at="https://acme.com", _source="nuclei")
	yield Url(url="https://acme.com/login", status_code=200, _source="httpx")
	yield Url(url="https://acme.com/admin", status_code=403, _source="httpx")
	yield Port(port=443, ip="1.2.3.4", host="acme.com", state="open", _source="nmap")
	yield Ai(content="Critical CVE-2021-41773 (Apache path traversal → RCE). Verifying with a probe:", ai_type="response")
	yield Ai(content="curl", ai_type="shell", extra_data={"name": "curl -s http://acme.com/cgi-bin/.%2e/etc/passwd"})
	yield Ai(content="$ curl -s http://acme.com/cgi-bin/.%2e/%2e%2e/etc/passwd", ai_type="shell_output")
	yield Ai(content="root:x:0:0:root:/root:/bin/bash", ai_type="shell_output")
	yield Ai(content="daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", ai_type="shell_output")
	yield Ai(content="Confirmed RCE — marked exploited with PoC.", ai_type="mark_vuln_exploited")


def run_live(prompt: str, workspace: str = None):
	"""THE LIVE HOOKUP (needs API key + a real model + TTY). Build the ai runner and
	drive its generator into the TUI instead of the demo stream."""
	def stream():
		from secator.template import TemplateLoader
		from secator.runners.task import Task
		tpl = TemplateLoader(input="ai")
		runner = Task(tpl, [prompt], run_opts={"mode": "chat", "interactive": "local", "sync": True})
		# TODO wire: inject this app as the interactivity backend (poll_steers/ask_user/status)
		# and suppress the console exporter + _run_batch Live. For now just stream items.
		yield from runner
	AITUI(stream, session=workspace or "ai", mode="chat").run()


def _screenshot(path: str) -> None:
	import asyncio

	async def run() -> None:
		app = AITUI(_demo_stream, session="recon-acme", mode="scan", delay=0.0, threaded=False)
		async with app.run_test(size=(106, 40)) as pilot:
			await pilot.pause(0.3)
			app.save_screenshot(path)

	asyncio.run(run())
	print(f"wrote {path}")


if __name__ == "__main__":
	if len(sys.argv) >= 3 and sys.argv[1] == "--shot":
		_screenshot(sys.argv[2])
	else:
		AITUI(_demo_stream, session="recon-acme", mode="scan", delay=0.35).run()

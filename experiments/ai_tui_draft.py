"""Secator AI chat — Textual TUI draft (experiment).

Why: the Rich always-on-input experiment (#1485) hit Rich's hard limit — only ONE
`Live` display at a time — so the pinned input Live and the batch-progress Live
fight ("Only one live display may be active at once"). Textual is a real
multi-widget app framework (same author as Rich): independent widgets all update
at once — a scrollable conversation log, a live batch-progress panel, a status
line, and an always-on input, coexisting with no single-Live constraint.

This is a VISUAL DRAFT with mock data — not wired to the AI loop yet. Run it:

    pip install textual
    python experiments/ai_tui_draft.py           # interactive
    python experiments/ai_tui_draft.py --shot x.svg   # headless screenshot

Keys: Enter sends · Ctrl+B toggles a mock batch · Ctrl+C quits.
"""
from __future__ import annotations

import sys

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Footer, Header, Input, ProgressBar, RichLog, Static


class StatusLine(Static):
	"""One-line activity indicator, ABOVE the input (never mistaken for input)."""

	def set_activity(self, text: str, spinning: bool = True) -> None:
		dot = "[gold3]⠋[/] " if spinning else "[green]✓[/] "
		self.update(Text.from_markup(f"{dot}[gold3]{text}[/]"))


class BatchPanel(Vertical):
	"""Live progress for parallel runners — shown AT THE SAME TIME as the log and
	input (the exact combination Rich can't do with its single Live)."""

	def compose(self) -> ComposeResult:
		yield Static("[b]Running 3 tasks[/]", classes="panel-title")
		for name, total, done in (("nmap", 100, 80), ("httpx", 100, 100), ("nuclei", 100, 30)):
			row = ProgressBar(total=total, show_eta=False, id=f"pb-{name}")
			row.advance(done)
			yield Static(f"[cyan]{name:<8}[/]", classes="pb-label")
			yield row


class AIChat(App):
	CSS = """
	Screen { background: #0b0e14; }
	#log { background: #0b0e14; border: round #2b3245; padding: 0 1; height: 1fr; }
	#log:focus { border: round #3d6fb4; }
	#batch { height: auto; border: round #5a4b1f; background: #15130a; padding: 0 1; margin-top: 1; }
	#batch.hidden { display: none; }
	.panel-title { color: #d7a93b; }
	.pb-label { color: #7fd1e0; }
	ProgressBar { margin-bottom: 0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	#input-box { border: round #3d6fb4; background: #10141c; height: 3; }
	Input { background: #10141c; }
	Header { background: #141a26; color: #cdd6e4; }
	"""
	BINDINGS = [("ctrl+b", "toggle_batch", "Toggle batch"), ("ctrl+c", "quit", "Quit")]

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		yield RichLog(id="log", wrap=True, markup=True, highlight=False)
		with Vertical(BatchPanel(id="batch")):
			pass
		yield StatusLine(id="status")
		with Vertical(id="input-box"):
			yield Input(placeholder="Message, or steer a running scan…  (Enter to send)")
		yield Footer()

	def on_mount(self) -> None:
		self.title = "secator ai"
		self.sub_title = "session: recon-acme · mode: SCAN"
		log = self.query_one("#log", RichLog)
		w = log.write

		def ai(msg: str) -> None:
			w(Text.from_markup(f"[dim]ai ·[/] {msg}"))

		def user(msg: str) -> None:
			w(Text.from_markup(f"[bold cyan]›[/] {msg}"))

		# --- mock conversation / streamed findings ---
		user("scan acme.com for web vulns and open ports")
		w("")
		ai("Starting a web-vuln + port workflow on [b]acme.com[/] — streaming findings as they land.")
		w(Text.from_markup("[magenta]⌁ run_workflow[/]  [b]url_vuln[/]  →  workflow [dim]a1b2c3[/]"))
		w(Text.from_markup("   [red]●[/] [red]VULN[/]  ·  CVE-2021-41773  ·  [red]critical[/]  ·  http://acme.com/cgi-bin/  [dim](nuclei)[/]"))
		w(Text.from_markup("   [yellow]●[/] [yellow]VULN[/]  ·  Missing HSTS  ·  [yellow]low[/]  ·  https://acme.com  [dim](nuclei)[/]"))
		w(Text.from_markup("   [green]●[/] [green]PORT[/]  ·  443/tcp  ·  open  ·  http  [dim](nmap)[/]"))
		w(Text.from_markup("   [green]●[/] [green]PORT[/]  ·  22/tcp   ·  open  ·  ssh   [dim](nmap)[/]"))
		# steer: the user's own message, spaced above and below (per feedback — no label)
		w("")
		user("also enumerate subdomains while that runs")
		w("")
		ai("Queued [b]subdomain_recon[/] alongside the current run.")
		# status + batch panel both live at once
		self.query_one(StatusLine).set_activity("Running 3 tasks · 1 done · streaming findings")

	def action_toggle_batch(self) -> None:
		self.query_one("#batch").toggle_class("hidden")

	def on_input_submitted(self, event: Input.Submitted) -> None:
		text = event.value.strip()
		event.input.value = ""
		if not text:
			return
		log = self.query_one("#log", RichLog)
		# A sent message: blank line above and below so it stands out from streamed output.
		log.write("")
		log.write(Text.from_markup(f"[bold cyan]›[/] {text}"))
		log.write("")


def _screenshot(path: str) -> None:
	import asyncio

	async def run() -> None:
		app = AIChat()
		async with app.run_test(size=(104, 34)) as pilot:
			await pilot.pause()
			app.save_screenshot(path)

	asyncio.run(run())
	print(f"wrote {path}")


if __name__ == "__main__":
	if len(sys.argv) >= 3 and sys.argv[1] == "--shot":
		_screenshot(sys.argv[2])
	else:
		AIChat().run()

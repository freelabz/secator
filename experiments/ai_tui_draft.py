"""Secator AI chat — Textual TUI draft (experiment).

Why Textual, not Rich: the Rich always-on-input experiment (#1485) hit Rich's hard
limit — only ONE `Live` at a time — so the pinned input Live and the batch-progress
Live collide ("Only one live display may be active at once"). Textual is a real
multi-widget app framework (same author) with no such constraint, AND its widgets
are interactive — which unlocks the thing we want:

  Runner outputs (task / workflow / scan / shell) are NOT dumped verbatim like
  Rich does. Each is a CLICKABLE DROPDOWN (Collapsible): a one-line summary by
  default, expanding to the Rich-style output on demand. Findings produced by a
  runner live inside its dropdown.

This is a VISUAL DRAFT with mock data — not wired to the ai loop yet. Run it:

    pip install textual
    python experiments/ai_tui_draft.py            # interactive — click a dropdown
    python experiments/ai_tui_draft.py --shot x.svg   # headless screenshot

Keys: Enter sends · click/Enter a dropdown to toggle · Ctrl+B toggles the batch
panel · Ctrl+C quits.
"""
from __future__ import annotations

import sys

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import (
	Collapsible, Footer, Header, Input, ProgressBar, Static,
)


def line(markup: str) -> Static:
	"""A single conversation line from rich markup."""
	return Static(Text.from_markup(markup), classes="line")


def runner_drop(title: str, body: list[str], collapsed: bool = True, raw: bool = False) -> Collapsible:
	"""A runner (task/workflow/scan/shell) rendered as a clickable dropdown.

	Collapsed: just the summary title. Expanded: the Rich-style output (findings,
	raw output) — the body lines, styled like the console display.

	raw=True → body lines are RAW runner output (shell/tool stdout): render as
	plain text, NEVER markup-parsed, so `:x:`, `[bold]`, etc. in untrusted output
	can't turn into emoji/styling (or inject markup). findings use markup (raw=False).
	"""
	def cell(b: str):
		return Text(b) if raw else Text.from_markup(b)
	rows = [Static(cell(b), classes="drop-line") for b in body]
	return Collapsible(*rows, title=title, collapsed=collapsed, classes="runner")


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
		for name, done in (("nmap", 80), ("httpx", 100), ("nuclei", 30)):
			yield Static(f"[cyan]{name:<8}[/]", classes="pb-label")
			bar = ProgressBar(total=100, show_eta=False)
			bar.advance(done)
			yield bar


class AIChat(App):
	CSS = """
	Screen { background: #0b0e14; }
	#convo { background: #0b0e14; border: round #2b3245; padding: 0 1; height: 1fr; }
	#convo:focus-within { border: round #3d6fb4; }
	.line { padding: 0 0; }
	.user { margin: 1 0; }

	/* runner dropdowns */
	.runner { margin: 0 0 1 0; }
	.runner > CollapsibleTitle { color: #c2a0ff; background: #171a24; }
	.runner.-collapsed > CollapsibleTitle { color: #8a8fa3; }
	.runner Contents { background: #10131b; border-left: thick #2b3245; padding: 0 1; }
	.drop-line { color: #cdd6e4; }

	#batch { height: auto; border: round #5a4b1f; background: #15130a; padding: 0 1; margin-top: 1; }
	#batch.hidden { display: none; }
	.panel-title { color: #d7a93b; }
	.pb-label { color: #7fd1e0; }
	#status { height: 1; color: #d7a93b; padding: 0 1; }
	#input-box { border: round #3d6fb4; background: #10141c; height: 3; }
	Input { background: #10141c; }
	Header { background: #141a26; color: #cdd6e4; }
	"""
	BINDINGS = [("ctrl+b", "toggle_batch", "Batch"), ("ctrl+c", "quit", "Quit")]

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		with VerticalScroll(id="convo"):
			yield line("[bold cyan]›[/] scan acme.com for web vulns and open ports")
			yield line("[dim]ai ·[/] Running a web-vuln + port workflow on [b]acme.com[/] — I'll summarize; expand a step to see its output.")
			# a workflow: collapsed dropdown with its findings inside
			yield runner_drop(
				"run_workflow  url_vuln  ·  4 findings (1 critical)  ·  done · 42s",
				[
					"[red]●[/] [red]VULN[/]  ·  CVE-2021-41773  ·  [red]critical[/]  ·  http://acme.com/cgi-bin/  [dim](nuclei)[/]",
					"[yellow]●[/] [yellow]VULN[/]  ·  Missing HSTS  ·  [yellow]low[/]  ·  https://acme.com  [dim](nuclei)[/]",
					"[green]●[/] [green]URL[/]   ·  200  ·  https://acme.com/login  [dim](httpx)[/]",
					"[green]●[/] [green]URL[/]   ·  403  ·  https://acme.com/admin  [dim](httpx)[/]",
				],
				collapsed=True,
			)
			yield line("[dim]ai ·[/] A critical [b]CVE-2021-41773[/] (Apache path traversal → RCE). Verifying with a quick probe:")
			# a shell: EXPANDED dropdown, Rich-style raw output
			yield runner_drop(
				"run_shell  ·  curl -s http://acme.com/cgi-bin/.%2e/.%2e/etc/passwd  ·  exit 0",
				[
					"$ curl -s http://acme.com/cgi-bin/.%2e/%2e%2e/etc/passwd",
					"root:x:0:0:root:/root:/bin/bash",
					"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
					"… 24 more lines",
				],
				collapsed=False, raw=True,
			)
			yield line("[green]✓[/] [dim]ai ·[/] Confirmed RCE — marked [b]exploited[/] with PoC.")
			# steer: the user's own message, spaced above and below (no label)
			yield line("[bold cyan]›[/] also enumerate subdomains while that runs", )
			yield line("[dim]ai ·[/] Queued [b]subdomain_recon[/] alongside the current run.")
		with Vertical(BatchPanel(id="batch")):
			pass
		yield StatusLine(id="status")
		with Vertical(id="input-box"):
			yield Input(placeholder="Message, or steer a running scan…  (Enter to send)")
		yield Footer()

	def on_mount(self) -> None:
		self.title = "secator ai"
		self.sub_title = "session: recon-acme · mode: SCAN"
		self.query_one(StatusLine).set_activity("Running 3 tasks · 1 done · streaming findings")
		# space the steer line (it's a user message mid-stream)
		for w in self.query(".line"):
			pass

	def action_toggle_batch(self) -> None:
		self.query_one("#batch").toggle_class("hidden")

	def on_input_submitted(self, event: Input.Submitted) -> None:
		text = event.value.strip()
		event.input.value = ""
		if not text:
			return
		convo = self.query_one("#convo", VerticalScroll)
		# A sent message: blank line above and below so it stands out from streamed output.
		msg = line(f"[bold cyan]›[/] {text}")
		msg.add_class("user")
		convo.mount(msg)
		convo.scroll_end(animate=False)


def _screenshot(path: str) -> None:
	import asyncio

	async def run() -> None:
		app = AIChat()
		async with app.run_test(size=(106, 40)) as pilot:
			await pilot.pause()
			app.save_screenshot(path)

	asyncio.run(run())
	print(f"wrote {path}")


if __name__ == "__main__":
	if len(sys.argv) >= 3 and sys.argv[1] == "--shot":
		_screenshot(sys.argv[2])
	else:
		AIChat().run()

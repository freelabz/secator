"""Rendering helpers for the secator TUI.

Generic (not AI-specific): turn secator items into Textual-ready Rich renderables,
reusing each OutputType's own ``__rich__`` so findings / info lines look exactly like
secator's console. Reusable by any TUI frontend (the AI task today, normal task /
workflow output later).
"""
import re

from rich.markup import escape
from rich.text import Text


def markdown_text(content: str):
	"""Render AI markdown with secator's own renderer (``CustomMarkdown``) so TUI responses
	look like the console (e.g. left-justified headings) instead of Textual's native Markdown.

	Returns a Rich renderable to drop into a Textual ``Static`` (width-aware: it reflows to the
	widget on render). Collapses 3+ blank lines to one, matching the console path.
	"""
	from secator.rich import CustomMarkdown
	text = re.sub(r"\n{3,}", "\n\n", content or "")
	return CustomMarkdown(text)


def command_text(cmd: str) -> Text:
	"""Render a '$ <cmd>' line with bash syntax highlighting.

	Uses Rich's Syntax highlighter (pygments), which returns a Text here. Cost is
	~0.1 ms per command and runs ONCE per runner (only the command line — never the raw
	output), so it adds no perceptible overhead. Falls back to dim plain text on error.
	"""
	t = Text("$ ", style="dim")
	try:
		from rich.syntax import Syntax
		hl = Syntax(cmd, "bash", theme="ansi_dark", background_color="default").highlight(cmd)
		hl.rstrip()   # highlight() appends a trailing newline
		t.append_text(hl)
	except Exception:  # noqa: BLE001
		t.append(cmd, style="dim")
	return t


def rehydrate(d: dict):
	"""Rebuild an OutputType from a plain dict (e.g. query results arrive as dicts) so
	we can use its own __rich__ rendering."""
	from secator.output_types import FINDING_TYPES
	t = d.get("_type")
	for cls in FINDING_TYPES:
		try:
			if cls.get_name() == t:
				return cls.load(d)
		except Exception:  # noqa: BLE001
			return None
	return None


def finding_text(item, d: dict) -> Text:
	"""Render a finding EXACTLY like secator's console: use the OutputType's own
	__rich__ (icons, fields, colors). Falls back to a compact line if that fails."""
	obj = item if hasattr(item, "__rich__") else rehydrate(d)
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
	return Text.from_markup(finding_markup(d))


def message_text(item, d: dict):
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


def finding_markup(d: dict) -> str:
	"""Compact fallback markup when an OutputType can't be rehydrated/rendered."""
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

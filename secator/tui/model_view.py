"""Model view for the ``ai`` TUI: the conversation exactly as the model receives it.

The ``ai`` task keeps a model-facing history (``ChatHistory.messages``): the system prompt,
the user turns, the per-iteration instructions the loop injects under the ``user`` role, the
assistant replies with their raw tool calls, and each tool result. When the sensitive-data
encryptor is on, every one of those messages is stored ALREADY encrypted — hosts, IPs,
emails and custom patterns appear as their ``[TYPE:hash]`` placeholders, the same text that
was sent. The model view renders that history verbatim, so it never has to re-encrypt
anything: no new placeholder is minted and the encryptor's map is never touched.

Pure helpers live here (no Textual import) so they can be unit-tested without an app.
"""
from __future__ import annotations

import hashlib
import json

from rich.text import Text

from secator.ai.encryption import _PLACEHOLDER_RE, find_placeholders
from secator.ai.history import classify_user_message

# Style of a placeholder inside a model-view message (the encrypted value as sent).
PLACEHOLDER_STYLE = "bold #c2a0ff"
# Tool results longer than this many lines start collapsed (click the header to expand).
COLLAPSE_LINES = 20

MODEL_VIEW_ON = "Model view on: showing what the model receives"
MODEL_VIEW_OFF = "Model view off"


def highlight_placeholders(text: str, style: str = "") -> Text:
	"""``text`` as a Rich ``Text`` (no markup parsing) with every placeholder highlighted."""
	out = Text(text or "", style=style)
	for m in _PLACEHOLDER_RE.finditer(text or ""):
		out.stylize(PLACEHOLDER_STYLE, m.start(), m.end())
	return out


def _content_text(content) -> str:
	"""A message ``content`` as text: strings as-is, multi-part content (lists of text
	blocks) joined, anything else as JSON."""
	if content is None:
		return ""
	if isinstance(content, str):
		return content
	if isinstance(content, list):
		parts = []
		for part in content:
			if isinstance(part, dict) and isinstance(part.get("text"), str):
				parts.append(part["text"])
			else:
				parts.append(json.dumps(part, ensure_ascii=False, default=str))
		return "\n".join(parts)
	return json.dumps(content, ensure_ascii=False, default=str)


def _tool_call_text(tc) -> "tuple[str, str]":
	"""``(name, arguments)`` of a raw tool call, arguments pretty-printed when they are JSON."""
	fn = (tc.get("function") or {}) if isinstance(tc, dict) else {}
	name = str(fn.get("name") or "tool")
	args = fn.get("arguments")
	if isinstance(args, str):
		try:
			args = json.loads(args)
		except ValueError:
			return name, args
	if args is None:
		return name, ""
	return name, json.dumps(args, ensure_ascii=False, indent=2, default=str)


def model_view_entries(messages) -> list:
	"""One display entry per model-facing message (and per raw tool call), in send order.

	Each entry is a dict: ``role`` (system/user/assistant/tool_call/tool), ``label`` (the
	header), ``body`` (the exact text sent or received) and ``collapsed`` (start folded:
	the system prompt and long tool results). Reads ``messages`` only — never mutates them.
	"""
	entries = []
	for m in messages or []:
		if not isinstance(m, dict):
			continue
		role = m.get("role") or ""
		body = _content_text(m.get("content"))
		if role == "system":
			entries.append({
				"role": "system", "label": f"system prompt · {len(body):,} chars",
				"body": body, "collapsed": True})
		elif role == "user":
			kind, _ = classify_user_message(body)
			label = {
				"internal": "user · loop instruction",
				"summary": "user · summary of earlier turns",
			}.get(kind, "user")
			entries.append({"role": "user", "label": label, "body": body, "collapsed": False})
		elif role == "assistant":
			if body.strip():
				entries.append({"role": "assistant", "label": "assistant", "body": body, "collapsed": False})
			for tc in m.get("tool_calls") or []:
				name, args = _tool_call_text(tc)
				cid = tc.get("id") if isinstance(tc, dict) else ""
				label = f"tool call · {name}" + (f" · {cid}" if cid else "")
				entries.append({"role": "tool_call", "label": label, "body": args, "collapsed": False})
		elif role == "tool":
			name = m.get("name") or ""
			cid = m.get("tool_call_id") or ""
			lines = body.count("\n") + 1 if body else 0
			label = "tool result" + (f" · {name}" if name else "") + (f" · {cid}" if cid else "")
			collapsed = lines > COLLAPSE_LINES
			if collapsed:
				label += f" · {lines} lines"
			entries.append({"role": "tool", "label": label, "body": body, "collapsed": collapsed})
		else:
			entries.append({"role": role or "message", "label": role or "message", "body": body, "collapsed": False})
	return entries


def model_view_summary(messages, encrypted: bool) -> str:
	"""The second banner line: message count + how many distinct encrypted values were sent."""
	n = sum(1 for m in messages or [] if isinstance(m, dict))
	head = f"{n} message{'s' if n != 1 else ''}"
	if not encrypted:
		return f"{head} · sensitive-data encryption is off: values are sent as written"
	found = set()
	for m in messages or []:
		if isinstance(m, dict):
			found.update(find_placeholders(_content_text(m.get("content"))))
			for tc in m.get("tool_calls") or []:
				found.update(find_placeholders(_tool_call_text(tc)[1]))
	k = len(found)
	return f"{head} · {k} encrypted value{'s' if k != 1 else ''} shown as placeholders"


def message_signature(m) -> str:
	"""A stable digest of one message (role, content, tool calls), used to tell an appended
	history from a rewritten one (compaction, a new system prompt) between refreshes."""
	if not isinstance(m, dict):
		return ""
	payload = {k: m.get(k) for k in ("role", "content", "tool_calls", "tool_call_id", "name")}
	raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
	return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).hexdigest()

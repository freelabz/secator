"""User-provided AI context files (`~/.secator/templates/ai/*.md`).

Each file is a Markdown document with an optional YAML frontmatter block that
scopes *when* it is autoloaded onto the system prompt. The frontmatter keys:

``type``: ``context`` (default) | ``rule`` | ``mode``. ``context`` and ``rule``
are both injected into the system prompt, each wrapped in its own
``<type:filename>`` block so the model can attribute a rule to its file.
``mode`` is reserved for a future custom-system-prompt feature and is not
injected yet.
``modes``: str | list. Omitted / empty => all modes (scan, chat, exploit).
``workspaces``: str | dict | list. Omitted / empty => all workspaces. A bare
string matches a workspace NAME or ID (exact); a mapping forces the
interpretation — ``{id: ...}``, ``{name: ...}`` or ``{regex: ...}`` (the regex
is ``re.search``-ed against the workspace name).

A file with no frontmatter is global (all modes, all workspaces). Everything
after the frontmatter (the body) is appended verbatim to the system prompt.

Profiles can also pull a file in explicitly via an ``ai_context`` key, so running
with a custom profile loads engagement context regardless of the frontmatter
scope (an explicit include always wins — frontmatter scope is NOT re-checked).

Example file (``~/.secator/templates/ai/acme.md``); the frontmatter below scopes
it to scan+exploit modes on any ``acme-*`` workspace:

	---
	modes: [scan, exploit]
	workspaces:
	  - regex: ^acme-.*$
	---
	Scope is 10.0.0.0/8. Out of scope: 10.9.0.0/16 (prod DB).
"""
import re
from pathlib import Path

import yaml

from secator.config import CONFIG
from secator.output_types import Warning
from secator.rich import console

# Frontmatter delimiter: a file starts with `---\n`, the YAML block, then `---`.
_FRONTMATTER = re.compile(r'^---\s*\n(.*?)\n---\s*\n?', re.DOTALL)

# Cap a single context body so a runaway note can't blow up the system prompt /
# token budget. Oversized bodies are truncated (with a marker) rather than dropped.
_MAX_BODY_CHARS = 20000

# `type:` frontmatter — what the file is. `context` (default) and `rule` are both
# injected into the system prompt, each wrapped in its own `<type:filename>` block
# so the model can attribute a rule to its file. `mode` is RESERVED for a future
# custom-system-prompt feature and is NOT injected as context yet.
_DEFAULT_TYPE = 'context'
_TYPES = ('context', 'rule', 'mode')
_APPEND_TYPES = ('context', 'rule')


def _ai_context_dir():
	return Path(CONFIG.dirs.templates) / 'ai'


def _parse(path):
	"""Split a context file into (frontmatter_dict, body).

	Any read/parse error is surfaced as a Warning and the file is skipped (returns
	None) rather than crashing a run — a malformed or unreadable engagement note
	must never take down the AI task.
	"""
	try:
		text = path.read_text()
	except (OSError, UnicodeDecodeError) as e:
		console.print(Warning(message=f'Skipping AI context {path.name}: unreadable ({e}).'))
		return None
	meta, body = {}, text
	match = _FRONTMATTER.match(text)
	if match:
		try:
			meta = yaml.safe_load(match.group(1)) or {}
		except yaml.YAMLError as e:
			console.print(Warning(message=f'Skipping AI context {path.name}: bad frontmatter ({e}).'))
			return None
		if not isinstance(meta, dict):
			console.print(Warning(message=f'Skipping AI context {path.name}: frontmatter is not a mapping.'))
			return None
		if not _valid_scope_types(path.name, meta):
			return None
		body = text[match.end():]
	body = body.strip()
	if len(body) > _MAX_BODY_CHARS:
		console.print(Warning(message=f'Truncating AI context {path.name}: body exceeds {_MAX_BODY_CHARS} chars.'))
		body = body[:_MAX_BODY_CHARS] + '\n... [truncated]'
	return meta, body


def _valid_scope_types(name, meta):
	"""Reject scope keys with the wrong shape (fail-soft: warn + skip the file).

	``modes`` must be a str or list; ``workspaces`` a str, mapping or list. A
	mapping with a non-string ``regex`` would blow up ``re.search`` later, so it
	is rejected here too.
	"""
	ctype = meta.get('type')
	if ctype is not None and (not isinstance(ctype, str) or ctype not in _TYPES):
		console.print(Warning(message=f'Skipping AI context {name}: `type` must be one of {", ".join(_TYPES)}.'))
		return False
	modes = meta.get('modes')
	if modes is not None and not isinstance(modes, (str, list)):
		console.print(Warning(message=f'Skipping AI context {name}: `modes` must be a string or list.'))
		return False
	workspaces = meta.get('workspaces')
	if workspaces is None:
		return True
	if not isinstance(workspaces, (str, dict, list)):
		console.print(Warning(message=f'Skipping AI context {name}: `workspaces` must be a string, mapping or list.'))
		return False
	specs = workspaces if isinstance(workspaces, list) else [workspaces]
	for spec in specs:
		if isinstance(spec, dict) and 'regex' in spec and not isinstance(spec['regex'], str):
			console.print(Warning(message=f'Skipping AI context {name}: `regex` selector must be a string.'))
			return False
	return True


def _mode_matches(meta, mode):
	modes = meta.get('modes')
	if not modes:  # omitted / empty => all modes
		return True
	if isinstance(modes, str):
		modes = [modes]
	return mode in modes


def _one_workspace_matches(spec, name, wid):
	"""Match a single workspace selector against the current (name, id)."""
	if isinstance(spec, str):  # bare string => name OR id (exact)
		return spec == name or spec == wid
	if isinstance(spec, dict):
		if 'regex' in spec:
			try:
				return bool(name and re.search(spec['regex'], name))
			except re.error as e:
				console.print(Warning(message=f'Invalid AI context workspace regex {spec["regex"]!r}: {e}.'))
				return False
		if 'name' in spec:
			return spec['name'] == name
		if 'id' in spec:
			return spec['id'] == wid
	return False


def _workspace_matches(meta, name, wid):
	workspaces = meta.get('workspaces')
	if not workspaces:  # omitted / empty => all workspaces
		return True
	if isinstance(workspaces, (str, dict)):
		workspaces = [workspaces]
	return any(_one_workspace_matches(s, name, wid) for s in workspaces)


def load_context_blocks(mode, workspace_name=None, workspace_id=None, includes=None):
	"""Return the extra prompt bodies to append, in sorted-filename order.

	Args:
		mode: active AI mode (scan/chat/exploit/...).
		workspace_name: current workspace name (for frontmatter workspace scope).
		workspace_id: current workspace id (for frontmatter workspace scope).
		includes: filenames (from profiles' ``ai_context``) that are ALWAYS loaded,
			bypassing the frontmatter mode/workspace scope.

	Returns:
		list[str]: rendered context blocks, each wrapped as
		``<type:filename>\n<body>\n</type>`` (type is ``context`` or ``rule``),
		deterministically ordered by filename. ``type: mode`` files are skipped
		(reserved for a future feature).
	"""
	ctx_dir = _ai_context_dir()
	if not ctx_dir.is_dir():
		return []
	includes = {Path(i).name for i in (includes or [])}
	blocks = []
	for path in sorted(ctx_dir.glob('*.md')):
		parsed = _parse(path)
		if parsed is None:
			continue
		meta, body = parsed
		if not body:
			continue
		ctype = meta.get('type') or _DEFAULT_TYPE
		if ctype not in _APPEND_TYPES:  # e.g. `type: mode` — reserved, not injected yet
			continue
		forced = path.name in includes
		if forced or (_mode_matches(meta, mode) and _workspace_matches(meta, workspace_name, workspace_id)):
			# Tag each block with its type + filename so the model can tell which
			# user rule/context came from which file.
			blocks.append(f'<{ctype}:{path.name}>\n{body}\n</{ctype}>')
	return blocks

"""User-provided AI context files (`~/.secator/templates/ai/**/*.md`).

Files are discovered recursively, so they can be organised in subfolders (e.g.
``ai/rules/no-destructive.md``, ``ai/engagements/acme.md``). Hidden files and
folders (``.git``, ``.obsidian``, editor swap files, ...) are ignored, symlinked
folders are followed once (loops are skipped), and files are loaded in the
order of their path relative to ``ai/`` (POSIX, sorted).

Each file is a Markdown document with an optional YAML frontmatter block that
scopes *when* it is autoloaded onto the system prompt. The frontmatter keys:

``type``: ``context`` (default) | ``rule`` | ``mode``. ``context`` and ``rule``
are both injected into the system prompt, each wrapped in its own
``<type:relative/path.md>`` block so the model can attribute a rule to its file.
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
An include is matched against the path relative to ``ai/`` first (``rules/x.md``;
a bare ``x.md`` therefore picks the top-level file), then by file name when
exactly one file has that name. An ambiguous file name (several subfolders hold
it) or an unknown include is reported as a Warning and loads nothing.

Example file (``~/.secator/templates/ai/acme.md``); the frontmatter below scopes
it to scan+exploit modes on any ``acme-*`` workspace:

	---
	modes: [scan, exploit]
	workspaces:
	  - regex: ^acme-.*$
	---
	Scope is 10.0.0.0/8. Out of scope: 10.9.0.0/16 (prod DB).
"""
import os
import re
from pathlib import Path, PurePosixPath

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
# injected into the system prompt, each wrapped in its own `<type:relpath>` block
# so the model can attribute a rule to its file. `mode` is RESERVED for a future
# custom-system-prompt feature and is NOT injected as context yet.
_DEFAULT_TYPE = 'context'
_TYPES = ('context', 'rule', 'mode')
_APPEND_TYPES = ('context', 'rule')


def _ai_context_dir():
	return Path(CONFIG.dirs.templates) / 'ai'


def _parse(path, label=None):
	"""Split a context file into (frontmatter_dict, body).

	Any read/parse error is surfaced as a Warning and the file is skipped (returns
	None) rather than crashing a run — a malformed or unreadable engagement note
	must never take down the AI task.
	"""
	name = label or path.name
	try:
		text = path.read_text()
	except (OSError, UnicodeDecodeError) as e:
		console.print(Warning(message=f'Skipping AI context {name}: unreadable ({e}).'))
		return None
	meta, body = {}, text
	match = _FRONTMATTER.match(text)
	if match:
		try:
			meta = yaml.safe_load(match.group(1)) or {}
		except yaml.YAMLError as e:
			console.print(Warning(message=f'Skipping AI context {name}: bad frontmatter ({e}).'))
			return None
		if not isinstance(meta, dict):
			console.print(Warning(message=f'Skipping AI context {name}: frontmatter is not a mapping.'))
			return None
		if not _valid_scope_types(name, meta):
			return None
		body = text[match.end():]
	body = body.strip()
	if len(body) > _MAX_BODY_CHARS:
		console.print(Warning(message=f'Truncating AI context {name}: body exceeds {_MAX_BODY_CHARS} chars.'))
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


def _iter_context_files(ctx_dir):
	"""Yield ``(relative_posix_path, path)`` for every ``*.md`` under ``ctx_dir``.

	Hidden files / folders are skipped. Symlinked folders are followed, but each
	real folder is visited once so a symlink loop can't recurse forever. Sorted by
	relative path for a deterministic prompt.
	"""
	found = []
	seen_dirs = set()
	for root, dirs, files in os.walk(ctx_dir, followlinks=True):
		real = os.path.realpath(root)
		if real in seen_dirs:
			dirs[:] = []
			continue
		seen_dirs.add(real)
		# Sorted (real folders before symlinked ones) so the spelling kept for a folder
		# reachable through a symlink is deterministic.
		dirs[:] = sorted(
			(d for d in dirs if not d.startswith('.')),
			key=lambda d: (os.path.islink(os.path.join(root, d)), d))
		for name in files:
			if name.startswith('.') or not name.endswith('.md'):
				continue
			path = Path(root) / name
			if not path.is_file():
				continue
			found.append((path.relative_to(ctx_dir).as_posix(), path))
	return sorted(found, key=lambda item: item[0])


def _resolve_includes(includes, files, ctx_dir):
	"""Map profile ``ai_context`` entries to relative paths of context files.

	Each entry matches by relative path first (so a bare name picks the top-level
	file), then by file name when exactly one file has that name. An absolute path
	is matched against the real path of each discovered file (so it works through
	symlinked folders). Ambiguous or unknown entries are warned about and skipped.
	"""
	rel_paths = {rel for rel, _ in files}
	by_real = {}
	for rel, path in files:
		by_real.setdefault(os.path.realpath(path), rel)
	resolved = set()
	by_name = {}
	for rel in sorted(rel_paths):
		by_name.setdefault(PurePosixPath(rel).name, []).append(rel)
	for inc in includes or []:
		if not isinstance(inc, str) or not inc.strip():
			continue
		inc = inc.strip().replace('\\', '/')
		path = Path(inc).expanduser()
		if path.is_absolute() and os.path.realpath(path) in by_real:
			resolved.add(by_real[os.path.realpath(path)])
			continue
		rel = PurePosixPath(inc).as_posix()  # also drops a leading './'
		if rel in rel_paths:
			resolved.add(rel)
			continue
		matches = by_name.get(PurePosixPath(rel).name, [])
		if len(matches) == 1:
			resolved.add(matches[0])
		elif matches:
			console.print(Warning(message=(
				f'AI context include {inc!r} is ambiguous ({", ".join(matches)}): '
				'use the path relative to the ai/ folder.')))
		else:
			console.print(Warning(message=f'AI context include {inc!r} not found in {ctx_dir}.'))
	return resolved


def load_context_blocks(mode, workspace_name=None, workspace_id=None, includes=None):
	"""Return the extra prompt bodies to append, in sorted relative-path order.

	Args:
		mode: active AI mode (scan/chat/exploit/...).
		workspace_name: current workspace name (for frontmatter workspace scope).
		workspace_id: current workspace id (for frontmatter workspace scope).
		includes: file names or paths relative to the ``ai/`` folder (from profiles'
			``ai_context``) that are ALWAYS loaded, bypassing the frontmatter
			mode/workspace scope.

	Returns:
		list[str]: rendered context blocks, each wrapped as
		``<type:relative/path.md>\n<body>\n</type>`` (type is ``context`` or
		``rule``), deterministically ordered by relative path. ``type: mode`` files
		are skipped (reserved for a future feature).
	"""
	ctx_dir = _ai_context_dir()
	if not ctx_dir.is_dir():
		return []
	files = _iter_context_files(ctx_dir)
	forced_paths = _resolve_includes(includes, files, ctx_dir)
	blocks = []
	for rel, path in files:
		parsed = _parse(path, rel)
		if parsed is None:
			continue
		meta, body = parsed
		if not body:
			continue
		ctype = meta.get('type') or _DEFAULT_TYPE
		if ctype not in _APPEND_TYPES:  # e.g. `type: mode` — reserved, not injected yet
			continue
		forced = rel in forced_paths
		if forced or (_mode_matches(meta, mode) and _workspace_matches(meta, workspace_name, workspace_id)):
			# Tag each block with its type + relative path so the model can tell which
			# user rule/context came from which file.
			blocks.append(f'<{ctype}:{rel}>\n{body}\n</{ctype}>')
	return blocks

# secator/ai/session.py
"""AI session management - save, list, pick, replay."""
import glob
import json
from datetime import datetime
from pathlib import Path

from secator.config import CONFIG
from secator.output_types import Error, Warning
from secator.rich import console


def save_history(history, reports_folder, debug_fn=None):
	"""Save chat history to reports/history.json; best-effort, warns via debug_fn or console on failure."""
	try:
		history_path = Path(reports_folder) / 'history.json'
		with open(history_path, 'w', encoding='utf-8') as f:
			json.dump(history.messages, f, indent=2)
		if debug_fn:
			debug_fn(f'Saved history to {history_path}', sub='llm')
	except (OSError, TypeError) as e:
		if debug_fn:
			debug_fn(f'Failed to save history: {e}', sub='llm')
		else:
			console.print(Warning(message=f'Failed to save history: {e}'))


def list_sessions(max_sessions=20):
	"""Scan reports folders for AI sessions with history.json; return dicts
	sorted by mtime (most recent first), capped at max_sessions."""
	sessions = []
	pattern = str(Path(CONFIG.dirs.reports) / '*/tasks/*/history.json')
	for history_path_str in glob.glob(pattern):
		history_path = Path(history_path_str)
		report_path = history_path.parent / 'report.json'
		if not report_path.exists():
			continue
		try:
			with open(report_path) as f:
				data = json.load(f)
			ai_items = data.get('results', {}).get('ai', [])
			if not ai_items:
				continue
			# Find first user prompt content and session name
			first_prompt = ''
			session_name = ''
			for item in ai_items:
				if item.get('ai_type') == 'prompt':
					first_prompt = item.get('content', '')
					session_name = (item.get('_context') or {}).get('session_name', '') or (item.get('_context') or {}).get('name', '')
					break
			# session_id: first non-empty `_context.session_id` across ALL ai docs (every
			# persisted item stamps it) -- lets a resumed run adopt this session's id.
			session_id = ''
			for item in ai_items:
				sid = (item.get('_context') or {}).get('session_id', '')
				if sid:
					session_id = sid
					break
			info = data.get('info', {})
			sessions.append({
				'folder': str(history_path.parent),
				'history_path': str(history_path),
				'report_path': str(report_path),
				'name': session_name,
				'prompt': first_prompt,
				'session_id': session_id,
				'targets': info.get('targets', []),
				'timestamp': info.get('end_time') or info.get('start_time') or 0,
				'mtime': history_path.stat().st_mtime,
			})
		except (json.JSONDecodeError, OSError):
			continue

	sessions.sort(key=lambda s: s['mtime'], reverse=True)
	return sessions[:max_sessions]


def show_session_picker():
	"""Show interactive menu to pick a session to resume; returns the selected session dict, or None if cancelled."""
	from secator.rich import InteractiveMenu

	sessions = list_sessions()
	if not sessions:
		console.print(Warning(message='No previous AI sessions found.'))
		return None

	import shutil
	term_width = shutil.get_terminal_size().columns
	# Reserve space for menu chrome (prefix "❯ N. " ~7 chars + padding)
	max_label = term_width - 10

	options = []
	for s in sessions:
		name = s.get('name', '')
		prompt = s.get('prompt', '')
		# Only show bracket label when name is an explicit custom name, not auto-derived from the prompt
		if name and prompt and name != prompt and not prompt.startswith(name.rstrip('.')):
			label_text = f"[{name}] {prompt}"
		else:
			label_text = prompt or name
		prompt_preview = label_text[:max_label]
		if len(label_text) > max_label:
			prompt_preview += '...'
		ts = datetime.fromtimestamp(s['mtime']).strftime('%Y-%m-%d %H:%M')
		targets = ', '.join(s['targets'][:2]) if s['targets'] else 'no target'
		workspace = s['folder'].split('/tasks/')[0].split('/')[-1] if '/tasks/' in s['folder'] else ''
		description = f"{ts} - {workspace} - {targets}"
		options.append({"label": prompt_preview, "description": description})
	options.append({"label": "Cancel"})

	result = InteractiveMenu("Resume a session", options).show()
	if result is None:
		return None
	idx, _ = result
	if idx >= len(sessions):
		return None
	return sessions[idx]


def print_session_results(session):
	"""Print a prior session's persisted results in ``_timestamp`` order -- the
	"here's where you left off" replay shown on resume. Reads ``report.json``;
	best-effort (never raises) so a display error can't block a resume."""
	from secator.output_types import OUTPUT_TYPES

	report_path = session.get('report_path')
	if not report_path:
		return
	type_map = {cls.__name__.lower(): cls for cls in OUTPUT_TYPES}
	try:
		with open(report_path) as f:
			data = json.load(f)
	except (json.JSONDecodeError, OSError):
		return
	# Flatten all items with their type class, then print in timestamp order
	all_items = []
	for type_name, items in data.get('results', {}).items():
		cls = type_map.get(type_name)
		if not cls:
			continue
		for item_data in items:
			all_items.append((item_data, cls))
	all_items.sort(key=lambda x: x[0].get('_timestamp', 0))
	for item_data, cls in all_items:
		try:
			console.print(cls.load(item_data), highlight=False)
		except Exception:
			continue


def replay_session(session):
	"""Replay all results from a previous session and restore history; returns None on error."""
	from secator.ai.history import ChatHistory

	# Show the prior conversation + findings on the console
	print_session_results(session)

	# Load history
	history_path = session['history_path']
	try:
		with open(history_path) as f:
			messages = json.load(f)
		history = ChatHistory()
		history.messages = messages
		return history
	except (json.JSONDecodeError, OSError) as e:
		console.print(Error(message=f'Failed to load history: {e}'))
		return None


def restore_history_from_db(session_id, query_engine, model=None, encryptor=None, system_prompt=None):
	"""Rebuild an in-memory ChatHistory from the workspace's `_type:"ai"` Mongo docs.

	Headless equivalent of ``replay_session`` for the remote path: a respawned
	``ai`` task has no local report files, so history is rebuilt from the
	channel docs (queried by ``session_id``, ordered by ``_timestamp``).

	Post-upgrade docs carry a raw litellm ``message`` and are appended verbatim
	(already encrypted at persist time -- do NOT re-encrypt, or it double-encrypts).
	Legacy docs (no ``message`` field) fall back to text-only prompt/response/steer
	reconstruction, re-encrypted here since their plaintext was never encrypted at
	persist time; other legacy ai_types are UX artifacts and are skipped. A session
	is never a mix of the two, so restoring each group in its own timestamp order
	never reorders an actual transcript.

	Returns:
		ChatHistory: rebuilt history (system-prompt-only if no prior docs exist).
	"""
	from secator.ai.history import ChatHistory
	from secator.ai.encryption import maybe_encrypt
	from secator.ai.utils import _repair_orphan_tool_uses, _strip_leading_orphan_tools

	history = ChatHistory(model=model)
	if system_prompt is not None:
		history.set_system(maybe_encrypt(system_prompt, encryptor))

	try:
		docs = query_engine.search({'_type': 'ai', '_context.session_id': session_id})
	except Exception as e:  # noqa: BLE001 - backend errors must not crash the worker
		console.print(Warning(message=f'Failed to restore session from DB: {e}'))
		return history

	docs = sorted(docs or [], key=lambda d: d.get('_timestamp', 0))
	legacy = []  # docs without a raw message (pre-upgrade) -> text-only fallback
	for doc in docs:
		msg = doc.get('message')
		if isinstance(msg, dict) and msg.get('role'):
			# Byte-exact: the persisted message already holds encrypted content, so
			# append verbatim (no re-encryption) — mirrors a fresh run's history.
			history.messages.append(dict(msg))
		else:
			legacy.append(doc)

	# Legacy docs (no message field): fall back to text-only prompt/response.
	for doc in legacy:
		ai_type = doc.get('ai_type')
		content = doc.get('content', '')
		if not content:
			continue
		if ai_type == 'prompt':
			history.add_user(maybe_encrypt(content, encryptor))
		elif ai_type == 'response':
			history.add_assistant(maybe_encrypt(content, encryptor))
		elif ai_type == 'steer':
			# A mid-flight steer is a real user turn: preserve it as a user message on
			# respawn (mirroring the live-loop framing) so the redirect survives a restore.
			history.add_user(maybe_encrypt(f'[User interjected]: {content}', encryptor))
		# All other ai_types (action displays, follow_up/permission prompts,
		# shell_output, summaries) are channel/UX artifacts, not conversation
		# turns — intentionally skipped for a valid litellm transcript.

	# Guard against a partially-persisted turn producing an orphan tool result.
	_repair_orphan_tool_uses(history.messages)
	_strip_leading_orphan_tools(history.messages)

	return history

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
	"""Save chat history to reports folder.

	Args:
		history: ChatHistory instance.
		reports_folder: Path to reports folder.
		debug_fn: Optional debug function for logging.
	"""
	try:
		history_path = Path(reports_folder) / 'history.json'
		with open(history_path, 'w') as f:
			json.dump(history.messages, f, indent=2)
		if debug_fn:
			debug_fn(f'Saved history to {history_path}')
	except Exception as e:
		if debug_fn:
			debug_fn(f'Failed to save history: {e}')


def list_sessions(max_sessions=20):
	"""Scan reports folders for AI sessions with history.json.

	Args:
		max_sessions: Maximum number of sessions to return.

	Returns:
		list: Session dicts sorted by mtime (most recent first), capped at max_sessions.
	"""
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
					session_name = (item.get('_context') or {}).get('name', '')
					break
			info = data.get('info', {})
			sessions.append({
				'folder': str(history_path.parent),
				'history_path': str(history_path),
				'report_path': str(report_path),
				'name': session_name,
				'prompt': first_prompt,
				'targets': info.get('targets', []),
				'timestamp': info.get('end_time') or info.get('start_time') or 0,
				'mtime': history_path.stat().st_mtime,
			})
		except (json.JSONDecodeError, OSError):
			continue

	sessions.sort(key=lambda s: s['mtime'], reverse=True)
	return sessions[:max_sessions]


def show_session_picker():
	"""Show interactive menu to pick a session to resume.

	Returns:
		dict: Selected session dict, or None if cancelled.
	"""
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
		if s.get('name'):
			label_text = f"[{s['name']}] {s['prompt']}"
		else:
			label_text = s['prompt']
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


def replay_session(session):
	"""Replay all results from a previous session and restore history.

	Args:
		session: Session dict from show_session_picker.

	Returns:
		ChatHistory: Restored history, or None on error.
	"""
	from secator.ai.history import ChatHistory
	from secator.output_types import OUTPUT_TYPES

	# Build type map for loading items
	type_map = {cls.__name__.lower(): cls for cls in OUTPUT_TYPES}

	# Load and replay all results from report.json, sorted by timestamp
	report_path = session.get('report_path')
	if report_path:
		try:
			with open(report_path) as f:
				data = json.load(f)
			results = data.get('results', {})
			# Flatten all items with their type class
			all_items = []
			for type_name, items in results.items():
				cls = type_map.get(type_name)
				if not cls:
					continue
				for item_data in items:
					all_items.append((item_data, cls))
			# Sort by _timestamp
			all_items.sort(key=lambda x: x[0].get('_timestamp', 0))
			for item_data, cls in all_items:
				try:
					item = cls.load(item_data)
					console.print(item)
				except Exception:
					continue
		except (json.JSONDecodeError, OSError):
			pass

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

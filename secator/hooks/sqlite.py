# secator/hooks/sqlite.py

import re
import sqlite3
import threading
from pathlib import Path

from celery import shared_task  # noqa: F401

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES  # noqa: F401
from secator.utils import debug
from secator.hooks._dedup import compute_duplicate_updates  # noqa: F401

_conns = {}
_conn_lock = threading.Lock()


def _get_db_path():
	path = CONFIG.addons.sqlite.path
	if path:
		return Path(path).expanduser()
	return Path(CONFIG.dirs.data) / 'secator.db'


def _regexp(pattern, value):
	"""Custom REGEXP function: X REGEXP Y -> regexp(Y, X), so pattern=Y, value=X."""
	if value is None or pattern is None:
		return False
	pattern = str(pattern).lstrip('*')
	try:
		return re.search(pattern, str(value)) is not None
	except re.error as exc:
		debug(f'REGEXP: invalid pattern {pattern!r}: {exc}', sub='hooks.sqlite')
		return False


SCHEMA = [
	"""CREATE TABLE IF NOT EXISTS findings (
		uuid TEXT PRIMARY KEY,
		type TEXT,
		workspace_id TEXT,
		is_false_positive INTEGER DEFAULT 0,
		_tagged INTEGER DEFAULT 0,
		data TEXT
	)""",
	"CREATE INDEX IF NOT EXISTS idx_findings_ws ON findings(workspace_id)",
	"CREATE INDEX IF NOT EXISTS idx_findings_ws_tag ON findings(workspace_id, _tagged)",
	"CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, workspace_id TEXT, data TEXT)",
	"CREATE TABLE IF NOT EXISTS workflows (id TEXT PRIMARY KEY, workspace_id TEXT, data TEXT)",
	"CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, workspace_id TEXT, data TEXT)",
]


def get_sqlite_conn(db_path=None):
	"""Get or create a cached SQLite connection (one per db path) with schema + REGEXP."""
	key = str(db_path) if db_path else str(_get_db_path())
	conn = _conns.get(key)
	if conn is None:
		with _conn_lock:
			conn = _conns.get(key)
			if conn is None:
				db_file = Path(key)
				db_file.parent.mkdir(parents=True, exist_ok=True)
				timeout = CONFIG.addons.sqlite.busy_timeout_ms / 1000
				conn = sqlite3.connect(key, check_same_thread=False, timeout=timeout)
				try:
					conn.execute('PRAGMA journal_mode=WAL')
					conn.execute(f'PRAGMA busy_timeout={CONFIG.addons.sqlite.busy_timeout_ms}')
					conn.execute('PRAGMA synchronous=NORMAL')
					conn.create_function('REGEXP', 2, _regexp)
					for stmt in SCHEMA:
						conn.execute(stmt)
					conn.commit()
					_conns[key] = conn
				except Exception:
					conn.close()
					raise
	return conn

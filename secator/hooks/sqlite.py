# secator/hooks/sqlite.py

import json
import re
import sqlite3
import threading
import uuid
from pathlib import Path

from celery import shared_task

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug
from secator.hooks._dedup import compute_duplicate_updates

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


def _apply_finding_update(conn, uuid_, update):
	"""Apply a single dedup update dict to a findings row via json_set.

	The JSON document patches are chained into a single nested ``json_set(...)``
	expression because SQLite evaluates every assignment in an ``UPDATE`` against
	the original row value, so repeated ``data = json_set(data, ...)`` clauses
	would clobber one another.
	"""
	data_expr = "data"
	data_params = []
	extra_exprs = []
	extra_params = []
	for key, val in update.items():
		data_expr = f"json_set({data_expr}, '$.{key}', json(?))"
		data_params.append(json.dumps(val, default=str))
		if key == '_tagged':
			extra_exprs.append("_tagged = ?")
			extra_params.append(int(bool(val)))
		elif key == 'is_false_positive':
			extra_exprs.append("is_false_positive = ?")
			extra_params.append(int(bool(val)))
	set_exprs = [f"data = {data_expr}"] + extra_exprs
	params = data_params + extra_params + [uuid_]
	conn.execute(f"UPDATE findings SET {', '.join(set_exprs)} WHERE uuid=?", params)


def load_finding(obj, exclude_types=[]):
	finding_type = obj.get('_type')
	if finding_type in exclude_types:
		return None
	for otype in OUTPUT_TYPES:
		if finding_type == otype.get_name():
			item = otype.load(obj)
			item._uuid = obj.get('_uuid', '')
			return item
	return None


def load_findings(objs, exclude_types=[]):
	findings = [load_finding(obj, exclude_types) for obj in objs]
	return [f for f in findings if f is not None]


def update_runner(self):
	conn = get_sqlite_conn()
	_type = self.config.type
	table = f'{_type}s'
	update = self.toDict()
	chunk = update.get('chunk')
	key = f'{_type}_chunk_id' if chunk else f'{_type}_id'
	_id = self.context.get(key)
	workspace_id = self.context.get('workspace_id')
	payload = json.dumps(update, default=str)
	if _id:
		conn.execute(f"UPDATE {table} SET workspace_id=?, data=? WHERE id=?", (workspace_id, payload, _id))
	else:
		_id = str(uuid.uuid4())
		conn.execute(f"INSERT INTO {table} (id, workspace_id, data) VALUES (?, ?, ?)", (_id, workspace_id, payload))
		self.context[key] = _id
	conn.commit()


def update_finding(self, item):
	if type(item) not in OUTPUT_TYPES:
		return item
	conn = get_sqlite_conn()
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	data = item.toDict()
	data['_uuid'] = item._uuid
	ctx = data.get('_context') or {}
	workspace_id = ctx.get('workspace_id')
	payload = json.dumps(data, default=str)
	conn.execute(
		"INSERT INTO findings (uuid, type, workspace_id, is_false_positive, _tagged, data) "
		"VALUES (?, ?, ?, ?, ?, ?) "
		"ON CONFLICT(uuid) DO UPDATE SET "
		"type=excluded.type, workspace_id=excluded.workspace_id, "
		"is_false_positive=excluded.is_false_positive, _tagged=excluded._tagged, data=excluded.data",
		(item._uuid, item._type, workspace_id,
			int(bool(data.get('is_false_positive'))), int(bool(data.get('_tagged'))), payload),
	)
	conn.commit()
	return item


def find_duplicates(self):
	from secator.definitions import IN_WORKER
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	if not IN_WORKER:
		tag_duplicates(ws_id)
	else:
		tag_duplicates.delay(ws_id)


@shared_task
def tag_duplicates(ws_id: str = None, full_scan: bool = False, exclude_types=[], max_items=None, log_hook=None):
	"""Tag duplicate findings in a workspace (SQLite)."""
	if max_items is None:
		max_items = CONFIG.addons.sqlite.max_items
	conn = get_sqlite_conn()
	ws_rows = conn.execute(
		"SELECT data FROM findings WHERE workspace_id=? AND _tagged=1 "
		"AND json_extract(data,'$._context.workspace_duplicate')=0",
		(str(ws_id),),
	).fetchall()
	workspace_findings = load_findings([json.loads(r[0]) for r in ws_rows], exclude_types)

	if full_scan:
		unt_rows = conn.execute("SELECT data FROM findings WHERE workspace_id=?", (str(ws_id),)).fetchall()
	else:
		unt_rows = conn.execute(
			"SELECT data FROM findings WHERE workspace_id=? AND (_tagged IS NULL OR _tagged=0)",
			(str(ws_id),),
		).fetchall()
	if max_items != -1:
		unt_rows = unt_rows[:max_items]
	untagged_findings = load_findings([json.loads(r[0]) for r in unt_rows], exclude_types)

	debug(
		f'Workspace non-duplicates: {len(workspace_findings)} Untagged: {len(untagged_findings)}',
		sub='hooks.sqlite', log_hook=log_hook,
	)

	db_updates = compute_duplicate_updates(
		workspace_findings, untagged_findings, CONFIG.addons.sqlite.duplicate_main_copy_fields,
	)
	if not db_updates:
		debug('no db updates to execute', sub='hooks.sqlite', log_hook=log_hook)
		return
	for uuid_, update in db_updates.items():
		_apply_finding_update(conn, uuid_, update)
	conn.commit()
	debug(f'Executed {len(db_updates)} database updates', sub='hooks.sqlite', log_hook=log_hook)


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner],
	},
}

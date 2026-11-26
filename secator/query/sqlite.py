# secator/query/sqlite.py

import json
import re
from typing import List, Dict, Any, Optional

from secator.output_types import Warning
from secator.query._base import QueryBackend, sort_runners_chronologically, validate_runner_order
from secator.rich import console

# Query fields that map to real indexed columns instead of json_extract.
MIRRORED_COLUMNS = {
	'_context.workspace_id': 'workspace_id',
	'is_false_positive': 'is_false_positive',
	'_tagged': '_tagged',
	'_type': 'type',
	'_uuid': 'uuid',  # the TEXT PRIMARY KEY (populated by the hook) — seek it, don't json_extract-scan
}

COMPARISON_OPS = {
	'$ne': '!=',
	'$gt': '>',
	'$gte': '>=',
	'$lt': '<',
	'$lte': '<=',
}


# Runner tables written by the sqlite driver (see hooks/sqlite.py).
RUNNER_TABLES = ('tasks', 'workflows', 'scans')

_FIELD_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.]*$')


def _col_expr(field: str) -> str:
	"""Return the SQL expression for a query field (mirrored column or json_extract path).

	Field names are interpolated into the SQL text (json1 paths cannot be parameterized),
	so they are validated against a strict allowlist to prevent SQL injection.
	"""
	if field in MIRRORED_COLUMNS:
		return MIRRORED_COLUMNS[field]
	if not _FIELD_RE.match(field):
		raise ValueError(f'Invalid query field name: {field!r}')
	return f"json_extract(data, '$.{field}')"


def _build_where(query: dict):
	"""Translate a MongoDB-style query dict into a parameterized SQL WHERE fragment.

	Returns (sql_fragment, params). An empty query yields ('', []).
	"""
	clauses = []
	params = []
	for key, condition in query.items():
		if key == '$and':
			sub = [_build_where(q) for q in condition]
			if not sub:
				clauses.append('1=1')
				continue
			joined = ' AND '.join(s if s else '1=1' for s, _ in sub)
			clauses.append(f'({joined})')
			for _, p in sub:
				params.extend(p)
			continue
		if key == '$or':
			sub = [_build_where(q) for q in condition]
			if not sub:
				clauses.append('0')
				continue
			joined = ' OR '.join(s if s else '0' for s, _ in sub)
			clauses.append(f'({joined})')
			for _, p in sub:
				params.extend(p)
			continue
		expr = _col_expr(key)
		if isinstance(condition, dict):
			for op, val in condition.items():
				if op in COMPARISON_OPS:
					clauses.append(f'{expr} {COMPARISON_OPS[op]} ?')
					params.append(val)
				elif op == '$in':
					if not val:
						clauses.append('0')
						continue
					placeholders = ', '.join('?' for _ in val)
					clauses.append(f'{expr} IN ({placeholders})')
					params.extend(val)
				elif op == '$nin':
					# NOT IN [] matches everything -> emit no constraint.
					if not val:
						continue
					# SQL three-valued logic: `x NOT IN (..., NULL, ...)` is NULL (never TRUE)
					# for any x, so a None in the list would drop every row. Pull NULLs out
					# into an explicit `IS NOT NULL` guard and NOT IN only the non-null values
					# (this is what makes bare truthiness checks like `ip.alive` work on sqlite).
					non_null = [v for v in val if v is not None]
					sub = []
					if len(non_null) != len(val):
						sub.append(f'{expr} IS NOT NULL')
					if non_null:
						placeholders = ', '.join('?' for _ in non_null)
						sub.append(f'{expr} NOT IN ({placeholders})')
						params.extend(non_null)
					if sub:
						clauses.append('(' + ' AND '.join(sub) + ')')
				elif op == '$contains':
					# Literal, case-insensitive substring (same as the normalized $regex form);
					# LIKE would treat % and _ in the value as wildcards.
					clauses.append(f'{expr} REGEXP ?')
					params.append('(?i)' + re.escape(str(val)))
				elif op == '$regex':
					clauses.append(f'{expr} REGEXP ?')
					params.append(str(val))
				elif op == '$not' and isinstance(val, dict) and '$regex' in val:
					# Negated regex from '!~='.
					clauses.append(f'{expr} NOT REGEXP ?')
					params.append(str(val['$regex']))
				# unknown operators are ignored, matching the json backend
		else:
			clauses.append(f'{expr} = ?')
			params.append(condition)
	return ' AND '.join(clauses), params


class SqliteBackend(QueryBackend):
	"""Query backend for SQLite (JSON-blob rows + SQL translation)."""

	name = 'sqlite'

	def _datetime_operand(self, dt, raw):
		# The sqlite driver stores datetimes as json.dumps(default=str) -> 'YYYY-MM-DD HH:MM:SS+00:00';
		# compare against the same UTC text form so string ordering is chronological.
		return str(dt)

	def _get_conn(self):
		from secator.hooks.sqlite import get_sqlite_conn
		return get_sqlite_conn(self.config.get('db_path'))

	def _execute_search(self, query: dict, limit: int = 0, exclude_fields: list = None,
	                    offset: int = 0) -> List[Dict[str, Any]]:
		try:
			conn = self._get_conn()
			where, params = _build_where(query)
			sql = f"SELECT data FROM findings WHERE {where or '1=1'}"
			if limit:  # limit=0 means unlimited (matches ABC contract and JsonBackend)
				sql += " LIMIT ?"
				params.append(limit)
				if offset:
					# SQLite requires a LIMIT before OFFSET; only valid on the limited path.
					sql += " OFFSET ?"
					params.append(offset)
			elif offset:
				# limit=0 (unlimited): emulate OFFSET with LIMIT -1 OFFSET ? (SQLite idiom).
				sql += " LIMIT -1 OFFSET ?"
				params.append(offset)
			results = []
			for (data,) in conn.execute(sql, params).fetchall():
				finding = json.loads(data)
				if exclude_fields:
					finding = {k: v for k, v in finding.items() if k not in exclude_fields}
				results.append(finding)
			return results
		except Exception as e:
			console.print(Warning(message=f'SQLite search failed: {e}'))
			return []

	def _execute_iterate(self, query: dict, batch_size: int = 1000):
		"""Stream rows with a cursor + fetchmany — never loads all N into memory."""
		try:
			conn = self._get_conn()
			where, params = _build_where(query)
			cur = conn.execute(f"SELECT data FROM findings WHERE {where or '1=1'}", params)
			while True:
				rows = cur.fetchmany(batch_size)
				if not rows:
					break
				yield [json.loads(d) for (d,) in rows]
		except Exception as e:
			console.print(Warning(message=f'SQLite iterate failed: {e}'))
			raise

	def _execute_count(self, query: dict) -> int:
		try:
			conn = self._get_conn()
			where, params = _build_where(query)
			sql = f"SELECT COUNT(*) FROM findings WHERE {where or '1=1'}"
			return conn.execute(sql, params).fetchone()[0]
		except Exception as e:
			console.print(Warning(message=f'SQLite count failed: {e}'))
			return 0

	def vuln_counts_by_runner(self, runner_ids_by_type: dict) -> dict:
		"""Group vulnerability severities by runner id in SQLite."""
		query = self._vulnerability_query(runner_ids_by_type)
		if not query:
			return {}
		try:
			conn = self._get_conn()
			counts = {}
			for runner_type, runner_ids in (runner_ids_by_type or {}).items():
				if runner_type not in ('task', 'workflow', 'scan') or not runner_ids:
					continue
				field = _col_expr(f'_context.{runner_type}_id')
				severity = f"LOWER(COALESCE({_col_expr('severity')}, ''))"
				# Filter per type so the group key is unambiguous, and keep the aggregation
				# in SQLite instead of reading every matching finding into Python. Chunk ids
				# to stay below SQLite builds with a 999-variable limit.
				ids = list(runner_ids)
				for offset in range(0, len(ids), 500):
					type_query = self._merge_query({
						'_type': 'vulnerability',
						f'_context.{runner_type}_id': {'$in': ids[offset:offset + 500]},
					})
					type_where, type_params = _build_where(type_query)
					sql = (
						f"SELECT {field}, {severity}, COUNT(*) FROM findings "
						f"WHERE {type_where or '1=1'} GROUP BY 1, 2"
					)
					for runner_id, severity_name, total in conn.execute(sql, type_params).fetchall():
						if runner_id is None:
							continue
						severity_name = str(severity_name or '').lower()
						if severity_name not in ('critical', 'high', 'medium', 'low'):
							continue
						by_id = counts.setdefault(runner_type, {})
						severity_counts = by_id.setdefault(str(runner_id), {})
						severity_counts[severity_name] = severity_counts.get(severity_name, 0) + total
			return counts
		except Exception as e:
			console.print(Warning(message=f'SQLite vulnerability count aggregation failed: {e}'))
			return {}

	def _execute_update(self, query: dict, update: dict) -> int:
		set_fields = update.get('$set', {})
		if not set_fields:
			return 0
		conn = self._get_conn()
		where, where_params = _build_where(query)
		data_expr = "data"
		data_params = []
		extra_exprs = []
		extra_params = []
		for field, val in set_fields.items():
			_col_expr(field)  # validate field name (raises ValueError on SQL metacharacters)
			data_expr = f"json_set({data_expr}, '$.{field}', json(?))"
			data_params.append(json.dumps(val, default=str))
			if field == '_tagged':
				extra_exprs.append("_tagged = ?")
				extra_params.append(int(bool(val)))
			elif field == 'is_false_positive':
				extra_exprs.append("is_false_positive = ?")
				extra_params.append(int(bool(val)))
		set_clause = ', '.join([f"data = {data_expr}"] + extra_exprs)
		sql = f"UPDATE findings SET {set_clause} WHERE {where or '1=1'}"
		cur = conn.execute(sql, data_params + extra_params + where_params)
		# Connection is shared; commit flushes pending writes (best-effort single-host semantics, per design).
		conn.commit()
		return cur.rowcount

	def list_runners(self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
					 has_parent: Optional[bool] = None, order: str = 'asc') -> List[Dict[str, Any]]:
		"""List runners from the sqlite tasks/workflows/scans tables.

		workspace_id: a workspace id or name. Rows mirror ``context.workspace_id`` (which
		defaults to the workspace name when no id is set) into the ``workspace_id`` column,
		and carry ``context.workspace_name`` in the JSON blob, so either value matches.
		has_parent: None lists all runners, False only outermost (root) runners,
		True only nested children.
		order: 'asc' (default) = oldest first, most recent last; 'desc' = most recent first.
		"""
		validate_runner_order(order)
		if runner_type:
			table = runner_type.rstrip('s') + 's'
			tables = [table] if table in RUNNER_TABLES else []
		else:
			tables = list(RUNNER_TABLES)
		runners = []
		try:
			conn = self._get_conn()
			for table in tables:
				clauses, params = [], []
				if workspace_id:
					clauses.append("(workspace_id = ? OR json_extract(data, '$.context.workspace_name') = ?)")
					params.extend([workspace_id, workspace_id])
				if has_parent is not None:
					# json booleans extract as 1/0; a missing key means a root runner.
					clauses.append("COALESCE(json_extract(data, '$.has_parent'), 0) = ?")
					params.append(int(has_parent))
				where = ' AND '.join(clauses) or '1=1'
				# `table` comes from the fixed RUNNER_TABLES allowlist, never from user input.
				sql = f"SELECT id, workspace_id, data FROM {table} WHERE {where}"  # nosec B608
				for rid, ws_id, data in conn.execute(sql, params).fetchall():
					doc = json.loads(data)
					doc['_type'] = table
					doc['_id_str'] = f'{table}/{rid}'
					doc['_workspace'] = (doc.get('context') or {}).get('workspace_name') or ws_id or ''
					runners.append(doc)
			# In the requested order (default oldest first), across the tasks/workflows/scans tables.
			return sort_runners_chronologically(runners, order=order)
		except Exception as e:
			console.print(Warning(message=f'SQLite list_runners failed: {e}'))
			return []

	def _execute_create_note(self, note: dict) -> int:
		"""Insert a note into a dedicated ``notes`` table (created on first use).

		Notes are a JSON blob keyed by their own uuid, with ``workspace_id``/``target_type``
		mirrored to columns for cheap lookup — the same JSON-blob-plus-indexed-columns shape
		as the ``findings`` table, but a SEPARATE table so a note is never confused with a finding.
		"""
		try:
			import uuid as _uuidlib
			conn = self._get_conn()
			conn.execute(
				"CREATE TABLE IF NOT EXISTS notes ("
				"uuid TEXT PRIMARY KEY, workspace_id TEXT, target_type TEXT, data TEXT)"
			)
			nid = note.get('_uuid') or str(_uuidlib.uuid4())
			conn.execute(
				"INSERT INTO notes (uuid, workspace_id, target_type, data) VALUES (?, ?, ?, ?)",
				(
					nid,
					note.get('_context', {}).get('workspace_id', ''),
					note.get('target_type', ''),
					json.dumps(note, default=str),
				),
			)
			conn.commit()
			return 1
		except Exception as e:
			console.print(Warning(message=f'SQLite create_note failed: {e}'))
			return 0

	def get_runner(self, runner_id: str, runner_type: str):
		"""Get a single runner by id from its runner table (live: written by update_runner).

		The row key is the runner's ``{type}_chunk_id`` or ``{type}_id``; a runner is also found
		by either id in its persisted context, so callers need not know which one keyed it."""
		rtype = (runner_type or '').rstrip('s')
		if rtype not in ('task', 'workflow', 'scan'):
			return None
		table = f'{rtype}s'
		try:
			conn = self._get_conn()
			row = conn.execute(
				f"SELECT data FROM {table} WHERE id = ? "
				f"OR json_extract(data, '$.context.{rtype}_chunk_id') = ? "
				f"OR json_extract(data, '$.context.{rtype}_id') = ? LIMIT 1",
				(runner_id, runner_id, runner_id)).fetchone()
			if not row:
				return None
			doc = json.loads(row[0])
			doc['_id'] = runner_id
			doc['_type'] = table
			return doc
		except Exception as e:
			console.print(Warning(message=f'SQLite get_runner failed: {e}'))
			return None

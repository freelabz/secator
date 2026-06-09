# secator/query/sqlite.py

import json
import re
from typing import List, Dict, Any

from secator.output_types import Warning
from secator.query._base import QueryBackend
from secator.rich import console

# Query fields that map to real indexed columns instead of json_extract.
MIRRORED_COLUMNS = {
	'_context.workspace_id': 'workspace_id',
	'is_false_positive': 'is_false_positive',
	'_tagged': '_tagged',
	'_type': 'type',
}

COMPARISON_OPS = {
	'$ne': '!=',
	'$gt': '>',
	'$gte': '>=',
	'$lt': '<',
	'$lte': '<=',
}


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
				elif op == '$contains':
					clauses.append(f"{expr} LIKE '%' || ? || '%'")
					params.append(val)
				elif op == '$regex':
					clauses.append(f'{expr} REGEXP ?')
					params.append(str(val))
				# unknown operators are ignored, matching the json backend
		else:
			clauses.append(f'{expr} = ?')
			params.append(condition)
	return ' AND '.join(clauses), params


class SqliteBackend(QueryBackend):
	"""Query backend for SQLite (JSON-blob rows + SQL translation)."""

	name = 'sqlite'

	def _get_conn(self):
		from secator.hooks.sqlite import get_sqlite_conn
		return get_sqlite_conn(self.config.get('db_path'))

	def _execute_search(self, query: dict, limit: int = 0, exclude_fields: list = None) -> List[Dict[str, Any]]:
		try:
			conn = self._get_conn()
			where, params = _build_where(query)
			sql = f"SELECT data FROM findings WHERE {where or '1=1'}"
			if limit:  # limit=0 means unlimited (matches ABC contract and JsonBackend)
				sql += " LIMIT ?"
				params.append(limit)
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

	def _execute_count(self, query: dict) -> int:
		try:
			conn = self._get_conn()
			where, params = _build_where(query)
			sql = f"SELECT COUNT(*) FROM findings WHERE {where or '1=1'}"
			return conn.execute(sql, params).fetchone()[0]
		except Exception as e:
			console.print(Warning(message=f'SQLite count failed: {e}'))
			return 0

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

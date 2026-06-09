# secator/query/sqlite.py

import json  # noqa: F401
import re
from typing import List, Dict, Any, Optional  # noqa: F401

from secator.output_types import Warning  # noqa: F401
from secator.query._base import QueryBackend  # noqa: F401
from secator.rich import console  # noqa: F401

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

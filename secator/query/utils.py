"""Utilities for converting CLI query syntax to MongoDB-style queries."""

import json
import re

# Maps path prefix -> _context field singular name
_RUNNER_TYPE_MAP = {
    'scans': 'scan',
    'scan': 'scan',
    'tasks': 'task',
    'task': 'task',
    'workflows': 'workflow',
    'workflow': 'workflow',
}


def parse_report_paths(paths_str):
    """Convert comma-separated path strings to a MongoDB-style runner filter.

    Examples:
        ''                → {}
        'scans/5'         → {'_context.scan_id': '5'}
        'scans/5,tasks/3' → {'$or': [{'_context.scan_id': '5'}, {'_context.task_id': '3'}]}
    """
    if not paths_str:
        return {}

    parts = [p.strip() for p in paths_str.split(',') if p.strip()]
    if not parts:
        return {}

    filters = []
    for part in parts:
        if '/' not in part:
            continue
        runner_type, runner_id = part.split('/', 1)
        runner_type = runner_type.strip().lower()
        runner_id = runner_id.strip().rstrip('/')
        singular = _RUNNER_TYPE_MAP.get(runner_type)
        if singular:
            filters.append({f'_context.{singular}_id': runner_id})

    if not filters:
        return {}
    if len(filters) == 1:
        return filters[0]
    return {'$or': filters}


_COMPARISON_OPS = [
    ('>=', '$gte'),
    ('<=', '$lte'),
    ('>', '$gt'),
    ('<', '$lt'),
    ('!=', '$ne'),
    ('==', None),   # equality: no operator wrapper
]


def _parse_value(raw):
    """Convert a string token to int, float, or stripped string."""
    raw = raw.strip().strip("'\"")
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _parse_single_expr(expr):
    """Parse one expression like 'vulnerability.severity_score > 7' into a query dict."""
    expr = expr.strip()

    if isinstance(expr, dict):
        return expr

    if expr.startswith('{'):
        try:
            return json.loads(expr)
        except json.JSONDecodeError:
            pass

    # Type-only: "domain" or "vulnerability"
    if re.match(r'^[a-z_]+$', expr):
        return {'_type': expr}

    # Dotted: "type.field op value" — try operators longest-first to avoid ambiguity
    for op_str, mongo_op in _COMPARISON_OPS:
        if op_str in expr:
            left, _, right = expr.partition(op_str)
            left = left.strip()
            right = right.strip()
            parts = left.split('.', 1)
            _type = parts[0].strip()
            field = parts[1].strip() if len(parts) > 1 else None
            value = _parse_value(right)
            result = {'_type': _type}
            if field:
                result[field] = value if mongo_op is None else {mongo_op: value}
            return result

    # Fallback: treat as type name
    parts = expr.split('.', 1)
    return {'_type': parts[0].strip()}


def python_expr_to_mongo(query):
    """Translate a Python-like CLI query expression to a MongoDB-style query dict.

    Accepts:
        - None / '' → {}
        - dict → returned as-is
        - JSON string (starts with '{') → parsed as dict
        - 'type' → {'_type': 'type'}
        - 'type.field > value' → {'_type': 'type', 'field': {'$gt': value}}
        - 'expr1 && expr2' → merged dict (AND)
        - 'expr1 || expr2' → {'$or': [...]}
    """
    if not query:
        return {}

    if isinstance(query, dict):
        return query

    if isinstance(query, str) and query.strip().startswith('{'):
        try:
            return json.loads(query)
        except json.JSONDecodeError:
            pass

    if '&&' in query and '||' in query:
        raise ValueError("Cannot mix && and || in the same query expression")

    if '||' in query:
        parts = [p.strip() for p in query.split('||')]
        return {'$or': [_parse_single_expr(p) for p in parts]}

    if '&&' in query:
        parts = [p.strip() for p in query.split('&&')]
        merged = {}
        for part in parts:
            merged.update(_parse_single_expr(part))
        return merged

    return _parse_single_expr(query)

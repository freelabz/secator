"""Utilities for converting CLI query syntax to MongoDB-style queries."""

import json
import re

from secator.utils import debug


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
        singular = runner_type.rstrip('s')
        filters.append({f'_context.{singular}_id': runner_id})

    if not filters:
        return {}
    if len(filters) == 1:
        result = filters[0]
    else:
        result = {'$or': filters}
    debug('parse_report_paths', sub='query', obj={'input': paths_str, 'output': result})
    return result


def _split_logical_op(query, op):
    """Split query string on logical operator, skipping quoted substrings."""
    parts = []
    current = []
    i = 0
    in_quote = None
    op_len = len(op)
    while i < len(query):
        ch = query[i]
        if in_quote is None and ch in ('"', "'"):
            in_quote = ch
            current.append(ch)
            i += 1
        elif ch == in_quote:
            in_quote = None
            current.append(ch)
            i += 1
        elif in_quote is None and query[i:i + op_len] == op:
            parts.append(''.join(current).strip())
            current = []
            i += op_len
        else:
            current.append(ch)
            i += 1
    parts.append(''.join(current).strip())
    return [p for p in parts if p]


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


# Regex that finds the first comparison operator outside of quotes.
# Alternatives are ordered longest-first so >= matches before >.
_OP_RE = re.compile(r'^(.*?)\s*(>=|<=|!=|>|<|==)\s*(.+)$', re.DOTALL)

_OP_MAP = {
    '>=': '$gte',
    '<=': '$lte',
    '>': '$gt',
    '<': '$lt',
    '!=': '$ne',
    '==': None,
}


def _normalize_field_path(field):
    """Convert Python-style method calls to dot notation for MongoDB.

    E.g. 'extra_data.get(\'product\')' → 'extra_data.product'
    E.g. 'extra_data.get(\'http-title\')' → 'extra_data.http-title'
    """
    return re.sub(r"\.get\(\s*(['\"])([^'\"]+)\1\s*\)", r'.\2', field)


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

    # Use regex to find the first operator (longest-first via alternation order).
    # This avoids mis-splitting on operators that appear inside quoted values.
    m = _OP_RE.match(expr)
    if m:
        left, op_str, right = m.group(1).strip(), m.group(2), m.group(3).strip()
        mongo_op = _OP_MAP.get(op_str)
        parts = left.split('.', 1)
        _type = parts[0].strip()
        field = _normalize_field_path(parts[1].strip()) if len(parts) > 1 else None
        value = _parse_value(right)
        result = {'_type': _type}
        if field:
            result[field] = value if mongo_op is None else {mongo_op: value}
        return result

    # Fallback: treat as type name
    parts = expr.split('.', 1)
    return {'_type': parts[0].strip()}


def _normalize_logical_ops(query):
    """Replace Python-style 'and'/'or' with '&&'/'||', skipping quoted substrings."""
    result = []
    i = 0
    in_quote = None
    while i < len(query):
        ch = query[i]
        if in_quote is None and ch in ('"', "'"):
            in_quote = ch
            result.append(ch)
            i += 1
        elif ch == in_quote:
            in_quote = None
            result.append(ch)
            i += 1
        elif in_quote is None:
            if query[i:i + 5] == ' and ':
                result.append(' && ')
                i += 5
            elif query[i:i + 4] == ' or ':
                result.append(' || ')
                i += 4
            else:
                result.append(ch)
                i += 1
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def python_expr_to_mongo(query):
    """Translate a Python-like CLI query expression to a MongoDB-style query dict.

    Accepts:
        - None / '' → {}
        - dict → returned as-is
        - JSON string (starts with '{') → parsed as dict
        - 'type' → {'_type': 'type'}
        - 'type.field > value' → {'_type': 'type', 'field': {'$gt': value}}
        - 'expr1 && expr2' or 'expr1 and expr2' → merged dict (AND)
        - 'expr1 || expr2' or 'expr1 or expr2' → {'$or': [...]}
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

    query = _normalize_logical_ops(query)

    or_parts = _split_logical_op(query, '||')
    and_parts = _split_logical_op(query, '&&')

    if len(or_parts) > 1 and len(and_parts) > 1:
        raise ValueError("Cannot mix && and || in the same query expression")

    if len(or_parts) > 1:
        result = {'$or': [_parse_single_expr(p) for p in or_parts]}
    elif len(and_parts) > 1:
        result = {}
        for part in and_parts:
            result.update(_parse_single_expr(part))
    else:
        result = _parse_single_expr(query)

    debug('python_expr_to_mongo', sub='query', obj={'input': query, 'output': result})
    return result

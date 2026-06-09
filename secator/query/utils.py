"""Utilities for converting CLI query syntax to MongoDB-style queries."""

import json
import re

from secator.output_types import Error
from secator.rich import console
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


RUNNER_TYPES = {'task', 'tasks', 'workflow', 'workflows', 'scan', 'scans'}


def expand_runner_paths(tokens):
    """Expand runner path tokens into individual runner references.

    Each token may be space-separated (passed as separate list items),
    comma-separated, and may contain inclusive numeric ranges. Examples:
        ['tasks/23', 'workflows/21']  → [('tasks', 'task', '23'), ('workflows', 'workflow', '21')]
        ['tasks/23,tasks/24']         → [('tasks', 'task', '23'), ('tasks', 'task', '24')]
        ['tasks/136-140']             → tasks 136, 137, 138, 139, 140

    Args:
        tokens (str | iterable[str]): One or more path tokens.

    Returns:
        tuple[list, list]: (refs, errors) where refs is an order-preserving,
        de-duplicated list of (type_plural, type_singular, number) tuples and
        errors is a list of human-readable error strings for invalid tokens.
    """
    if isinstance(tokens, str):
        tokens = [tokens]

    refs = []
    errors = []
    seen = set()

    parts = []
    for token in tokens:
        parts.extend(p.strip() for p in token.split(',') if p.strip())

    for part in parts:
        if '/' not in part:
            errors.append(f'Invalid runner path: {part!r}. Expected format: <type>/<id> (e.g. tasks/24)')
            continue
        runner_type_raw, spec = part.split('/', 1)
        runner_type_raw = runner_type_raw.strip().lower()
        spec = spec.strip().rstrip('/')

        if runner_type_raw not in RUNNER_TYPES:
            errors.append(f'Invalid runner type: {runner_type_raw!r}. Must be one of: task, workflow, scan.')
            continue

        type_plural = runner_type_raw if runner_type_raw.endswith('s') else runner_type_raw + 's'
        type_singular = type_plural[:-1]

        # Range (e.g. "136-140") or single number
        if '-' in spec:
            start_str, _, end_str = spec.partition('-')
            start_str, end_str = start_str.strip(), end_str.strip()
            if not (start_str.isdigit() and end_str.isdigit()):
                errors.append(f'Invalid range: {spec!r} in {part!r}. Both bounds must be numeric (e.g. 136-140).')
                continue
            start, end = int(start_str), int(end_str)
            if start > end:
                errors.append(f'Invalid range: {spec!r} in {part!r}. Start must be <= end.')
                continue
            numbers = [str(n) for n in range(start, end + 1)]
        else:
            if not spec.isdigit():
                errors.append(f'Invalid runner number: {spec!r} in {part!r}. Must be numeric.')
                continue
            numbers = [str(int(spec))]

        for number in numbers:
            key = (type_plural, number)
            if key in seen:
                continue
            seen.add(key)
            refs.append((type_plural, type_singular, number))

    debug('expand_runner_paths', sub='query', obj={'input': list(tokens), 'refs': refs, 'errors': errors})
    return refs, errors


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
# Alternatives are ordered longest-first so >= matches before > and ~= is included.
_OP_RE = re.compile(r'^(.*?)\s*(>=|<=|!=|~=|>|<|==)\s*(.+)$', re.DOTALL)

_OP_MAP = {
    '>=': '$gte',
    '<=': '$lte',
    '>': '$gt',
    '<': '$lt',
    '!=': '$ne',
    '==': None,
    '~=': '$regex',
}

# Regex for the 'in' operator: "type.field in [val1, val2]"
_IN_RE = re.compile(r'^(.+?)\s+in\s+\[(.*)\]\s*$', re.DOTALL)


def _has_in_op_outside_quotes(expr):
    """Return True if ' in [' appears outside of any quoted substring in expr."""
    in_quote = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_quote is None and ch in ('"', "'"):
            in_quote = ch
            i += 1
        elif ch == in_quote:
            in_quote = None
            i += 1
        elif in_quote is None and expr[i:i + 4] == ' in ':
            j = i + 4
            while j < len(expr) and expr[j] == ' ':
                j += 1
            if j < len(expr) and expr[j] == '[':
                return True
            i += 1
        else:
            i += 1
    return False


def _parse_list(values_str):
    """Parse a comma-separated list of values, respecting quoted strings."""
    values = []
    current = []
    in_quote = None
    for ch in values_str:
        if in_quote is None and ch in ('"', "'"):
            in_quote = ch
            current.append(ch)
        elif ch == in_quote:
            in_quote = None
            current.append(ch)
        elif in_quote is None and ch == ',':
            val = ''.join(current).strip()
            if val:
                values.append(_parse_value(val))
            current = []
        else:
            current.append(ch)
    val = ''.join(current).strip()
    if val:
        values.append(_parse_value(val))
    return values


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

    # Check for 'in' operator: "type.field in [val1, val2]"
    m_in = _IN_RE.match(expr) if _has_in_op_outside_quotes(expr) else None
    if m_in:
        left, values_str = m_in.group(1).strip(), m_in.group(2)
        parts = left.split('.', 1)
        _type = parts[0].strip()
        field = parts[1].strip() if len(parts) > 1 else None
        values = _parse_list(values_str)
        if field is None:
            console.print(Error(
                message=f"'in' operator requires a field (e.g. 'type.field in [...]'): {expr!r}"
            ))
            return {'_type': _type}
        result = {'_type': _type}
        result[field] = {'$in': values}
        return result

    # Use regex to find the first operator (longest-first via alternation order).
    # This avoids mis-splitting on operators that appear inside quoted values.
    m = _OP_RE.match(expr)
    if m:
        left, op_str, right = m.group(1).strip(), m.group(2), m.group(3).strip()
        mongo_op = _OP_MAP.get(op_str)
        parts = left.split('.', 1)
        _type = parts[0].strip()
        field = parts[1].strip() if len(parts) > 1 else None
        # Regex patterns must stay as strings — converting to int/float breaks re.search.
        if mongo_op == '$regex':
            value = right.strip().strip("'\"")
        else:
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


def _warn_unknown_field(field_name, type_name, valid_fields):
    """Emit a warning for an unknown field in a query fragment."""
    from secator.output_types import Warning
    public_fields = sorted(f for f in valid_fields if not f.startswith('_'))
    console.print(Warning(
        message=f"Field '{field_name}' does not exist on type '{type_name}'. "
                f"Available fields: {', '.join(public_fields)}"
    ))


def _build_type_map():
    from secator.output_types import OUTPUT_TYPES
    return {
        cls.__dataclass_fields__['_type'].default: cls
        for cls in OUTPUT_TYPES
        if '_type' in getattr(cls, '__dataclass_fields__', {})
        and isinstance(cls.__dataclass_fields__['_type'].default, str)
    }


def _validate_fragment(fragment, type_map):
    """Validate a single query fragment against known output type fields.

    Returns None if all user-specified fields were invalid (signals the caller
    to drop this fragment from an $or/$and list rather than keeping a bare
    {'_type': 'x'} that would match every object of that type).
    """
    if not isinstance(fragment, dict):
        return fragment
    _type = fragment.get('_type')
    if not _type:
        return fragment
    cls = type_map.get(_type)
    if cls is None:
        return fragment
    valid_fields = set(cls.fields())
    result = {}
    user_fields_seen = 0
    user_fields_kept = 0
    for k, v in fragment.items():
        if k.startswith('$') or k.startswith('_'):
            result[k] = v
            continue
        user_fields_seen += 1
        top_field = k.split('.')[0]
        if top_field in valid_fields:
            result[k] = v
            user_fields_kept += 1
        else:
            _warn_unknown_field(k, _type, valid_fields)
    # If the fragment had user-specified fields but ALL were invalid, signal
    # the caller to drop this fragment entirely rather than keeping a bare
    # {'_type': _type} that would match every object of that type.
    if user_fields_seen > 0 and user_fields_kept == 0:
        return None
    return result


def _validate_query(q, type_map):
    if not isinstance(q, dict):
        return q
    if '$or' in q:
        parts = [_validate_query(sub, type_map) for sub in q['$or']]
        parts = [p for p in parts if p]
        if len(parts) == 0:
            return {}
        if len(parts) == 1:
            return parts[0]
        return {'$or': parts}
    if '$and' in q:
        parts = [_validate_query(sub, type_map) for sub in q['$and']]
        parts = [p for p in parts if p]
        if len(parts) == 0:
            return {}
        if len(parts) == 1:
            return parts[0]
        return {'$and': parts}
    result = _validate_fragment(q, type_map)
    return result if result is not None else {}


def validate_query_fields(query):
    """Validate field names in a MongoDB-style query against known output types.

    For each fragment referencing a known _type, checks that the queried fields
    exist on that type. Prints a warning (with available fields) for unknown fields
    and removes them from the query.
    Returns the (possibly modified) query dict.
    """
    if not query or not isinstance(query, dict):
        return query

    type_map = _build_type_map()
    return _validate_query(query, type_map)


def query_has_type_constraint(query):
    """Check whether a MongoDB-style query contains a '_type' constraint anywhere (recursively).

    Args:
        query (dict | list): MongoDB-style query (or sub-query list from $and / $or).

    Returns:
        bool: True if a '_type' key is present at any nesting level.
    """
    if isinstance(query, dict):
        for key, value in query.items():
            if key == '_type':
                return True
            if isinstance(value, (dict, list)) and query_has_type_constraint(value):
                return True
    elif isinstance(query, list):
        return any(query_has_type_constraint(item) for item in query)
    return False

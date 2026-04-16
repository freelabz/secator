"""Utilities for converting CLI query syntax to MongoDB-style queries."""

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

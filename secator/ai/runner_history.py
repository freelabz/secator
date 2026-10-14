"""Helpers for the AI ``list_runners`` tool (runner run-history).

Pure, backend-agnostic functions over the runner dicts returned by
``QueryEngine.list_runners`` — timestamp parsing (a runner's ``start_time`` is an
epoch float on the json store but an ISO string once serialized elsewhere), a
relative/absolute ``since`` window parser ("24h", "7d", an ISO date), and the
filter/sort/summarize step. Kept out of the handler so they are unit-testable
without the AI action machinery.
"""

import re
from datetime import datetime, timedelta, timezone

_WINDOW_RE = re.compile(r'^\s*(\d+)\s*([smhdw])\s*$', re.I)
_UNIT_SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}

# The compact fields returned to the model per runner (rich runner docs are huge —
# config/opts/profiles/results would blow the token budget for a history listing).
SUMMARY_FIELDS = (
	'name', 'status', 'targets', 'start_time', 'end_time', 'elapsed_human',
	'results_count', 'errors_count', 'progress',
)


def parse_dt(value):
	"""Parse a runner timestamp into an aware UTC ``datetime``, or None.

	Accepts an epoch int/float (json store), an ISO-8601 string (serialized backends,
	trailing ``Z`` tolerated), or a ``datetime`` (naive is assumed UTC)."""
	if value is None or value == '':
		return None
	if isinstance(value, datetime):
		return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
	if isinstance(value, (int, float)):
		try:
			return datetime.fromtimestamp(float(value), tz=timezone.utc)
		except (OverflowError, OSError, ValueError):
			return None
	if isinstance(value, str):
		v = value.strip()
		# A bare epoch that arrived as a string.
		if re.fullmatch(r'\d+(\.\d+)?', v):
			try:
				return datetime.fromtimestamp(float(v), tz=timezone.utc)
			except (OverflowError, OSError, ValueError):
				return None
		try:
			dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
			return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
		except ValueError:
			return None
	return None


def parse_since(since, now=None):
	"""Turn a ``since`` argument into a UTC cutoff ``datetime``, or None if unset/unparseable.

	Accepts a relative window (``24h``, ``7d``, ``30m``, ``90s``, ``2w``) or an absolute
	ISO-8601 date/datetime. ``now`` is injectable for tests."""
	if not since:
		return None
	now = now or datetime.now(timezone.utc)
	m = _WINDOW_RE.match(str(since))
	if m:
		return now - timedelta(seconds=int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()])
	return parse_dt(since)


def summarize_runner(runner):
	"""Reduce a full runner dict to the compact history summary (SUMMARY_FIELDS + ids)."""
	out = {k: runner.get(k) for k in SUMMARY_FIELDS if k in runner}
	out['_type'] = (runner.get('_type') or '').rstrip('s')
	rid = runner.get('_id') or runner.get('_id_str')
	if rid:
		out['_id'] = rid
	return out


def filter_runners(runners, since=None, status=None, limit=50, now=None):
	"""Filter runners by ``since`` (cutoff on start_time, else end_time) and ``status``,
	sort newest-first, cap to ``limit``, and return compact summaries.

	Runners with no parseable timestamp are dropped when a ``since`` filter is set (they
	can't be shown to satisfy a time window) and sorted last otherwise."""
	cutoff = parse_since(since, now=now)
	status_norm = status.strip().upper() if isinstance(status, str) and status.strip() else None
	rows = []
	for r in runners:
		if status_norm and str(r.get('status', '')).upper() != status_norm:
			continue
		dt = parse_dt(r.get('start_time')) or parse_dt(r.get('end_time'))
		if cutoff is not None and (dt is None or dt < cutoff):
			continue
		rows.append((dt, r))
	# newest first; unknown-timestamp runners sort last (only reachable when no `since`).
	rows.sort(key=lambda t: (t[0] is not None, t[0] or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
	try:
		limit = int(limit)
	except (TypeError, ValueError):
		limit = 50
	if limit > 0:
		rows = rows[:limit]
	return [summarize_runner(r) for _, r in rows]

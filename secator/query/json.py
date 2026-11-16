# secator/query/json.py

import json
import orjson
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from secator.query._base import QueryBackend
from secator.config import CONFIG
from secator.utils import sanitize_folder_name
from secator.utils import debug


def resolve_local_report_paths(report_query, workspace_name):
	"""Rewrite a `report show`/`query` runner path so a human-friendly on-disk folder number resolves
	to the runner's real {type}_id (the UUID stamped into findings' _context).

	Local runs keep two ids: the sequential report FOLDER number (``tasks/0``, user-facing) and the
	run-scope ``_context.{type}_id`` UUID that findings actually carry. A path like ``task/0`` names the
	folder, so translate ``0`` -> that folder's ``info.context.{type}_id`` before it becomes a query
	filter. Values that are not a local folder number (already a UUID, or a missing folder) pass through
	unchanged. Only meaningful for the local json backend; DB backends already store the real id.

	Args:
		report_query (str): Comma-separated runner paths, e.g. ``tasks/0,scans/5``.
		workspace_name (str): Workspace whose report tree to resolve against.

	Returns:
		str: The runner path with folder numbers replaced by their real {type}_id.
	"""
	if not report_query:
		return report_query
	ws_path = Path(CONFIG.dirs.reports).expanduser() / sanitize_folder_name(workspace_name)
	out = []
	for part in report_query.split(','):
		token = part.strip()
		if '/' not in token:
			out.append(part)
			continue
		runner_type, runner_id = token.split('/', 1)
		singular = runner_type.strip().lower().rstrip('s')
		report_file = ws_path / f'{singular}s' / runner_id.strip() / 'report.json'
		try:
			with open(report_file) as f:
				real_id = json.load(f).get('info', {}).get('context', {}).get(f'{singular}_id')
			out.append(f'{runner_type}/{real_id}' if real_id else part)
		except (FileNotFoundError, json.JSONDecodeError):
			out.append(part)
	return ','.join(out)


def _regex_match(field, pattern):
	if field is None:
		return False
	pattern = str(pattern)
	# Strip the leading-glob convention, honoring an inline (?i) case-insensitivity flag.
	if pattern.startswith('(?i)'):
		pattern = '(?i)' + pattern[4:].lstrip('*')
	else:
		pattern = pattern.lstrip('*')
	try:
		return re.search(pattern, str(field)) is not None
	except re.error:
		return False


OPERATORS = {
	"$regex": _regex_match,
	"$contains": lambda field, value: value in str(field) if field else False,
	"$in": lambda field, values: field in values if field else False,
	"$nin": lambda field, values: field not in values if field else False,
	"$gt": lambda field, value: field > value if field is not None else False,
	"$gte": lambda field, value: field >= value if field is not None else False,
	"$lt": lambda field, value: field < value if field is not None else False,
	"$lte": lambda field, value: field <= value if field is not None else False,
	"$ne": lambda field, value: field != value,
}


def get_nested_field(item, key: str) -> Any:
	"""Get nested field value using dot notation (e.g., '_context.workspace_id').

	Supports both dict and object (e.g. OutputType dataclass) access.
	"""
	keys = key.split('.')
	value = item
	for k in keys:
		if isinstance(value, dict):
			value = value.get(k)
		elif hasattr(value, k):
			value = getattr(value, k)
		else:
			return None
	return value


def match_query(item: dict, query: dict) -> bool:
	"""Check if item matches MongoDB-style query."""
	if '$and' in query:
		and_result = all(match_query(item, sub_query) for sub_query in query['$and'])
		remaining = {k: v for k, v in query.items() if k != '$and'}
		if remaining:
			return and_result and match_query(item, remaining)
		return and_result
	if '$or' in query:
		or_result = any(match_query(item, sub_query) for sub_query in query['$or'])
		remaining = {k: v for k, v in query.items() if k != '$or'}
		if remaining:
			return or_result and match_query(item, remaining)
		return or_result
	for key, condition in query.items():
		value = get_nested_field(item, key)

		if isinstance(condition, dict):
			for op, op_value in condition.items():
				if op == '$not':
					# Negated operator dict, e.g. {'$not': {'$regex': p}} from '!~='.
					# Fails the match if every inner operator matches.
					if isinstance(op_value, dict) and all(
						OPERATORS[iop](value, ival)
						for iop, ival in op_value.items() if iop in OPERATORS
					):
						return False
					continue
				if op not in OPERATORS:
					continue
				if not OPERATORS[op](value, op_value):
					return False
		else:
			if value != condition:
				return False
	return True


def _apply_set(rec: dict, set_fields: dict) -> None:
	"""Apply a MongoDB-style ``$set`` to ``rec`` in place, resolving dotted keys to
	nested dicts (``extra_data.foo`` -> ``rec['extra_data']['foo']``)."""
	for k, v in set_fields.items():
		if '.' in k:
			parts = k.split('.')
			cur = rec
			for p in parts[:-1]:
				nxt = cur.get(p)
				if not isinstance(nxt, dict):
					nxt = {}
					cur[p] = nxt
				cur = nxt
			cur[parts[-1]] = v
		else:
			rec[k] = v


class JsonBackend(QueryBackend):
	"""Query backend for JSON files on filesystem."""

	name = "json"

	def __init__(self, workspace_id: str, config: Optional[dict] = None,
				 context: Optional[dict] = None):
		super().__init__(workspace_id, config, context=context)
		reports_dir = config.get('reports_dir', CONFIG.dirs.reports) if config else CONFIG.dirs.reports
		self.reports_dir = Path(reports_dir).expanduser()

	def get_base_query(self) -> dict:
		"""No base query needed for JSON - workspace filtering is done by directory."""
		# Don't filter by _context fields since local JSON files may not have them
		# Workspace filtering is implicit (we only load from the workspace directory)
		return {}

	def _get_workspace_path(self) -> Path:
		"""Get path to workspace reports directory."""
		# Sanitize workspace name the same way as the runner does
		workspace_folder = sanitize_folder_name(self.workspace_id)
		return self.reports_dir / workspace_folder

	def _iter_report_dir(self, report_dir: Path, runner_type_singular: str, query: dict, line_filter: str = None):
		"""Yield one runner's records matching ``query``, keeping only each finding's LATEST record.

		The live store (``results.ndjson``) is append-only: updating a finding appends a new record
		for the same ``_uuid`` and the last one wins. A finding therefore matches (or not) by its
		latest record only — an OPEN finding later updated to FIXED is not returned for
		``status: OPEN``. Records are yielded at their latest record's position (the order a
		compacted store keeps, see ``secator.utils.compact_ndjson``).

		Two streaming passes over ONE open file handle: pass 1 indexes each ``_uuid``'s last line
		(small entries, never full records), pass 2 yields the latest records that match. Using the
		same handle means a concurrent compaction (which replaces the file) cannot shift positions
		between the passes. Memory stays O(distinct uuids in this file); the caller can stop early.
		Each record gets the ``{type}_id`` context injection. A legacy ``report.json`` (no ndjson)
		is read whole.

		``line_filter``: skip ndjson lines not containing this string before parsing (a cheap
		prefilter for point reads; the parsed record is still checked)."""
		runner_id = report_dir.name

		def _tag(rec):
			if isinstance(rec, dict) and f'{runner_type_singular}_id' not in rec.get('_context', {}):
				rec.setdefault('_context', {})[f'{runner_type_singular}_id'] = runner_id
			return rec

		def _uid(rec):
			return rec.get('_uuid') if isinstance(rec, dict) else None

		def _latest_matching(records):
			"""records: callable returning a fresh iterator of (index, record)."""
			latest = {}
			for index, rec in records():
				uid = _uid(rec)
				if uid:
					latest[uid] = index
			for index, rec in records():
				uid = _uid(rec)
				if uid and latest.get(uid) != index:
					continue  # superseded by a later record of the same finding
				rec = _tag(rec)
				if match_query(rec, query):
					yield rec

		ndjson = report_dir / 'results.ndjson'
		if ndjson.exists():
			needle = line_filter.encode() if line_filter else None
			try:
				with open(ndjson, 'rb') as f:
					def records():
						f.seek(0)
						for index, line in enumerate(f):
							if needle and needle not in line:
								continue
							line = line.strip()
							if not line:
								continue
							try:
								yield index, orjson.loads(line)
							except json.JSONDecodeError:
								continue  # torn final line after a crash -> skip
					yield from _latest_matching(records)
			except IOError as e:
				debug(f'Error reading {ndjson}: {e}', sub='query.json')
			return
		report_file = report_dir / 'report.json'
		if not report_file.exists():
			return
		try:
			with open(report_file, 'r') as f:
				data = orjson.loads(f.read())  # legacy/completed report — nested JSON, can't stream without json_stream
		except (json.JSONDecodeError, IOError) as e:
			debug(f'Error loading {report_file}: {e}', sub='query.json')
			return
		flat = [rec for lst in data.get('results', {}).values() if isinstance(lst, list) for rec in lst]
		yield from _latest_matching(lambda: enumerate(flat))

	def _iter_latest(self, query: dict):
		"""Stream the records matching ``query`` across the run-scoped dir (when hinted) or every
		runner dir of the workspace, each finding by its latest record (see ``_iter_report_dir``).
		A point read (``_uuid`` equality) only parses lines containing that uuid. A finding lives in
		one runner's store; should a ``_uuid`` appear in several, the first runner dir read wins."""
		uuid = query.get('_uuid') if isinstance(query, dict) else None
		line_filter = uuid if isinstance(uuid, str) and uuid else None
		report_dir = self.context.get('report_dir')
		if report_dir:
			report_dir = Path(report_dir)
			dirs = [(report_dir, report_dir.parent.name.rstrip('s') or 'task')]
		else:
			workspace_path = self._get_workspace_path()
			dirs = []
			if workspace_path.exists():
				for runner_type in ['tasks', 'workflows', 'scans']:
					runner_path = workspace_path / runner_type
					if runner_path.exists():
						dirs.extend((d, runner_type.rstrip('s')) for d in runner_path.iterdir() if d.is_dir())
		seen = set()
		for d, singular in dirs:
			for rec in self._iter_report_dir(d, singular, query, line_filter):
				uid = rec.get('_uuid') if isinstance(rec, dict) else None
				if uid:
					if uid in seen:
						continue
					seen.add(uid)
				yield rec

	def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None,
	                    offset: int = 0) -> List[Dict[str, Any]]:
		"""Search findings matching query by FILTERING WHILE STREAMING over each finding's latest
		record (``_iter_latest``): peak memory is O(distinct uuids) small index entries plus the
		returned page, never every matching record, and the scan stops once ``offset + limit``
		matches are collected."""
		results = []
		for rec in self._iter_latest(query):
			if offset:
				offset -= 1
				continue
			if exclude_fields and isinstance(rec, dict):
				rec = {k: v for k, v in rec.items() if k not in exclude_fields}
			results.append(rec)
			if limit and len(results) >= limit:
				break
		return results

	def _execute_iterate(self, query: dict, batch_size: int = 1000):
		"""Stream matching records in batches (each finding's latest record, see ``_iter_latest``),
		never materializing the full record set (the base impl does _execute_search(limit=0), which
		collects everything). Used by the exporters (via StreamView.__iter__) so a report over N
		findings stays flat."""
		batch = []
		for rec in self._iter_latest(query):
			batch.append(rec)
			if len(batch) >= batch_size:
				yield batch
				batch = []
		if batch:
			yield batch

	def _execute_count(self, query: dict) -> int:
		"""Count DISTINCT matching findings by their latest record (see ``_iter_latest``)."""
		return sum(1 for _ in self._iter_latest(query))

	def _report_dirs(self):
		"""Yield each runner's report DIR — the run-scoped dir when ``context['report_dir']``
		is set, else every runner dir in the workspace. Yields dirs (not ``report.json`` paths) so
		the live ``results.ndjson`` is reachable too."""
		report_dir = self.context.get('report_dir')
		if report_dir:
			p = Path(report_dir)
			if p.exists():
				yield p
			return
		workspace_path = self._get_workspace_path()
		if not workspace_path.exists():
			return
		for runner_type in ['tasks', 'workflows', 'scans']:
			runner_path = workspace_path / runner_type
			if not runner_path.exists():
				continue
			for d in runner_path.iterdir():
				if d.is_dir():
					yield d

	def _execute_update(self, query: dict, update: dict) -> int:
		"""Apply a ``$set`` to matching findings directly in the store.

		The live store is the append-only ``results.ndjson`` (last-wins by ``_uuid`` on
		read), so an update appends the matched record with the ``$set`` applied — the same
		mechanism the ``update_finding`` hook uses — instead of rewriting a bucketed
		``report.json`` the runner only writes at end-of-run (mid-run, findings are queryable
		from the ndjson but were NOT in report.json, so the old rewrite matched nothing).
		Legacy dirs that only have a ``report.json`` keep the atomic-rewrite path.
		"""
		set_fields = update.get("$set", {})
		if not set_fields:
			return 0
		from secator.utils import append_ndjson, atomic_json, read_json
		count = 0
		for d in self._report_dirs():
			ndjson = d / 'results.ndjson'
			if ndjson.exists():
				# Collapse to the latest record per _uuid (matching read-time dedup), then
				# append an updated copy of each match so it wins on the next read.
				latest, order = {}, []
				try:
					with open(ndjson, 'r') as f:
						for line in f:
							line = line.strip()
							if not line:
								continue
							try:
								rec = orjson.loads(line)
							except json.JSONDecodeError:
								continue  # torn final line after a crash -> skip
							if not isinstance(rec, dict):
								continue
							key = rec.get('_uuid') or id(rec)
							if key not in latest:
								order.append(key)
							latest[key] = rec
				except IOError as e:
					debug(f'Error reading {ndjson}: {e}', sub='query.json')
					continue
				for key in order:
					rec = latest[key]
					if match_query(rec, query):
						_apply_set(rec, set_fields)
						append_ndjson(ndjson, orjson.dumps(rec, default=str).decode())
						count += 1
				continue
			# Legacy: rewrite the bucketed report.json in place.
			report = d / 'report.json'
			if not report.exists():
				continue
			data = read_json(report)
			if not data:
				continue
			buckets = data.get('results', {})
			if not any(match_query(it, query) for b in buckets.values() if isinstance(b, list) for it in b):
				continue
			with atomic_json(report, default=lambda: {'info': {}, 'results': {}}) as dd:
				for bucket in dd.get('results', {}).values():
					if isinstance(bucket, list):
						for item in bucket:
							if match_query(item, query):
								_apply_set(item, set_fields)
								count += 1
		return count

	def _execute_create_note(self, note: dict) -> int:
		"""Append the note to a workspace-level ``notes.ndjson`` (append-only, like the
		findings store). Notes live beside the runner report dirs, not inside one, so they
		aren't scoped to a single run — a note annotates a finding identity across re-scans.
		"""
		try:
			from secator.utils import append_ndjson
			ws = self._get_workspace_path()
			ws.mkdir(parents=True, exist_ok=True)
			append_ndjson(ws / 'notes.ndjson', orjson.dumps(note, default=str).decode())
			return 1
		except Exception as e:
			debug(f'JSON create_note failed: {e}', sub='query.json')
			return 0

	def list_workspaces(self):
		"""List workspaces from local reports directory."""
		workspaces = []
		if self.reports_dir.exists():
			for child in sorted(self.reports_dir.iterdir()):
				if child.is_dir():
					workspaces.append({
						'workspace_id': child.name,
						'workspace_name': child.name,
						'path': str(child),
					})
		return workspaces

	def get_workspace(self, workspace_id: str):
		"""Get workspace info from local filesystem."""
		workspace_path = self.reports_dir / sanitize_folder_name(workspace_id)
		if workspace_path.exists():
			return {'workspace_id': workspace_id, 'workspace_name': workspace_id, 'path': str(workspace_path)}
		return None

	def list_runners(self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
					 has_parent: Optional[bool] = None):
		"""List runners from local report JSON files.

		has_parent: when not None, only return runners matching that parent relationship
		(False = outermost runners only, True = nested children only).
		"""
		from secator.utils import list_reports, get_info_from_report_path
		paths = list_reports(workspace=workspace_id, type=runner_type)
		runners = []
		for path in paths:
			try:
				path_info = get_info_from_report_path(path)
				with open(path, 'r') as f:
					data = json.load(f)
				info = data.get('info', {})
				if has_parent is not None and info.get('has_parent', False) != has_parent:
					continue
				info['_type'] = path_info.get('type', '')
				info['_id'] = path_info.get('type', '') + '/' + path_info.get('id', '')
				info['_workspace'] = path_info.get('workspace', '')
				info['_path'] = str(path)
				runners.append(info)
			except Exception as e:
				debug(f'failed to load runner report {path}: {e}', sub='query.json')
				continue
		return runners

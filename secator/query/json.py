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


class JsonBackend(QueryBackend):
	"""Query backend for JSON files on filesystem."""

	name = "json"

	def __init__(self, workspace_id: str, config: Optional[dict] = None,
				 context: Optional[dict] = None):
		super().__init__(workspace_id, config, context=context)
		self._findings_cache = None
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

	def _load_all_findings(self) -> List[Dict[str, Any]]:
		"""Load findings from the LIVE report.json store — the SOLE source (no in-memory results).

		The json driver (#1299) writes each runner's report.json as results are produced, so the
		files are the authoritative store. A run-scoped read (``context['report_dir']``) reads only
		this run's report.json; without the hint it falls back to a full workspace scan.
		"""
		if self._findings_cache is not None:
			return self._findings_cache
		findings = self._load_from_files()
		self._findings_cache = findings
		return findings

	def _read_report_dir(self, report_dir: Path, runner_type_singular: str, findings: list):
		"""Append one runner's findings to `findings`, reading results.ndjson (live/new format)
		or falling back to report.json['results'] (legacy/completed pre-ndjson reports)."""
		ndjson = report_dir / 'results.ndjson'
		if ndjson.exists():
			by_uuid = {}
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
						by_uuid[rec.get('_uuid') or id(rec)] = rec  # last-wins
			except IOError as e:
				debug(f'Error reading {ndjson}: {e}', sub='query.json')
				return
			items = list(by_uuid.values())
		else:
			report_file = report_dir / 'report.json'
			if not report_file.exists():
				return
			try:
				with open(report_file, 'r') as f:
					data = json.load(f)
			except (json.JSONDecodeError, IOError) as e:
				debug(f'Error loading {report_file}: {e}', sub='query.json')
				return
			items = [it for lst in data.get('results', {}).values()
					 if isinstance(lst, list) for it in lst]
		runner_id = report_dir.name
		for item in items:
			if f'{runner_type_singular}_id' not in item.get('_context', {}):
				item.setdefault('_context', {})[f'{runner_type_singular}_id'] = runner_id
		findings.extend(items)

	def _load_from_files(self) -> List[Dict[str, Any]]:
		"""Load findings from report.json files.

		A run-scoped read (``context['report_dir']``) reads ONLY that one runner's report.json — the
		hot path during a run. Fan-in re-persists every descendant finding up into each ancestor's
		report.json (re-tagged with the ancestor's {type}_id), so a runner's own file already holds its
		complete result set: no need to scan (and re-parse) every historical report in the workspace on
		every query. Without the hint we fall back to the full workspace scan (report show, cross-run
		aggregation).
		"""
		findings = []
		report_dir = self.context.get('report_dir')
		if report_dir:
			report_dir = Path(report_dir)
			# tasks/<n> -> singular 'task' (parent dir name minus trailing 's'); default 'task'.
			singular = report_dir.parent.name.rstrip('s') or 'task'
			self._read_report_dir(report_dir, singular, findings)
			debug(f'Loaded {len(findings)} findings from run-scoped {report_dir}', sub='query.json')
			return findings

		workspace_path = self._get_workspace_path()
		debug(f'Looking for reports in: {workspace_path}', sub='query.json')
		debug(f'Workspace ID/name: {self.workspace_id}', sub='query.json')
		if not workspace_path.exists():
			debug(f'Workspace path does not exist: {workspace_path}', sub='query.json')
			if self.reports_dir.exists():
				available = [d.name for d in self.reports_dir.iterdir() if d.is_dir()]
				debug(f'Available workspaces in {self.reports_dir}: {available}', sub='query.json')
			return findings

		for runner_type in ['tasks', 'workflows', 'scans']:
			runner_path = workspace_path / runner_type
			if not runner_path.exists():
				continue
			for report_dir in runner_path.iterdir():
				if report_dir.is_dir():
					self._read_report_dir(report_dir, runner_type.rstrip('s'), findings)

		debug(f'Loaded {len(findings)} findings from workspace', sub='query.json')
		return findings

	def _iter_report_dir(self, report_dir: Path, runner_type_singular: str):
		"""Yield one runner's records one at a time — the ndjson streamed line-by-line (or a legacy
		report.json), with the {type}_id injection. No dedup or list here: this is the O(1)-memory
		read used for filter-while-streaming; last-wins dedup, when needed, is done by the caller over
		its (small) kept subset, not over the whole file."""
		runner_id = report_dir.name

		def _tag(rec):
			if isinstance(rec, dict) and f'{runner_type_singular}_id' not in rec.get('_context', {}):
				rec.setdefault('_context', {})[f'{runner_type_singular}_id'] = runner_id
			return rec

		ndjson = report_dir / 'results.ndjson'
		if ndjson.exists():
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
						yield _tag(rec)
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
		for lst in data.get('results', {}).values():
			if isinstance(lst, list):
				for rec in lst:
					yield _tag(rec)

	def _iter_records(self):
		"""Stream store records one at a time — never materializes the full result set. Mirrors
		_load_from_files' scoping (run-scoped report_dir hot path, else workspace scan)."""
		report_dir = self.context.get('report_dir')
		if report_dir:
			report_dir = Path(report_dir)
			singular = report_dir.parent.name.rstrip('s') or 'task'
			yield from self._iter_report_dir(report_dir, singular)
			return
		workspace_path = self._get_workspace_path()
		if not workspace_path.exists():
			return
		for runner_type in ['tasks', 'workflows', 'scans']:
			runner_path = workspace_path / runner_type
			if not runner_path.exists():
				continue
			for report_dir in runner_path.iterdir():
				if report_dir.is_dir():
					yield from self._iter_report_dir(report_dir, runner_type.rstrip('s'))

	def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None) -> List[Dict[str, Any]]:
		"""Search findings matching query by FILTERING WHILE STREAMING — peak memory is O(matches),
		not O(total findings). The fan-in extractor's one store query used to materialize the whole
		result set (_load_all_findings) before filtering to a handful of matches, which was the O(N)
		peak that defeated streaming. We iterate records one at a time, match, and keep only matches,
		deduped last-wins by _uuid over the (small) matched subset."""
		by_uuid = {}
		for finding in self._iter_records():
			if not match_query(finding, query):
				continue
			if exclude_fields and isinstance(finding, dict):
				finding = {k: v for k, v in finding.items() if k not in exclude_fields}
			by_uuid[(finding.get('_uuid') if isinstance(finding, dict) else None) or id(finding)] = finding
			if limit and len(by_uuid) >= limit:
				break
		return list(by_uuid.values())

	def _execute_iterate(self, query: dict, batch_size: int = 1000):
		"""Stream matching records in batches — O(batch) + O(distinct uuids), never materializing the
		full record set (the base impl does _execute_search(limit=0), which collects everything). Used
		by the exporters (via StreamView.__iter__) so a report over N findings stays flat. Deduped
		keep-first by _uuid with a seen-set, so the append-only ndjson's re-emitted lines don't yield
		duplicate rows. (Keep-first, not last-wins: true last-wins can't stream; fine for a report.)"""
		seen = set()
		batch = []
		for rec in self._iter_records():
			if not match_query(rec, query):
				continue
			uid = rec.get('_uuid') if isinstance(rec, dict) else None
			if uid is not None:
				if uid in seen:
					continue
				seen.add(uid)
			batch.append(rec)
			if len(batch) >= batch_size:
				yield batch
				batch = []
		if batch:
			yield batch

	def _execute_count(self, query: dict) -> int:
		"""Count DISTINCT matching findings by streaming (seen-set of _uuids), not by materializing
		every record via _load_all_findings — same O(distinct) memory as iterate, not O(all)."""
		seen = set()
		n = 0
		for rec in self._iter_records():
			if not match_query(rec, query):
				continue
			uid = rec.get('_uuid') if isinstance(rec, dict) else None
			if uid is None:
				n += 1
			elif uid not in seen:
				seen.add(uid)
				n += 1
		return n

	def _report_files(self):
		"""Yield the report.json paths this backend reads — the run-scoped file when
		``context['report_dir']`` is set, else every report in the workspace."""
		report_dir = self.context.get('report_dir')
		if report_dir:
			p = Path(report_dir) / 'report.json'
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
				if d.is_dir() and (d / 'report.json').exists():
					yield d / 'report.json'

	def _execute_update(self, query: dict, update: dict) -> int:
		"""Apply a ``$set`` update to matching findings directly in the report.json store.

		The store is the source of truth (no in-memory results). Each matching file is
		rewritten atomically; a read-first dirty check skips files with no match so an
		update never rewrites the whole workspace.
		"""
		set_fields = update.get("$set", {})
		if not set_fields:
			return 0
		from secator.utils import atomic_json, read_json
		count = 0
		for path in self._report_files():
			data = read_json(path)
			if not data:
				continue
			buckets = data.get('results', {})
			if not any(match_query(it, query) for b in buckets.values() if isinstance(b, list) for it in b):
				continue
			with atomic_json(path, default=lambda: {'info': {}, 'results': {}}) as d:
				for bucket in d.get('results', {}).values():
					if isinstance(bucket, list):
						for item in bucket:
							if match_query(item, query):
								item.update(set_fields)
								count += 1
		self._findings_cache = None
		return count

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

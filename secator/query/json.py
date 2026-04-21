# secator/query/json.py

import json
import re
from pathlib import Path
from typing import Generator, List, Dict, Any, Optional

from secator.query._base import QueryBackend
from secator.config import CONFIG
from secator.utils import sanitize_folder_name
from secator.utils import debug


OPERATORS = {
	"$regex": lambda field, pattern: re.search(pattern, str(field)) is not None if field else False,
	"$contains": lambda field, value: value in str(field) if field else False,
	"$in": lambda field, values: field in values if field else False,
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
				 context: Optional[dict] = None, results: Optional[list] = None):
		super().__init__(workspace_id, config, context=context)
		self._results = results
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

	def _load_all_findings(self) -> Generator[Dict[str, Any], None, None]:
		"""Yield findings from workspace JSON files, or iterate pre-loaded results."""
		if self._results is not None:
			yield from self._results
			return

		workspace_path = self._get_workspace_path()
		debug(f'Looking for reports in: {workspace_path}', sub='query.json')
		debug(f'Workspace ID/name: {self.workspace_id}', sub='query.json')

		if not workspace_path.exists():
			debug(f'Workspace path does not exist: {workspace_path}', sub='query.json')
			if self.reports_dir.exists():
				available = [d.name for d in self.reports_dir.iterdir() if d.is_dir()]
				debug(f'Available workspaces in {self.reports_dir}: {available}', sub='query.json')
			return

		for runner_type in ['tasks', 'workflows', 'scans']:
			runner_path = workspace_path / runner_type
			if not runner_path.exists():
				continue

			for report_dir in runner_path.iterdir():
				if not report_dir.is_dir():
					continue

				report_file = report_dir / 'report.json'
				if report_file.exists():
					try:
						with open(report_file, 'r') as f:
							data = json.load(f)

						results = data.get('results', {})
						runner_type_singular = runner_type.rstrip('s')  # "tasks" -> "task", "scans" -> "scan"
						runner_id = report_dir.name

						for type_name, items in results.items():
							if isinstance(items, list):
								for item in items:
									if f'{runner_type_singular}_id' not in item['_context']:
										item['_context'][f'{runner_type_singular}_id'] = runner_id
									yield item
					except (json.JSONDecodeError, IOError) as e:
						debug(f'Error loading {report_file}: {e}', sub='query.json')
						continue

	def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None) -> List[Dict[str, Any]]:
		"""Search findings matching query."""
		matched = []
		for finding in self._load_all_findings():
			if match_query(finding, query):
				if exclude_fields and isinstance(finding, dict):
					finding = {k: v for k, v in finding.items() if k not in exclude_fields}
				matched.append(finding)
				if limit and len(matched) >= limit:
					break
		return matched

	def _execute_count(self, query: dict) -> int:
		"""Count findings matching query."""
		return sum(1 for f in self._load_all_findings() if match_query(f, query))

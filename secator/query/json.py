# secator/query/json.py

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from secator.query._base import QueryBackend
from secator.config import CONFIG
from secator.utils import sanitize_folder_name


OPERATORS = {
    "$regex": lambda field, pattern: re.search(pattern, str(field)) is not None if field else False,
    "$contains": lambda field, value: value in str(field) if field else False,
    "$startswith": lambda field, value: str(field).startswith(value) if field else False,
    "$in": lambda field, values: field in values if field else False,
    "$gt": lambda field, value: field > value if field is not None else False,
    "$gte": lambda field, value: field >= value if field is not None else False,
    "$lt": lambda field, value: field < value if field is not None else False,
    "$lte": lambda field, value: field <= value if field is not None else False,
    "$ne": lambda field, value: field != value,
}


def get_nested_field(item: dict, key: str) -> Any:
    """Get nested field value using dot notation (e.g., '_context.workspace_id')."""
    keys = key.split('.')
    value = item
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            return None
    return value


def match_query(item: dict, query: dict) -> bool:
    """Check if item matches MongoDB-style query."""
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

    def __init__(self, workspace_id: str, config: Optional[dict] = None):
        super().__init__(workspace_id, config)
        reports_dir = config.get('reports_dir', CONFIG.dirs.reports) if config else CONFIG.dirs.reports
        self.reports_dir = Path(reports_dir).expanduser()

    def get_base_query(self) -> dict:
        """No base query needed for JSON - workspace filtering is done by directory."""
        # Don't filter by _context fields since local JSON files may not have them
        # Workspace filtering is implicit (we only load from the workspace directory)
        return {}

    def _get_workspace_path(self) -> Path:
        """Get path to workspace reports directory."""
        return self.reports_dir / self.workspace_id

    def _load_all_findings(self) -> List[Dict[str, Any]]:
        """Load all findings from workspace JSON files."""
        findings = []
        workspace_path = self._get_workspace_path()

        if not workspace_path.exists():
            return findings

        # Search for report.json files in tasks/, workflows/, scans/
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
                        for type_name, items in results.items():
                            if isinstance(items, list):
                                findings.extend(items)
                    except (json.JSONDecodeError, IOError):
                        continue

        return findings

    def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None) -> List[Dict[str, Any]]:
        """Search findings matching query."""
        findings = self._load_all_findings()

        matched = []
        for finding in findings:
            if match_query(finding, query):
                # Remove excluded fields
                if exclude_fields:
                    finding = {k: v for k, v in finding.items() if k not in exclude_fields}
                matched.append(finding)
                if len(matched) >= limit:
                    break

        return matched

    def _execute_count(self, query: dict) -> int:
        """Count findings matching query."""
        findings = self._load_all_findings()
        return sum(1 for f in findings if match_query(f, query))

# secator/query/_base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from secator.utils import debug


class QueryBackend(ABC):
    """Abstract base class for query backends."""

    name: str = "base"

    DEFAULT_LIMIT = 100

    PROTECTED_FIELDS = [
        "_context.workspace_id",
        "_context.workspace_duplicate",
    ]

    def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
        self.workspace_id = workspace_id
        self.config = config or {}
        self.context = context or {}

    def get_base_query(self) -> dict:
        """Base query - ALWAYS enforced, cannot be overridden."""
        base = {
            "_context.workspace_id": self.workspace_id,
            "_context.workspace_duplicate": False,
            "is_false_positive": False
        }
        # Narrow scope to current scan/workflow/task if available
        for key in ('scan_id', 'workflow_id', 'task_id'):
            value = self.context.get(key)
            if value:
                base[f"_context.{key}"] = value
                break
        return base

    def _merge_query(self, query: dict) -> dict:
        """Merge user query with base query. Base query always wins."""
        merged = query.copy()

        for field in self.PROTECTED_FIELDS:
            if field in merged:
                del merged[field]

        base = self.get_base_query()
        merged.update(base)

        return merged

    def search(self, query: dict, limit: int = None, exclude_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Execute query with enforced base query."""
        if limit is None:
            limit = self.DEFAULT_LIMIT
        if exclude_fields is None:
            exclude_fields = []
        safe_query = self._merge_query(query)
        debug_ctx = {k: v for k, v in self.context.items() if k != 'results'}
        debug('context', sub=f'query.{self.name}', obj=debug_ctx)
        if hasattr(self, '_results') and self._results is not None:
            debug(f'{len(self._results)} pre-loaded results', sub=f'query.{self.name}')
        debug('search', sub=f'query.{self.name}', obj=safe_query)
        results = self._execute_search(safe_query, limit, exclude_fields)
        debug(f'{len(results)} results', sub=f'query.{self.name}')
        return results

    @abstractmethod
    def _execute_search(self, query: dict, limit: int, exclude_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Backend-specific search implementation."""
        pass

    def count(self, query: dict) -> int:
        """Count matching findings with enforced base query."""
        safe_query = self._merge_query(query)
        return self._execute_count(safe_query)

    @abstractmethod
    def _execute_count(self, query: dict) -> int:
        """Backend-specific count implementation."""
        pass

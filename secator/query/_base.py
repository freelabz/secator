# secator/query/_base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class QueryBackend(ABC):
    """Abstract base class for query backends."""

    name: str = "base"

    PROTECTED_FIELDS = [
        "_context.workspace_id",
        "_context.workspace_duplicate",
    ]

    def __init__(self, workspace_id: str, config: dict = None):
        self.workspace_id = workspace_id
        self.config = config or {}

    def get_base_query(self) -> dict:
        """Base query - ALWAYS enforced, cannot be overridden."""
        return {
            "_context.workspace_id": self.workspace_id,
            "_context.workspace_duplicate": False,
            "is_false_positive": False
        }

    def _merge_query(self, query: dict) -> dict:
        """Merge user query with base query. Base query always wins."""
        merged = query.copy()

        for field in self.PROTECTED_FIELDS:
            if field in merged:
                del merged[field]

        base = self.get_base_query()
        merged.update(base)

        return merged

    def search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Execute query with enforced base query."""
        safe_query = self._merge_query(query)
        return self._execute_search(safe_query, limit)

    @abstractmethod
    def _execute_search(self, query: dict, limit: int) -> List[Dict[str, Any]]:
        """Backend-specific search implementation."""
        pass

    @abstractmethod
    def count(self, query: dict) -> int:
        """Count matching findings."""
        pass

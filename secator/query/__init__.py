# secator/query/__init__.py

from typing import List, Dict, Any

from secator.query._base import QueryBackend
from secator.query.api import ApiBackend
from secator.query.mongodb import MongoDBBackend
from secator.query.json import JsonBackend


__all__ = ['QueryEngine', 'QueryBackend', 'ApiBackend', 'MongoDBBackend', 'JsonBackend']


class QueryEngine:
    """Query engine with pluggable backends."""

    BACKENDS = {
        'api': ApiBackend,
        'mongodb': MongoDBBackend,
        'json': JsonBackend,
    }

    def __init__(self, workspace_id: str, context: dict = None):
        self.workspace_id = workspace_id
        self.context = context or {}
        self.backend = self._select_backend()

    def _select_backend(self) -> QueryBackend:
        """Select appropriate backend based on context."""
        if self.context.get('api', False):
            return ApiBackend(self.workspace_id)
        elif self.context.get('mongodb', False):
            return MongoDBBackend(self.workspace_id)
        else:
            return JsonBackend(self.workspace_id)

    def search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for findings matching query."""
        return self.backend.search(query, limit)

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        return self.backend.count(query)

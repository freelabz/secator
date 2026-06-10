# secator/query/__init__.py

from typing import List, Dict, Any, Optional

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
        """Select appropriate backend based on context or config default."""
        from secator.config import CONFIG
        drivers = self.context.get('drivers', [])
        if 'mongodb' in drivers:
            return MongoDBBackend(self.workspace_id, context=self.context)
        elif 'api' in drivers:
            return ApiBackend(self.workspace_id, context=self.context)
        else:
            # Fall back to config default backend
            current = CONFIG.backends.current
            if current == 'mongodb':
                return MongoDBBackend(self.workspace_id, context=self.context)
            elif current == 'api':
                return ApiBackend(self.workspace_id, context=self.context)
            else:
                # For JSON backend, use workspace_name for directory (reports are saved by name)
                workspace_name = self.context.get('workspace_name', self.workspace_id)
                results = self.context.get('results')
                return JsonBackend(workspace_name, context=self.context, results=results)

    def search(self, query: dict, limit: int = 0, dedupe: bool = False,
               exclude_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Search for findings matching query."""
        from secator.utils import debug, remove_duplicates
        debug(f'search via {self.backend.name} backend', sub='query', obj=query)
        results = self.backend.search(query, limit, exclude_fields)
        if dedupe:
            results = remove_duplicates(results)
        return results

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        return self.backend.count(query)

    def update(self, query: dict, update: dict) -> int:
        """Update records matching query."""
        return self.backend.update(query, update)

    def list_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces via the active backend."""
        return self.backend.list_workspaces()

    def get_workspace(self, workspace_id: str) -> Dict[str, Any]:
        """Get info for a specific workspace via the active backend."""
        return self.backend.get_workspace(workspace_id)

    def list_runners(
        self, workspace_id: str = None, runner_type: str = None, has_parent: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List runners (tasks/workflows/scans) via the active backend.

        has_parent: filter on the runner's parent relationship. None lists all runners,
        False lists only outermost (root) runners, True lists only nested children.
        """
        return self.backend.list_runners(
            workspace_id=workspace_id, runner_type=runner_type, has_parent=has_parent
        )

    def get_runner(self, runner_id: str, runner_type: str) -> Optional[Dict[str, Any]]:
        """Get a single runner by ID via the active backend.

        runner_id: the backend runner id. runner_type: singular type (task/workflow/scan).
        """
        return self.backend.get_runner(runner_id, runner_type=runner_type)

# secator/query/__init__.py

from typing import List, Dict, Any, Optional

from secator.query._base import QueryBackend
from secator.query.api import ApiBackend
from secator.query.mongodb import MongoDBBackend
from secator.query.json import JsonBackend
from secator.query.sqlite import SqliteBackend


__all__ = ['QueryEngine', 'QueryBackend', 'ApiBackend', 'MongoDBBackend', 'JsonBackend', 'SqliteBackend']


class QueryEngine:
    """Query engine with pluggable backends."""

    # Drivers that have a query backend, keyed by driver name. 'local' is the
    # filesystem (JSON) backend.
    BACKENDS = {
        'api': ApiBackend,
        'mongodb': MongoDBBackend,
        'sqlite': SqliteBackend,
        'local': JsonBackend,
    }

    def __init__(self, workspace_id: str, context: dict = None):
        self.workspace_id = workspace_id
        self.context = context or {}
        self.backend = self._select_backend()

    @classmethod
    def resolve_backend(cls, driver: str = None) -> str:
        """Resolve the effective query backend driver name.

        Uses the passed --driver if it corresponds to an available backend, else the
        first driver in CONFIG.drivers.defaults that does, else 'local'.
        """
        from secator.config import CONFIG
        if driver in cls.BACKENDS:
            return driver
        for d in CONFIG.drivers.defaults:
            if d in cls.BACKENDS:
                return d
        return 'local'

    @classmethod
    def resolve_backend_from_drivers(cls, drivers) -> str:
        """Resolve the backend name from a drivers list, honouring canonical
        driver priority (e.g. mongodb over api), defaulting to 'local'."""
        from secator.loader import order_drivers
        ordered = order_drivers(drivers or [])
        return next((d for d in ordered if d in cls.BACKENDS), 'local')

    def _select_backend(self) -> QueryBackend:
        """Select the backend from the context drivers (highest-priority backend),
        defaulting to the local (JSON) backend."""
        drivers = self.context.get('drivers', [])
        backend_name = self.resolve_backend_from_drivers(drivers)
        if backend_name == 'local':
            # The JSON backend reads from the workspace_name directory (reports are
            # saved by name), not the workspace id.
            workspace_name = self.context.get('workspace_name', self.workspace_id)
            results = self.context.get('results')
            return JsonBackend(workspace_name, context=self.context, results=results)
        return self.BACKENDS[backend_name](self.workspace_id, context=self.context)

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

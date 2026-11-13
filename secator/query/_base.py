# secator/query/_base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from secator.utils import debug


class QueryBackend(ABC):
	"""Abstract base class for query backends."""

	name: str = 'base'

	PROTECTED_FIELDS = [
		'_context.workspace_id',
		'_context.workspace_duplicate',
	]

	def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
		self.workspace_id = workspace_id
		self.config = config or {}
		self.context = context or {}

	def list_workspaces(self) -> List[Dict[str, Any]]:
		"""List all workspaces accessible via this backend."""
		return []

	def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
		"""Get info for a specific workspace."""
		return None

	def list_runners(
		self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
		has_parent: Optional[bool] = None
	) -> List[Dict[str, Any]]:
		"""List runners (tasks/workflows/scans) from this backend.

		has_parent: None lists all runners, False only outermost (root) runners,
		True only nested children.
		"""
		return []

	def get_runner(self, runner_id: str, runner_type: str) -> Optional[Dict[str, Any]]:
		"""Get a single runner by ID from this backend.

		runner_id: the backend runner id. runner_type: singular type (task/workflow/scan).
		"""
		return None

	def get_base_query(self) -> dict:
		"""Base query - ALWAYS enforced, cannot be overridden."""
		return {
			'_context.workspace_id': self.workspace_id,
			# "_context.workspace_duplicate": False,
			# A finding is a false positive only when explicitly marked. Most
			# findings never set the field at all, so an exact `False` match drops
			# them (Mongo `is_false_positive: false` does not match missing fields)
			# — that returned 0 results for fully-populated workspaces. `$ne: True`
			# keeps false/null/absent and excludes only explicit false positives.
			'is_false_positive': {'$ne': True},
		}

	# Display/perf filters in the base query that scope READS but must NOT gate a targeted
	# write: an update by id/uuid has to reach a finding regardless of its display state.
	_DISPLAY_FILTER_FIELDS = ('is_false_positive', '_tagged')

	def _merge_query(self, query: dict, scope_only: bool = False) -> dict:
		"""Merge user query with base query. Base query always wins.

		``scope_only`` keeps ONLY the workspace-scope of the base query (drops the display
		filters) — used for updates so re-writing an already-false-positive/marked finding
		still matches, instead of matching 0 rows and looking like "not found".
		"""
		merged = query.copy()

		for field in self.PROTECTED_FIELDS:
			if field in merged:
				del merged[field]

		base = self.get_base_query()
		if scope_only:
			base = {k: v for k, v in base.items() if k not in self._DISPLAY_FILTER_FIELDS}
		merged.update(base)

		return merged

	def search(self, query: dict, limit: int = 0, exclude_fields: List[str] = None,
	           scope_only: bool = False, offset: int = 0) -> List[Dict[str, Any]]:
		"""Execute query with enforced base query.

		``scope_only`` drops the display filters (is_false_positive/_tagged), keeping only
		the workspace scope — for a targeted read that must reach a finding regardless of
		its display state (mirrors ``update``'s scope_only merge).

		``offset`` skips the first N matching results (pagination); combine with ``limit``
		to page through large result sets. offset=0 preserves the legacy behaviour.
		"""
		if exclude_fields is None:
			exclude_fields = []
		safe_query = self._merge_query(query, scope_only=scope_only)
		debug('context', sub=f'query.{self.name}', obj=self.context)
		debug('search', sub=f'query.{self.name}', obj=safe_query)
		results = self._execute_search(safe_query, limit, exclude_fields, offset=offset)
		debug(f'{len(results)} results', sub=f'query.{self.name}')
		return results

	@abstractmethod
	def _execute_search(self, query: dict, limit: int, exclude_fields: List[str] = None,
	                    offset: int = 0) -> List[Dict[str, Any]]:
		"""Backend-specific search implementation.

		``offset`` skips the first N matching results; backends with no native skip apply a
		Python slice fallback. offset=0 is the legacy no-skip behaviour.
		"""
		pass

	def iterate(self, query: dict, batch_size: int = 1000):
		"""Stream matching findings in batches (never materializes all N). Yields lists of dicts."""
		safe_query = self._merge_query(query)
		yield from self._execute_iterate(safe_query, batch_size)

	def _execute_iterate(self, query: dict, batch_size: int = 1000):
		"""Default: no native cursor — chunk the full result, so this path DOES materialize all N.
		Only the api backend still uses it (a single limit=0 fetch); json/sqlite/mongodb override
		with a true streaming cursor. TODO: paginate the api backend via its skip/limit endpoint."""
		results = self._execute_search(query, limit=0)
		for i in range(0, len(results), batch_size):
			yield results[i:i + batch_size]

	def count(self, query: dict) -> int:
		"""Count matching findings with enforced base query."""
		safe_query = self._merge_query(query)
		return self._execute_count(safe_query)

	@abstractmethod
	def _execute_count(self, query: dict) -> int:
		"""Backend-specific count implementation."""
		pass

	def update(self, query: dict, update: dict) -> int:
		"""Update records matching query, scoped to the workspace only.

		The `is_false_positive` display filter is intentionally NOT applied to writes (see
		`_merge_query(scope_only=True)`): a targeted update must reach the finding even if it's
		already a false positive / already in the target state — otherwise a legitimate re-mark
		matches 0 rows and surfaces a misleading "not found".
		"""
		safe_query = self._merge_query(query, scope_only=True)
		return self._execute_update(safe_query, update)

	@abstractmethod
	def _execute_update(self, query: dict, update: dict) -> int:
		"""Backend-specific update implementation."""
		pass

	def create_note(self, note: dict) -> int:
		"""Persist a NOTE to this backend's notes store. Returns 1 on success, 0 otherwise.

		Notes live in a dedicated store (NEVER the findings collection) keyed by the
		target's ``(target_type, target_key)`` dedup identity — not its mutable ``_uuid`` —
		so a note survives a re-scan that mints a fresh ``_uuid`` for the same finding.
		The workspace scope is enforced HERE from the backend's own ``workspace_id`` (never
		trusted from the note body), mirroring the write gate on ``update``.
		"""
		note = dict(note)
		ctx = note.get('_context')
		if not isinstance(ctx, dict):
			ctx = {}
		ctx['workspace_id'] = self.workspace_id
		note['_context'] = ctx
		return self._execute_create_note(note)

	def _execute_create_note(self, note: dict) -> int:
		"""Backend-specific note insert. Default: no notes store on this backend."""
		debug(f'create_note not supported by {self.name} backend', sub='query')
		return 0

	# Store-wide maintenance (``secator migrate``): no workspace scope, no display filters.

	def bulk_update(self, query: dict, fn, dry_run: bool = False, batch_size: int = 1000):
		"""Apply ``fn(doc)`` as a ``$set`` to every finding in the store matching ``query``.

		False positives and every workspace are included.

		Args:
			query (dict): Store query (MongoDB-style).
			fn (callable): ``fn(doc)`` returns the fields to set, or None to leave the doc as-is.
			dry_run (bool): Count the changes without writing them.
			batch_size (int): Documents per write batch.

		Returns:
			tuple[int, int]: Matched and changed (or to-be-changed) document counts.
		"""
		raise NotImplementedError(f'bulk updates are not supported by the {self.name} backend')

	def get_migrations(self) -> Dict[str, dict]:
		"""Return the migrations applied to this store, keyed by migration id."""
		raise NotImplementedError(f'migrations are not supported by the {self.name} backend')

	def set_migration(self, migration_id: str, info: dict):
		"""Stamp a migration as applied to this store."""
		raise NotImplementedError(f'migrations are not supported by the {self.name} backend')

	def ensure_index(self, keys: List[str]):
		"""Create a findings index on ``keys`` (no-op for stores that manage their own)."""

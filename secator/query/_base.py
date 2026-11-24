# secator/query/_base.py

from abc import ABC, abstractmethod
from datetime import datetime
from functools import lru_cache
from typing import List, Dict, Any, Optional

import click

from secator.utils import debug


# Internal `ai` docs that hold bookkeeping, not results: the sensitive-data placeholder map
# (placeholder -> real value). They are stored like any result (so a resumed run can restore
# them) but must never be read back by a normal query — the AI's query tools feed results to
# the model, and listings/reports would show raw values. Only an explicit
# ``include_internal=True`` read (the restore itself) reaches them.
INTERNAL_AI_TYPES = ('pii_map',)

# Operators whose operand is a field VALUE (so a datetime field's operand is a date).
_VALUE_OPS = ('$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin')


@lru_cache(maxsize=None)
def datetime_fields() -> frozenset:
	"""Top-level field names declared ``datetime`` on any output type (e.g. not_after)."""
	from secator.output_types import OUTPUT_TYPES
	return frozenset(
		name for cls in OUTPUT_TYPES for name, typ in cls.field_types().items() if typ is datetime)


def internal_docs_filter() -> dict:
	"""A query clause excluding internal ai docs. Expressed as `_type != ai OR ai_type not in
	(...)` so it stays null-safe on every backend (sqlite's `!=` is NULL for a missing field,
	which would otherwise drop every non-ai finding)."""
	return {'$or': [{'_type': {'$ne': 'ai'}}, {'ai_type': {'$nin': list(INTERNAL_AI_TYPES)}}]}


def is_internal_doc(doc) -> bool:
	"""True for an internal ai doc (dict or output type) that must never be surfaced."""
	get = doc.get if isinstance(doc, dict) else (lambda k, d=None: getattr(doc, k, d))
	return get('_type') == 'ai' and get('ai_type') in INTERNAL_AI_TYPES


class QueryBackendError(click.ClickException):
	"""A query backend failure that must reach the caller instead of degrading to an empty result.

	Raised for failures that make every result meaningless, e.g. rejected or missing
	credentials: best-effort reads re-raise it rather than return "0 results". A
	``ClickException``, so CLI commands print the message and exit non-zero without a traceback.

	Attributes:
		backend (str): name of the backend that failed (e.g. ``api``).
		status_code (int | None): the backend's status code, when it has one.
	"""

	def __init__(self, message: str, backend: Optional[str] = None, status_code: Optional[int] = None):
		super().__init__(message)
		self.backend = backend
		self.status_code = status_code


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
			# No `_tagged` filter: findings are written untagged and only tagged later by
			# an out-of-band dedup pass, so requiring `_tagged: True` hides every finding of
			# an in-progress run (a workflow's downstream tasks then extract no inputs).
			# Callers that want the deduplicated set pass `_tagged` explicitly.
		}

	# Display/perf filters in the base query that scope READS but must NOT gate a targeted
	# write: an update by id/uuid has to reach a finding regardless of its display state.
	_DISPLAY_FILTER_FIELDS = ('is_false_positive', '_tagged')

	def _merge_query(self, query: dict, scope_only: bool = False, include_internal: bool = False) -> dict:
		"""Merge user query with base query. Base query always wins.

		``scope_only`` keeps ONLY the workspace-scope of the base query (drops the display
		filters) — used for updates so re-writing an already-false-positive/marked finding
		still matches, instead of matching 0 rows and looking like "not found".

		Internal ai docs (see ``INTERNAL_AI_TYPES``) are excluded unless ``include_internal``.
		The exclusion is ANDed in (never overwrites the caller's own ``$or``/``$and``/``ai_type``).
		"""
		merged = query.copy()

		for field in self.PROTECTED_FIELDS:
			if field in merged:
				del merged[field]

		base = self.get_base_query()
		if scope_only:
			base = {k: v for k, v in base.items() if k not in self._DISPLAY_FILTER_FIELDS}
		merged.update(base)

		if not include_internal:
			ands = merged.get('$and')
			merged['$and'] = (list(ands) if isinstance(ands, list) else []) + [internal_docs_filter()]

		return self._normalize_datetime_operands(merged)

	def _datetime_operand(self, dt: datetime, raw: Any) -> Any:
		"""How this backend compares a datetime field: ``dt`` is the operand parsed to aware UTC,
		``raw`` the value the caller passed. Default: a native datetime (mongodb stores a BSON date;
		the json matcher parses the stored ISO string before comparing)."""
		return dt

	def _normalize_datetime_operands(self, query: Any) -> Any:
		"""Rewrite the operands of comparisons on datetime fields (``not_after < '2027-01-01'``)
		into the representation this backend stores, so date filters behave the same everywhere.
		Only strings / datetimes / ``{'$date': ...}`` are converted (a bare int stays an int: '2027'
		is a year, not an epoch); anything unparseable is left as-is."""
		from secator.utils import to_datetime
		if isinstance(query, list):
			return [self._normalize_datetime_operands(q) for q in query]
		if not isinstance(query, dict):
			return query
		dt_fields = datetime_fields()

		def conv(value):
			if not isinstance(value, (str, datetime, dict)):
				return value
			dt = to_datetime(value)
			return value if dt is None else self._datetime_operand(dt, value)

		out = {}
		for key, cond in query.items():
			if key in ('$and', '$or', '$nor'):
				out[key] = self._normalize_datetime_operands(cond)
			elif key not in dt_fields:
				out[key] = cond
			elif isinstance(cond, dict) and any(str(k).startswith('$') for k in cond):
				new = {}
				for op, val in cond.items():
					if op in ('$in', '$nin') and isinstance(val, list):
						new[op] = [conv(v) for v in val]
					elif op in _VALUE_OPS:
						new[op] = conv(val)
					elif op == '$not' and isinstance(val, dict):
						new[op] = self._normalize_datetime_operands({key: val})[key]
					else:
						new[op] = val
				out[key] = new
			else:
				out[key] = conv(cond)
		return out

	def search(self, query: dict, limit: int = 0, exclude_fields: List[str] = None,
	           scope_only: bool = False, offset: int = 0, include_internal: bool = False) -> List[Dict[str, Any]]:
		"""Execute query with enforced base query.

		``scope_only`` drops the display filters (is_false_positive/_tagged), keeping only
		the workspace scope — for a targeted read that must reach a finding regardless of
		its display state (mirrors ``update``'s scope_only merge).

		``offset`` skips the first N matching results (pagination); combine with ``limit``
		to page through large result sets. offset=0 preserves the legacy behaviour.

		``include_internal`` also returns internal ai docs (the placeholder map) — only for the
		run's own restore, never for anything that reaches the model or a listing.
		"""
		if exclude_fields is None:
			exclude_fields = []
		safe_query = self._merge_query(query, scope_only=scope_only, include_internal=include_internal)
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
		# writes target a specific doc (incl. the run's own placeholder map upsert)
		safe_query = self._merge_query(query, scope_only=True, include_internal=True)
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

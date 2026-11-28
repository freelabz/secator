# secator/query/mongodb.py

from typing import List, Dict, Any, Optional

from secator.output_types import Warning
from secator.query._base import QueryBackend, sort_runners_chronologically, validate_runner_order
from secator.rich import console

RUNNER_COLLECTIONS = ('tasks', 'workflows', 'scans')


def _seek_by_native_id(query: dict) -> dict:
	"""Rewrite a plain-string `_uuid` equality into a native `_id` seek.

	The mongodb driver owns finding identity (`_uuid = str(_id)`), so a valid-ObjectId
	`_uuid` is always the primary key — querying `_id` uses the index instead of scanning
	the `_uuid` field. uuid4s (json/sqlite / pre-backfill findings) are NOT valid ObjectIds,
	so they stay a `_uuid` field match — correct before and after the backfill. Only a plain
	string equality is rewritten; an operator dict (`$in`/`$ne`/…) or absent `_uuid` is left
	untouched.
	"""
	u = query.get('_uuid')
	if isinstance(u, str):
		from bson.objectid import ObjectId
		if ObjectId.is_valid(u):
			query = {k: v for k, v in query.items() if k != '_uuid'}
			query['_id'] = ObjectId(u)
	return query


class MongoDBBackend(QueryBackend):
	"""Query backend for MongoDB."""

	name = 'mongodb'

	def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
		super().__init__(workspace_id, config, context=context)
		self._client = None

	def _get_client(self):
		"""Get or create MongoDB client."""
		if self._client is None:
			from secator.hooks.mongodb import get_mongodb_client

			self._client = get_mongodb_client()
		return self._client

	def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None,
	                    offset: int = 0) -> List[Dict[str, Any]]:
		"""Search MongoDB for findings matching query."""
		try:
			client = self._get_client()
			db = client.main

			query = _seek_by_native_id(query)

			# Build projection to exclude fields
			projection = None
			if exclude_fields:
				projection = {field: 0 for field in exclude_fields}

			# Native server-side pagination: .skip(offset) before .limit(limit).
			cursor = db.findings.find(query, projection).skip(offset).limit(limit)

			results = []
			for doc in cursor:
				doc.pop('_id', None)
				results.append(doc)

			return results
		except Exception as e:
			console.print(Warning(message=f'MongoDB search failed: {e}'))
			return []

	def _execute_iterate(self, query: dict, batch_size: int = 1000):
		"""Stream a MongoDB cursor in batches — the driver never buffers all N."""
		try:
			client = self._get_client()
			db = client.main
			batch = []
			for doc in db.findings.find(query).batch_size(batch_size):
				doc.pop('_id', None)
				batch.append(doc)
				if len(batch) >= batch_size:
					yield batch
					batch = []
			if batch:
				yield batch
		except Exception as e:
			console.print(Warning(message=f'MongoDB iterate failed: {e}'))
			raise

	def _execute_count(self, query: dict) -> int:
		"""Count findings matching query."""
		try:
			client = self._get_client()
			db = client.main
			return db.findings.count_documents(query)
		except Exception as e:
			console.print(Warning(message=f'MongoDB count failed: {e}'))
			return 0

	def vuln_counts_by_runner(self, runner_ids_by_type: dict) -> dict:
		"""Aggregate vulnerability severities by runner id in MongoDB."""
		if not self._vulnerability_query(runner_ids_by_type):
			return {}
		counts = {}
		try:
			db = self._get_client().main
			for runner_type, runner_ids in (runner_ids_by_type or {}).items():
				if runner_type not in ('task', 'workflow', 'scan') or not runner_ids:
					continue
				# Mongo-backed runner ids are normally stored as strings in finding context,
				# but older data may retain the equivalent BSON ObjectId. Match both forms.
				from bson.objectid import ObjectId
				query_ids = []
				for runner_id in runner_ids:
					query_ids.append(runner_id)
					if isinstance(runner_id, str) and ObjectId.is_valid(runner_id):
						query_ids.append(ObjectId(runner_id))
					elif isinstance(runner_id, ObjectId):
						query_ids.append(str(runner_id))
				query = self._merge_query({
					'_type': 'vulnerability',
					f'_context.{runner_type}_id': {'$in': query_ids},
				})
				pipeline = [
					{'$match': query},
					{'$group': {
						'_id': {
							'runner_id': f'$_context.{runner_type}_id',
							'severity': '$severity',
						},
						'count': {'$sum': 1},
					}},
				]
				for row in db.findings.aggregate(pipeline):
					group = row.get('_id') or {}
					runner_id = group.get('runner_id')
					severity = str(group.get('severity') or '').strip().lower()
					if runner_id is None or severity not in ('critical', 'high', 'medium', 'low'):
						continue
					by_id = counts.setdefault(runner_type, {})
					severity_counts = by_id.setdefault(str(runner_id), {})
					severity_counts[severity] = severity_counts.get(severity, 0) + row.get('count', 0)
			return counts
		except Exception as e:
			console.print(Warning(message=f'MongoDB vulnerability count aggregation failed: {e}'))
			return counts

	def _execute_update(self, query: dict, update: dict) -> int:
		"""Update every document matching query in MongoDB.

		Returns the number of MATCHED documents, like the other backends: a document already in
		the requested state still counts (``modified_count`` would be 0 for an idempotent update,
		which callers would misreport as "not found").
		"""
		client = self._get_client()
		result = client.main.findings.update_many(_seek_by_native_id(query), update)
		return result.matched_count

	def _execute_create_note(self, note: dict) -> int:
		"""Insert a note into the dedicated ``notes`` collection (NOT findings).

		The shape matches what consumers reading notes expect — ``target_type`` + ``target_key``
		identity, ``body``/``changes``, and ``_context.workspace_id`` scope — so a note the
		AI writes here renders exactly like one posted through the notes endpoint.
		"""
		try:
			client = self._get_client()
			doc = {k: v for k, v in note.items() if k != '_id'}
			client.main.notes.insert_one(doc)
			return 1
		except Exception as e:
			console.print(Warning(message=f'MongoDB create_note failed: {e}'))
			return 0

	def list_workspaces(self):
		"""List workspaces for the mongodb backend.

		There are no workspace objects, so workspaces are derived from the unique
		`context.workspace_name` values across the tasks/workflows/scans collections
		(with runner counts), plus a best-effort finding count per workspace name.
		"""
		try:
			client = self._get_client()
			db = client.main
			runners_count = {}
			for rtype in ['tasks', 'workflows', 'scans']:
				pipeline = [{'$group': {'_id': '$context.workspace_name', 'count': {'$sum': 1}}}]
				for row in db[rtype].aggregate(pipeline):
					name = row.get('_id')
					if not name:
						continue
					runners_count[name] = runners_count.get(name, 0) + row.get('count', 0)

			findings_count = {}
			try:
				pipeline = [{'$group': {'_id': '$_context.workspace_name', 'count': {'$sum': 1}}}]
				for row in db.findings.aggregate(pipeline):
					name = row.get('_id')
					if name:
						findings_count[name] = row.get('count', 0)
			except Exception:
				pass

			return [
				{
					'name': name,
					'_id': '',
					'description': None,
					'runners_count': runners_count[name],
					'findings_count': findings_count.get(name, 0),
				}
				for name in sorted(runners_count)
			]
		except Exception as e:
			console.print(Warning(message=f'MongoDB list_workspaces failed: {e}'))
			return []

	def get_workspace(self, workspace_id: str):
		"""Get workspace info from MongoDB by aggregating findings for workspace_id."""
		try:
			client = self._get_client()
			db = client.main
			pipeline = [
				{'$match': {'_context.workspace_id': workspace_id}},
				{'$group': {
					'_id': '$_context.workspace_id',
					'workspace_name': {'$first': '$_context.workspace_name'},
					'count': {'$sum': 1},
				}},
				{'$project': {
					'_id': 0,
					'workspace_id': '$_id',
					'workspace_name': 1,
					'count': 1,
				}},
			]
			results = list(db.findings.aggregate(pipeline))
			return results[0] if results else None
		except Exception as e:
			console.print(Warning(message=f'MongoDB get_workspace failed: {e}'))
			return None

	def get_runner(self, runner_id: str, runner_type: str):
		"""Get a single runner by ID from MongoDB."""
		try:
			from bson.objectid import ObjectId

			client = self._get_client()
			db = client.main
			# Normalize singular/plural and reject unknown runner types.
			rtype = runner_type.rstrip('s') + 's'
			if rtype not in RUNNER_COLLECTIONS:
				return None
			query = {'_id': ObjectId(runner_id)} if ObjectId.is_valid(runner_id) else {'_id': runner_id}
			doc = db[rtype].find_one(query)
			if doc:
				doc['_id'] = str(doc['_id'])
				doc['_type'] = rtype
				return doc
			return None
		except Exception as e:
			console.print(Warning(message=f'MongoDB get_runner failed: {e}'))
			return None

	def list_runners(self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
					 has_parent: Optional[bool] = None, order: str = 'asc'):
		"""List runners from MongoDB tasks/workflows/scans collections.

		has_parent: when not None, only return runners matching that parent relationship
		(False = outermost runners only, True = nested children only).
		order: 'asc' (default) = oldest first, most recent last; 'desc' = most recent first.
		"""
		validate_runner_order(order)
		try:
			client = self._get_client()
			db = client.main
			if runner_type:
				rtype = runner_type.rstrip('s') + 's'
				runner_types = [rtype] if rtype in RUNNER_COLLECTIONS else []
			else:
				runner_types = list(RUNNER_COLLECTIONS)
			runners = []
			for rtype in runner_types:
				query = {}
				if workspace_id:
					# Scope by workspace. Runner docs carry BOTH context.workspace_id and
					# context.workspace_name; callers pass either a 24-char hex ObjectId
					# (API callers pass the workspace _id) or a workspace name (the CLI's
					# -ws). Match the right field so an id doesn't get compared to names
					# (which returned 0 runners for every id-scoped call). Mirrors the
					# ObjectId-vs-name detection in the api backend.
					from bson.objectid import ObjectId
					if ObjectId.is_valid(workspace_id):
						query['context.workspace_id'] = workspace_id
					else:
						query['context.workspace_name'] = workspace_id
				if has_parent is not None:
					query['has_parent'] = has_parent
				for doc in db[rtype].find(query):
					doc.pop('_id', None)
					doc['_type'] = rtype
					rtype_singular = rtype.rstrip('s')
					runner_id = doc.get('context', {}).get(f'{rtype_singular}_id', '')
					doc['_id_str'] = f'{rtype}/{runner_id}' if runner_id else rtype
					doc['_workspace'] = doc.get('context', {}).get('workspace_name', '')
					runners.append(doc)
			# In the requested order (default oldest first), across the tasks/workflows/scans collections.
			return sort_runners_chronologically(runners, order=order)
		except Exception as e:
			console.print(Warning(message=f'MongoDB list_runners failed: {e}'))
			return []

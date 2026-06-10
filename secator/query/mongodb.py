# secator/query/mongodb.py

from typing import List, Dict, Any, Optional

from secator.output_types import Warning
from secator.query._base import QueryBackend
from secator.rich import console


class MongoDBBackend(QueryBackend):
	"""Query backend for MongoDB."""

	name = 'mongodb'

	def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
		super().__init__(workspace_id, config, context=context)
		self._client = None

	def get_base_query(self) -> dict:
		"""Base query with _tagged for MongoDB."""
		base = super().get_base_query()
		return base

	def _get_client(self):
		"""Get or create MongoDB client."""
		if self._client is None:
			from secator.hooks.mongodb import get_mongodb_client

			self._client = get_mongodb_client()
		return self._client

	def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None) -> List[Dict[str, Any]]:
		"""Search MongoDB for findings matching query."""
		try:
			client = self._get_client()
			db = client.main

			# Build projection to exclude fields
			projection = None
			if exclude_fields:
				projection = {field: 0 for field in exclude_fields}

			cursor = db.findings.find(query, projection).limit(limit)

			results = []
			for doc in cursor:
				doc.pop('_id', None)
				results.append(doc)

			return results
		except Exception as e:
			console.print(Warning(message=f'MongoDB search failed: {e}'))
			return []

	def _execute_count(self, query: dict) -> int:
		"""Count findings matching query."""
		try:
			client = self._get_client()
			db = client.main
			return db.findings.count_documents(query)
		except Exception as e:
			console.print(Warning(message=f'MongoDB count failed: {e}'))
			return 0

	def _execute_update(self, query: dict, update: dict) -> int:
		"""Update documents matching query in MongoDB."""
		client = self._get_client()
		result = client.main.findings.update_one(query, update)
		return result.modified_count

	def list_workspaces(self):
		"""List workspaces by aggregating workspace_id from the findings collection."""
		try:
			client = self._get_client()
			db = client.main
			pipeline = [
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
				{'$sort': {'workspace_id': 1}},
			]
			return list(db.findings.aggregate(pipeline))
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
			rtype = runner_type + 's'
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

	def list_runners(self, workspace_id: str = None, runner_type: str = None, has_parent: Optional[bool] = None):
		"""List runners from MongoDB tasks/workflows/scans collections.

		has_parent: when not None, only return runners matching that parent relationship
		(False = outermost runners only, True = nested children only).
		"""
		try:
			client = self._get_client()
			db = client.main
			runner_types = [runner_type + 's'] if runner_type else ['tasks', 'workflows', 'scans']
			runners = []
			for rtype in runner_types:
				query = {}
				if workspace_id:
					# Runners are keyed by workspace name for the mongodb backend.
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
			return runners
		except Exception as e:
			console.print(Warning(message=f'MongoDB list_runners failed: {e}'))
			return []

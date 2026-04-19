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

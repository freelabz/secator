# secator/query/mongodb.py

from typing import List, Dict, Any, Optional

from secator.query._base import QueryBackend


class MongoDBBackend(QueryBackend):
    """Query backend for MongoDB."""

    name = "mongodb"

    def __init__(self, workspace_id: str, config: Optional[dict] = None):
        super().__init__(workspace_id, config)
        self._client = None

    def get_base_query(self) -> dict:
        """Base query with _tagged for MongoDB."""
        base = super().get_base_query()
        base['_tagged'] = True
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
                doc['_id'] = str(doc['_id'])
                results.append(doc)

            return results
        except Exception:
            return []

    def _execute_count(self, query: dict) -> int:
        """Count findings matching query."""
        try:
            client = self._get_client()
            db = client.main
            return db.findings.count_documents(query)
        except Exception:
            return 0

# secator/query/api.py

import json
from typing import List, Dict, Any, Optional

import requests

from secator.query._base import QueryBackend
from secator.config import CONFIG


class ApiBackend(QueryBackend):
    """Query backend for remote API."""

    name = "api"

    def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
        super().__init__(workspace_id, config, context=context)
        self.api_url = CONFIG.addons.api.url
        self.api_key = CONFIG.addons.api.key
        self.header_name = CONFIG.addons.api.header_name
        self.search_endpoint = CONFIG.addons.api.finding_search_endpoint
        self.force_ssl = CONFIG.addons.api.force_ssl

    def get_base_query(self) -> dict:
        """Base query with _tagged for API."""
        base = super().get_base_query()
        base['_tagged'] = True
        return base

    def _make_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make HTTP request to API."""
        url = f"{self.api_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"{self.header_name} {self.api_key}"

        response = requests.request(
            method=method,
            url=url,
            data=json.dumps(data) if data else None,
            headers=headers,
            verify=self.force_ssl,
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None) -> List[Dict[str, Any]]:
        """Search API for findings matching query."""
        try:
            endpoint = f"{self.search_endpoint}?skip=0&limit={limit}"
            if exclude_fields:
                endpoint += f"&exclude_fields={','.join(exclude_fields)}"
            result = self._make_request('POST', endpoint, query)

            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'items' in result:
                return result['items']
            elif isinstance(result, dict) and 'results' in result:
                return result['results']

            return []
        except Exception:
            return []

    def _execute_count(self, query: dict) -> int:
        """Count findings matching query."""
        try:
            endpoint = f"{self.search_endpoint}?skip=0&limit=0"
            result = self._make_request('POST', endpoint, query)

            if isinstance(result, dict) and 'total' in result:
                return result['total']

            return 0
        except Exception:
            return 0

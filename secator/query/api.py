# secator/query/api.py

import json
from typing import List, Dict, Any, Optional

import requests

from secator.output_types import Warning
from secator.query._base import QueryBackend
from secator.config import CONFIG
from secator.rich import console


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
                items = result
            elif isinstance(result, dict) and 'items' in result:
                items = result['items']
            elif isinstance(result, dict) and 'results' in result:
                items = result['results']
            else:
                items = []

            # Drop the backend-only '_id' field so results match the output-type
            # schema (the CSV exporter rejects unknown fields), matching the
            # MongoDB backend behaviour.
            for item in items:
                if isinstance(item, dict):
                    item.pop('_id', None)
            return items
        except Exception as e:
            console.print(Warning(message=f"API search failed: {e}"))
            return []

    def _execute_count(self, query: dict) -> int:
        """Count findings matching query."""
        try:
            endpoint = f"{self.search_endpoint}?skip=0&limit=0"
            result = self._make_request('POST', endpoint, query)

            if isinstance(result, dict) and 'total' in result:
                return result['total']

            return 0
        except Exception as e:
            console.print(Warning(message=f"API count failed: {e}"))
            return 0

    def _execute_update(self, query: dict, update: dict) -> int:
        """Update records via API PATCH endpoint."""
        payload = {"query": query, "update": update}
        result = self._make_request("PATCH", "findings/update", data=payload)
        return result.get("modified_count", 0)

    def list_workspaces(self):
        """List workspaces from API."""
        try:
            endpoint = CONFIG.addons.api.workspace_list_endpoint
            if CONFIG.addons.api.org_id is not None:
                endpoint += f'?org_id={CONFIG.addons.api.org_id}'
            result = self._make_request('GET', endpoint)
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'items' in result:
                return result['items']
            elif isinstance(result, dict) and 'results' in result:
                return result['results']
            return []
        except Exception as e:
            console.print(Warning(message=f'API list_workspaces failed: {e}'))
            return []

    def get_runner(self, runner_id: str, runner_type: str):
        """Get a single runner by ID from API (GET /runner/{runner_id}?type=<type>)."""
        try:
            endpoint = CONFIG.addons.api.runner_get_endpoint.format(runner_id=runner_id)
            endpoint += f'?type={runner_type}'
            return self._make_request('GET', endpoint)
        except Exception as e:
            console.print(Warning(message=f'API get_runner failed: {e}'))
            return None

    def get_workspace(self, workspace_id: str):
        """Get workspace info from API."""
        try:
            endpoint = CONFIG.addons.api.workspace_get_endpoint.format(workspace_id=workspace_id)
            return self._make_request('GET', endpoint)
        except Exception as e:
            console.print(Warning(message=f'API get_workspace failed: {e}'))
            return None

    @staticmethod
    def _is_object_id(value: str) -> bool:
        """Return True if value looks like a 24-char hex MongoDB ObjectId."""
        return bool(value) and len(value) == 24 and all(c in '0123456789abcdefABCDEF' for c in value)

    def list_runners(self, workspace_id: str = None, runner_type: str = None, has_parent: Optional[bool] = None):
        """List runners from API.

        The CLI passes a workspace name via -ws. The API accepts either workspace_id
        (a 24-char hex ObjectId) or workspace_name. Detect which one was passed so that
        names resolve correctly while raw ObjectIds keep working.

        has_parent: when not None, only return runners matching that parent relationship
        (False = outermost runners only, True = nested children only).
        """
        try:
            endpoint = CONFIG.addons.api.runners_list_endpoint
            params = []
            if workspace_id:
                if self._is_object_id(workspace_id):
                    params.append(f'workspace_id={workspace_id}')
                else:
                    params.append(f'workspace_name={workspace_id}')
            if runner_type:
                params.append(f'type={runner_type}')
            if CONFIG.addons.api.org_id is not None:
                params.append(f'org_id={CONFIG.addons.api.org_id}')
            if has_parent is not None:
                params.append(f'has_parent={str(has_parent).lower()}')
            if params:
                endpoint += '?' + '&'.join(params)
            result = self._make_request('GET', endpoint)
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'items' in result:
                return result['items']
            elif isinstance(result, dict) and 'results' in result:
                return result['results']
            return []
        except Exception as e:
            console.print(Warning(message=f'API list_runners failed: {e}'))
            return []

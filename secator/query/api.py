# secator/query/api.py

import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode

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

    def _execute_search(self, query: dict, limit: int = 100, exclude_fields: list = None,
                        offset: int = 0) -> List[Dict[str, Any]]:
        """Search API for findings matching query (``offset`` maps to the endpoint's skip)."""
        items = self._search_items(query, limit=limit, exclude_fields=exclude_fields, offset=offset)
        # Drop the backend-only '_id' field so results match the output-type
        # schema (the CSV exporter rejects unknown fields), matching the
        # MongoDB backend behaviour.
        for item in items:
            if isinstance(item, dict):
                item.pop('_id', None)
        return items

    def _search_items(self, query: dict, limit: int = 100, exclude_fields: list = None,
                      offset: int = 0) -> List[Dict[str, Any]]:
        """Raw search results, with the API's own ``_id`` kept."""
        try:
            endpoint = f"{self.search_endpoint}?skip={offset}&limit={limit}"
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
        """Apply a ``$set`` to the matching findings through the API's per-finding update endpoint.

        The API has no query-based update route: the matches are resolved with a search (which
        also returns each finding's API id, ``_id``, and current values), then each one is
        written with ``finding_update_endpoint``, as the api driver does. The endpoint takes
        top-level fields only, so a dotted ``field.key`` path is folded into the finding's
        current ``field``.
        """
        set_fields = update.get("$set") or {}
        if not set_fields:
            return 0
        # Snapshot every match first (all pages), so writes that change a finding's eligibility
        # can't shift the pages being read.
        docs, page_size = [], 1000
        while True:
            page = self._search_items(query, limit=page_size, offset=len(docs))
            docs.extend(page)
            if len(page) < page_size:
                break
        modified = 0
        for doc in docs:
            finding_id = doc.get("_id") if isinstance(doc, dict) else None
            if not finding_id:
                continue
            try:
                endpoint = CONFIG.addons.api.finding_update_endpoint.format(finding_id=finding_id)
                result = self._make_request("PUT", endpoint, data=_fold_dotted_fields(doc, set_fields))
            except Exception as e:
                console.print(Warning(message=f"API finding update failed for {finding_id}: {e}"))
                continue
            modified += int(result.get("modified_count", 1 if result.get("success") else 0) or 0)
        return modified

    def _execute_create_note(self, note: dict) -> int:
        """POST the note to the remote notes endpoint.

        Author identity + timestamps are set SERVER-SIDE from the session there, so only
        the target identity + content are sent (``target_type``/``target_key``/``body``/
        ``changes`` + the workspace scope). Mirrors the ``update`` PATCH pattern.
        """
        try:
            payload = {
                "target_type": note.get("target_type"),
                "workspace_id": note.get("_context", {}).get("workspace_id") or self.workspace_id,
                "target_key": note.get("target_key") or {},
                "body": note.get("body") or "",
            }
            if note.get("changes"):
                payload["changes"] = note["changes"]
            self._make_request("POST", "notes", data=payload)
            return 1
        except Exception as e:
            console.print(Warning(message=f"API create_note failed: {e}"))
            return 0

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

    def list_runners(self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
                     has_parent: Optional[bool] = None):
        """List runners from API.

        The CLI passes a workspace name via -ws. The API accepts either workspace_id
        (a 24-char hex ObjectId) or workspace_name. Detect which one was passed so that
        names resolve correctly while raw ObjectIds keep working.

        has_parent: when not None, only return runners matching that parent relationship
        (False = outermost runners only, True = nested children only).
        """
        try:
            endpoint = CONFIG.addons.api.runners_list_endpoint
            # Build params as a dict and url-encode them (workspace names may contain
            # spaces or other characters that must be escaped).
            params = {}
            if workspace_id:
                if self._is_object_id(workspace_id):
                    params['workspace_id'] = workspace_id
                else:
                    params['workspace_name'] = workspace_id
            if runner_type:
                params['type'] = runner_type
            if CONFIG.addons.api.org_id is not None:
                params['org_id'] = CONFIG.addons.api.org_id
            if has_parent is not None:
                params['has_parent'] = str(has_parent).lower()
            if params:
                endpoint += '?' + urlencode(params)
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


def _fold_dotted_fields(doc: dict, set_fields: dict) -> dict:
    """Turn ``{"extra_data.key": v}`` into ``{"extra_data": {..doc's extra_data.., "key": v}}``."""
    fields = {k: v for k, v in set_fields.items() if "." not in k}
    for path, value in set_fields.items():
        if "." not in path:
            continue
        top, rest = path.split(".", 1)
        base = fields.get(top, doc.get(top))
        obj = dict(base) if isinstance(base, dict) else {}
        node = obj
        keys = rest.split(".")
        for key in keys[:-1]:
            node[key] = dict(node[key]) if isinstance(node.get(key), dict) else {}
            node = node[key]
        node[keys[-1]] = value
        fields[top] = obj
    return fields

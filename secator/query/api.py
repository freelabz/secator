# secator/query/api.py

import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode


from secator.output_types import Warning
from secator.query._base import QueryBackend, QueryBackendError, sort_runners_chronologically, validate_runner_order
from secator.config import CONFIG
from secator.requests import get_api_session
from secator.rich import console
from secator.serializers.dataclass import DataclassEncoder


def _auth_error_message(status_code: int, url: str, has_key: bool) -> str:
    if not has_key:
        return (
            f'API request to {url} was rejected ({status_code}): no API key is configured. '
            'Export it as SECATOR_ADDONS_API_KEY, or set addons.api.key with `secator config edit`.'
        )
    return (
        f'API request to {url} was rejected ({status_code}): the configured API key '
        '(addons.api.key) is invalid, expired, or not allowed to access this resource.'
    )


# Same retry policy as the api driver hooks.
_session = get_api_session(retries=CONFIG.addons.api.retries, backoff=CONFIG.addons.api.retry_backoff)


class ApiBackend(QueryBackend):
    """Query backend for remote API."""

    name = "api"

    def _datetime_operand(self, dt, raw):
        # The remote search endpoint interprets the query itself: send the operand unchanged.
        return raw

    def __init__(self, workspace_id: str, config: Optional[dict] = None, context: Optional[dict] = None):
        super().__init__(workspace_id, config, context=context)
        self.api_url = CONFIG.addons.api.url
        self.api_key = CONFIG.addons.api.key
        self.header_name = CONFIG.addons.api.header_name
        self.search_endpoint = CONFIG.addons.api.finding_search_endpoint
        self.force_ssl = CONFIG.addons.api.force_ssl

    def _make_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make HTTP request to API."""
        url = f"{self.api_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"{self.header_name} {self.api_key}"

        response = _session.request(
            method=method,
            url=url,
            # DataclassEncoder (like the api driver hook): datetime values (e.g. a certificate's
            # not_after set by update_finding) serialize as ISO 8601 instead of raising TypeError.
            data=json.dumps(data, cls=DataclassEncoder) if data else None,
            headers=headers,
            verify=self.force_ssl,
            timeout=30
        )
        if response.status_code in (401, 403):
            raise QueryBackendError(
                _auth_error_message(response.status_code, url, bool(self.api_key)),
                backend=self.name, status_code=response.status_code)
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
                      offset: int = 0, raise_errors: bool = False) -> List[Dict[str, Any]]:
        """Raw search results, with the API's own ``_id`` kept.

        A failed request returns ``[]`` with a warning, unless ``raise_errors`` (writes must not
        mistake an auth / server error for "no matching finding")."""
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
        except QueryBackendError:
            raise
        except Exception as e:
            if raise_errors:
                raise
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
        except QueryBackendError:
            raise
        except Exception as e:
            console.print(Warning(message=f"API count failed: {e}"))
            return 0

    def _execute_update(self, query: dict, update: dict) -> int:
        """Apply a ``$set`` to the matching findings through the API's per-finding update endpoint.

        The API has no query-based update route: the matches are resolved with a search (which
        also returns each finding's API id, ``_id``, and current values), then each one is
        written with ``finding_update_endpoint``, as the api driver does.

        Returns the number of findings written (a finding already in the requested state counts).
        Raises when the search fails or when every write fails, so an API error is never reported
        as "no matching finding".
        """
        set_fields = update.get("$set") or {}
        if not set_fields:
            return 0
        docs = self._search_all(query)
        written, errors, auth_error = 0, [], None
        for doc in docs:
            finding_id = doc.get("_id") if isinstance(doc, dict) else None
            if not finding_id:
                continue
            try:
                endpoint = CONFIG.addons.api.finding_update_endpoint.format(finding_id=finding_id)
                self._make_request("PUT", endpoint, data=_fold_dotted_fields(doc, set_fields))
                written += 1
            except QueryBackendError as e:
                # Attempt every remaining write (a per-finding denial must not leave the rest
                # unwritten), then surface the auth failure once the loop is done.
                auth_error = e
            except Exception as e:
                errors.append(e)
                console.print(Warning(message=f"API finding update failed for {finding_id}: {e}"))
        if auth_error is not None:
            raise auth_error
        if errors and not written:
            raise RuntimeError(f"API finding update failed for all {len(errors)} matching finding(s): {errors[-1]}")
        return written

    def _search_all(self, query: dict, page_size: int = 1000) -> List[Dict[str, Any]]:
        """Every finding matching ``query`` (raw, with ``_id``), across all search pages.

        Snapshotting all matches before writing keeps writes that change a finding's eligibility
        from shifting the pages being read. Pages until an empty one (the API may serve fewer
        than ``page_size`` per page), and stops if a page brings no new finding."""
        docs, seen = [], set()
        while True:
            page = self._search_items(query, limit=page_size, offset=len(docs), raise_errors=True)
            new = [d for d in page if isinstance(d, dict) and d.get("_id") not in seen]
            if not new:
                return docs
            seen.update(d.get("_id") for d in new)
            docs.extend(new)

    def list_suggestions(self, limit: int) -> List[Dict[str, Any]]:
        """GET the workspace's suggestions from the suggestions list endpoint, most recent first."""
        try:
            endpoint = CONFIG.addons.api.suggestion_list_endpoint.format(workspace_id=self.workspace_id)
            result = self._make_request("GET", f"{endpoint}?skip=0&limit={limit}")
            items = result.get("items", []) if isinstance(result, dict) else (result or [])
            return sorted(items, key=lambda d: str(d.get("updated_at") or ""), reverse=True)
        except Exception as e:
            console.print(Warning(message=f"API list_suggestions failed: {e}"))
            return []

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
        except QueryBackendError:
            raise
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
        except QueryBackendError:
            raise
        except Exception as e:
            console.print(Warning(message=f'API list_workspaces failed: {e}'))
            return []

    def get_runner(self, runner_id: str, runner_type: str):
        """Get a single runner by ID from API (GET /runner/{runner_id}?type=<type>)."""
        try:
            endpoint = CONFIG.addons.api.runner_get_endpoint.format(runner_id=runner_id)
            endpoint += f'?type={runner_type}'
            return self._make_request('GET', endpoint)
        except QueryBackendError:
            raise
        except Exception as e:
            console.print(Warning(message=f'API get_runner failed: {e}'))
            return None

    def get_workspace(self, workspace_id: str):
        """Get workspace info from API."""
        try:
            endpoint = CONFIG.addons.api.workspace_get_endpoint.format(workspace_id=workspace_id)
            return self._make_request('GET', endpoint)
        except QueryBackendError:
            raise
        except Exception as e:
            console.print(Warning(message=f'API get_workspace failed: {e}'))
            return None

    @staticmethod
    def _is_object_id(value: str) -> bool:
        """Return True if value looks like a 24-char hex MongoDB ObjectId."""
        return bool(value) and len(value) == 24 and all(c in '0123456789abcdefABCDEF' for c in value)

    def list_runners(self, workspace_id: Optional[str] = None, runner_type: Optional[str] = None,
                     has_parent: Optional[bool] = None, order: str = 'asc'):
        """List runners from API.

        The CLI passes a workspace name via -ws. The API accepts either workspace_id
        (a 24-char hex ObjectId) or workspace_name. Detect which one was passed so that
        names resolve correctly while raw ObjectIds keep working.

        has_parent: when not None, only return runners matching that parent relationship
        (False = outermost runners only, True = nested children only).
        order: 'asc' (default) = oldest first, most recent last; 'desc' = most recent first.
        """
        validate_runner_order(order)
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
                runners = result
            elif isinstance(result, dict) and 'items' in result:
                runners = result['items']
            elif isinstance(result, dict) and 'results' in result:
                runners = result['results']
            else:
                runners = []
            # Don't rely on the endpoint's order (it may return newest first): sort
            # client-side in the requested order, like the other backends.
            return sort_runners_chronologically(runners, order=order)
        except QueryBackendError:
            raise
        except Exception as e:
            console.print(Warning(message=f'API list_runners failed: {e}'))
            return []


def _fold_dotted_fields(doc: dict, set_fields: dict) -> dict:
    """Turn ``{"extra_data.key": v}`` into ``{"extra_data": {..doc's extra_data.., "key": v}}``.

    The per-finding endpoint takes top-level fields only, so a dotted path is written by sending
    the whole parent object, rebuilt from ``doc`` (the search result). Known race: a change made
    to that parent object between the search and the write (e.g. another key of ``extra_data``)
    is overwritten. Updates without dotted paths are sent as-is and are not affected.
    """
    if not any("." in k for k in set_fields):
        return dict(set_fields)
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

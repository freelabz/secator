"""API hook for external integrations.

This hook enables Secator to send runner and finding data to external
API endpoints via HTTP requests. It supports both CREATE and UPDATE
operations for runners and findings.

Configuration:
	- addons.api.enabled: Enable/disable the API hook
	- addons.api.url: Base URL of the external API
	- addons.api.api_key: API key for authentication
	- addons.api.force_ssl: Enable/disable SSL certificate verification
"""

import json
import time
import requests

from functools import cache

from secator.config import CONFIG
from secator.output_types import FINDING_TYPES, Error, Info
from secator.runners import Scan, Task, Workflow
from secator.serializers.dataclass import DataclassEncoder
from secator.utils import debug
from secator.rich import console

API_URL = CONFIG.addons.api.url
API_KEY = CONFIG.addons.api.key
API_HEADER_NAME = CONFIG.addons.api.header_name
API_RUNNER_CREATE_ENDPOINT = CONFIG.addons.api.runner_create_endpoint
API_RUNNER_UPDATE_ENDPOINT = CONFIG.addons.api.runner_update_endpoint
API_FINDING_CREATE_ENDPOINT = CONFIG.addons.api.finding_create_endpoint
API_FINDING_UPDATE_ENDPOINT = CONFIG.addons.api.finding_update_endpoint
API_WORKSPACE_GET_ENDPOINT = CONFIG.addons.api.workspace_get_endpoint
API_WORKSPACE_LIST_ENDPOINT = CONFIG.addons.api.workspace_list_endpoint
API_WORKSPACE_CREATE_ENDPOINT = CONFIG.addons.api.workspace_create_endpoint
API_ORG_ID = CONFIG.addons.api.org_id
FORCE_SSL = CONFIG.addons.api.force_ssl
API_TIMEOUT = CONFIG.addons.api.timeout


def get_runner_dbg(runner):
	"""Runner debug object"""
	return {runner.unique_name: runner.status, 'type': runner.config.type, 'class': runner.__class__.__name__, 'caller': runner.config.name, **runner.context}  # noqa: E501


def _make_request(method, endpoint, data=None):
	"""Make HTTP request to external API endpoint."""
	url = f'{API_URL.rstrip("/")}/{endpoint.lstrip("/")}'
	headers = {'Content-Type': 'application/json'}
	if API_KEY:
		headers['Authorization'] = f'{API_HEADER_NAME} {API_KEY}'
	verify = FORCE_SSL
	timeout = API_TIMEOUT
	debug(f'API request: {method} {url}', sub='hooks.api', verbose=True)
	debug('API headers', sub='hooks.api', verbose=True, obj=headers)
	json_data = json.dumps(data, cls=DataclassEncoder) if data else None
	if json_data:
		debug('API data', sub='hooks.api', verbose=True, obj=json_data, obj_after=True)
	response = requests.request(method=method, url=url, data=json_data, headers=headers, verify=verify, timeout=timeout)
	result = response.json()
	debug('API response', sub='hooks.api', verbose=True, obj=result)
	if not response.ok and result.get('detail'):
		console.print(Error(message=f'API error: {result["detail"]}'))
	response.raise_for_status()
	return result


def update_runner(self):
	if 'api' not in self.context.get('drivers', []):
		self.context.setdefault('drivers', []).append('api')
	runner_type = self.config.type
	update = self.toDict()
	chunk = update.get('chunk')
	_id = self.context.get(f'{runner_type}_chunk_id') if chunk else self.context.get(f'{runner_type}_id')
	workspace_id, workspace_name = resolve_workspace(self.context.get('workspace_id'))
	self.context['workspace_id'] = workspace_id
	self.context['workspace_name'] = workspace_name
	update['context']['workspace_id'] = workspace_id
	update['context']['workspace_name'] = workspace_name
	debug('to_update', sub='hooks.api', id=_id, obj=get_runner_dbg(self), obj_after=True, obj_breaklines=False, verbose=True)  # noqa: E501

	start_time = time.time()

	if _id:
		# Update existing runner
		result = _make_request('PUT', f'{API_RUNNER_UPDATE_ENDPOINT.format(runner_id=_id)}', update)
		_log_runner_api_time(self, start_time, '[dim gold4]updated in ', 's[/]', _id)
		self.last_updated_db = start_time
	else:
		# Create new runner
		result = _make_request('POST', API_RUNNER_CREATE_ENDPOINT, update)
		if result and result.get('id'):
			_id = result.get('id')
			if chunk:
				self.context[f'{runner_type}_chunk_id'] = _id
			else:
				self.context[f'{runner_type}_id'] = _id
			_log_runner_api_time(self, start_time, 'in ', 's', _id)


def update_finding(self, item):
	"""Update finding state via API."""
	if 'api' not in self.context.get('drivers', []):
		self.context.setdefault('drivers', []).append('api')
	if type(item) not in FINDING_TYPES:
		return item

	start_time = time.time()
	update = item.toDict()
	in_api = update.get('_context', {}).get('api', False)
	_type = item._type
	_uuid = item._uuid if hasattr(item, '_uuid') else None
	workspace_id, workspace_name = resolve_workspace(self.context.get('workspace_id'))
	self.context['workspace_id'] = workspace_id
	self.context['workspace_name'] = workspace_name
	update['_context']['workspace_name'] = workspace_name
	update['_context']['workspace_id'] = workspace_id
	if not in_api:
		# Create new finding
		update['_context']['api'] = True
		result = _make_request('POST', API_FINDING_CREATE_ENDPOINT, update)
		if result and result.get('id'):
			item._uuid = result.get('id')
			item._context['api'] = True
			status = 'CREATED'
		else:
			status = 'FAILED'
	else:
		# Update existing finding
		result = _make_request('PUT', f'{API_FINDING_UPDATE_ENDPOINT.format(finding_id=_uuid)}', update)
		status = 'UPDATED'

	end_time = time.time()
	elapsed = end_time - start_time

	debug_obj = {_type: status, 'type': 'finding', 'class': self.__class__.__name__, 'caller': self.config.name, **self.context}  # noqa: E501
	debug(f'in {elapsed:.4f}s', sub='hooks.api', id=str(getattr(item, '_uuid', 'unknown')), obj=debug_obj, obj_after=False)

	return item


def _is_object_id(value):
	"""Return True if value looks like a 24-char hex MongoDB ObjectId."""
	return bool(value) and len(value) == 24 and all(c in '0123456789abcdefABCDEF' for c in value)


@cache
def resolve_workspace(value):
	"""Resolve a workspace name-or-id to (workspace_id, workspace_name) via the API.

	Accepts a 24-char hex ObjectId (looked up by id) or a workspace name (looked up
	in the workspace list, scoped to the configured org). Cached per input value.

	The runner's profile / route-based workspace assignment overwrites
	context['workspace_id'] with a workspace name, so callers re-resolve it here to
	make sure the id sent to the API is always the real ObjectId.
	"""
	if value == 'default':
		raise Exception('Workspace `default` cannot be used for API integration: please use a valid workspace using `-ws <workspace>` (CLI) or `context.workspace_id = <workspace>` (Python API).')  # noqa: E501
	if not value:
		raise Exception('No workspace provided: please use a valid workspace using `-ws <workspace>` (CLI) or `context.workspace_id = <workspace>` (Python API).')  # noqa: E501

	# ObjectId -> fetch the workspace to confirm it exists and get its name.
	if _is_object_id(value):
		result = _make_request('GET', f'{API_WORKSPACE_GET_ENDPOINT.format(workspace_id=value)}')
		if result and result.get('name'):
			console.print(Info(message=f'Loaded workspace "{result["name"]}" from remote API [id: {value}]'))
			return value, result['name']
		raise Exception(f'Workspace id "{value}" not found in remote API.')

	# Name -> resolve to id via the workspace list (scoped to the configured org).
	endpoint = API_WORKSPACE_LIST_ENDPOINT
	if API_ORG_ID is not None:
		endpoint += f'?org_id={API_ORG_ID}'
	result = _make_request('GET', endpoint)
	items = result if isinstance(result, list) else (result.get('items') or result.get('results') or [])
	match = next((w for w in items if w.get('name') == value), None)
	if not match:
		raise Exception(f'Workspace "{value}" not found in remote API.')
	workspace_id = str(match.get('_id') or match.get('id'))
	console.print(Info(message=f'Resolved workspace "{value}" from remote API [id: {workspace_id}]'))
	return workspace_id, value


def create_workspace(name, description=None):
	"""Create a workspace via the API (scoped to the configured org), idempotently.

	Returns (created, workspace_id): if a workspace with this name already exists in
	the org it is reused (created=False) instead of erroring, so `secator ws use`
	is safe to re-run. Otherwise it is created (created=True).
	"""
	# Reuse an existing workspace of the same name rather than hitting the API's
	# per-org name-uniqueness check. resolve_workspace raises if not found.
	try:
		existing_id, _ = resolve_workspace(name)
		return False, existing_id
	except Exception as e:
		if 'not found in remote API' not in str(e):
			raise
	data = {'name': name}
	if description:
		data['description'] = description
	result = _make_request('POST', API_WORKSPACE_CREATE_ENDPOINT, data)
	workspace_id = (result or {}).get('_id') or (result or {}).get('id')
	if not workspace_id:
		raise Exception('API workspace creation returned no workspace id.')
	return True, workspace_id


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {'on_init': [update_runner], 'on_start': [update_runner], 'on_interval': [update_runner], 'on_item': [update_finding], 'on_duplicate': [update_finding], 'on_end': [update_runner]},  # noqa: E501
}


def _log_runner_api_time(self, start_time, prefix, suffix, _id):
	"""Log elapsed time for runner API operation."""
	end_time = time.time()
	elapsed = end_time - start_time
	debug(
		f'{prefix}{elapsed:.4f}{suffix}',
		sub='hooks.api',
		id=_id,
		obj=get_runner_dbg(self),
		obj_after=False,
	)

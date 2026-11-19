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
import uuid
import requests

from functools import cache

from secator.config import CONFIG
from secator.output_types import FINDING_TYPES, Info
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
	timeout = _request_timeout()
	debug(f'API request: {method} {url}', sub='hooks.api', verbose=True)
	debug('API headers', sub='hooks.api', verbose=True, obj=headers)
	json_data = json.dumps(data, cls=DataclassEncoder) if data else None
	# never log an internal doc's payload (the placeholder map holds real values)
	from secator.query._base import is_internal_doc
	internal = isinstance(data, dict) and is_internal_doc(data)
	if json_data:
		logged = json.dumps({**data, 'extra_data': '<redacted>'}, cls=DataclassEncoder) if internal else json_data
		debug('API data', sub='hooks.api', verbose=True, obj=logged, obj_after=True)
	try:
		response = _send_with_retries(method, url, json_data, headers, verify, timeout)
	except requests.exceptions.ConnectTimeout:
		raise ApiRequestError(method, endpoint, reason=f'could not connect within {timeout[0]}s', delivered=False)
	except requests.exceptions.Timeout:
		# The request was sent: the endpoint may still complete it after we gave up.
		raise ApiRequestError(method, endpoint, reason=f'no response within {timeout[1]}s')
	except requests.exceptions.ConnectionError as e:
		if _is_read_timeout(e):
			raise ApiRequestError(method, endpoint, reason=f'no response within {timeout[1]}s')
		raise ApiRequestError(method, endpoint, reason=f'connection error: {type(e).__name__}', delivered=_maybe_delivered(e))
	except requests.exceptions.RequestException as e:
		# e.g. a truncated response body: the request reached the endpoint.
		raise ApiRequestError(method, endpoint, reason=f'request error: {type(e).__name__}')
	# 2xx only: Response.ok also accepts 3xx (e.g. an empty 304)
	success = response.ok and not (isinstance(response.status_code, int) and response.status_code >= 300)
	try:
		result = response.json()
	except ValueError:
		# Not JSON: typically an error page from a proxy / load balancer (HTML) or a
		# plain-text server error. Name the request instead of a bare JSONDecodeError.
		if success and not (response.text or '').strip():
			return None
		raise ApiRequestError(method, endpoint, response.status_code, _body_snippet(response.text), json_body=False)
	debug('API response', sub='hooks.api', verbose=True,
	      obj='<redacted>' if internal else result)
	if not success:
		detail = result.get('detail') if isinstance(result, dict) else None
		raise ApiRequestError(method, endpoint, response.status_code, _body_snippet(detail if detail is not None else result))
	return result


class ApiRequestError(Exception):
	"""An api driver request failed: non-2xx or non-JSON response, timeout or connection error.

	``delivered`` is False only when the request provably never reached the endpoint
	(connection refused / connect timeout / name resolution); otherwise the endpoint may
	have processed it (e.g. completed a create after a gateway error or a read timeout).
	"""

	def __init__(self, method, endpoint, status_code=None, snippet='', json_body=True, reason=None, delivered=True):
		self.method = method
		self.endpoint = endpoint
		self.status_code = status_code
		self.snippet = snippet
		self.delivered = delivered
		if reason:
			message = f'API {method} {endpoint} failed ({reason})'
		else:
			kind = '' if json_body else ', non-JSON body'
			message = f'API {method} {endpoint} failed (HTTP {status_code}{kind}): {snippet or "<empty body>"}'
		super().__init__(message)


API_CONNECT_TIMEOUT = 10  # seconds; the read timeout is addons.api.timeout
API_DEFAULT_TIMEOUT = 60  # seconds; used when addons.api.timeout is unset or not positive


def _request_timeout():
	"""(connect, read) timeout tuple. Never unbounded: a non-positive setting falls back to the default."""
	read = API_TIMEOUT if isinstance(API_TIMEOUT, (int, float)) and API_TIMEOUT > 0 else API_DEFAULT_TIMEOUT
	return (min(API_CONNECT_TIMEOUT, read), read)


def _is_read_timeout(exc):
	"""Whether a ConnectionError wraps a read timeout (e.g. the body stalled after the headers)."""
	from urllib3.exceptions import ReadTimeoutError
	reason = exc.args[0] if exc.args else None
	return isinstance(reason, ReadTimeoutError) or isinstance(getattr(reason, 'reason', None), ReadTimeoutError)


def _maybe_delivered(exc):
	"""Whether a ConnectionError may have happened after the request was sent."""
	from urllib3.exceptions import NewConnectionError  # also covers name resolution failures
	reason = getattr(exc.args[0], 'reason', None) if exc.args else None
	return not isinstance(reason, NewConnectionError)


def _body_snippet(body, size=200):
	"""Short single-line snippet of a response body for error messages."""
	if not isinstance(body, str):
		body = json.dumps(body, cls=DataclassEncoder)
	if API_KEY:
		body = body.replace(API_KEY, '<redacted>')
	body = ' '.join(body.split())
	return body if len(body) <= size else body[:size] + '...'


# Retries for a transiently unavailable endpoint (restarting / not-ready backend behind a
# gateway, refused connection). Only idempotent methods are retried: replaying a create
# (POST) whose first attempt reached the backend before the gateway error would create a
# duplicate runner / finding / workspace (see update_runner for how a failed runner
# create is handled). Read timeouts are not retried (the request may still be processing,
# and each wait is already the full read timeout).
API_RETRY_METHODS = ('GET', 'PUT', 'DELETE', 'HEAD')
API_RETRY_STATUSES = (502, 503, 504)
API_RETRY_BACKOFFS = (0.5, 1.0)  # seconds slept before each retry (2 retries, 3 attempts)


def _send_with_retries(method, url, json_data, headers, verify, timeout):
	"""Send the request, retrying idempotent methods on a gateway error or a refused connection."""
	backoffs = API_RETRY_BACKOFFS if method.upper() in API_RETRY_METHODS else ()
	for attempt in range(len(backoffs) + 1):
		last = attempt == len(backoffs)
		try:
			response = requests.request(method=method, url=url, data=json_data, headers=headers, verify=verify, timeout=timeout)  # noqa: E501
		except requests.exceptions.ConnectionError as e:
			if last or _is_read_timeout(e):
				raise
			debug(f'API {method} {url} connection error ({type(e).__name__}), retrying', sub='hooks.api')
		else:
			if last or response.status_code not in API_RETRY_STATUSES:
				return response
			debug(f'API {method} {url} returned HTTP {response.status_code}, retrying', sub='hooks.api')
		time.sleep(backoffs[attempt])


def update_runner(self):
	if 'api' not in self.context.get('drivers', []):
		self.context.setdefault('drivers', []).append('api')
	runner_type = self.config.type
	update = self.toDict()
	chunk = update.get('chunk')
	id_key = f'{runner_type}_chunk_id' if chunk else f'{runner_type}_id'
	_id = self.context.get(id_key)
	if not _id and chunk:
		# A chunk may arrive without its own id: mint a stable local one so a create that
		# may have reached the endpoint is not sent again by a later hook (see below).
		_id = self.context[id_key] = str(uuid.uuid4())
	local_id = _id
	# The runner constructor mints a run-scope uuid {type}_id, but API runner ids are
	# ObjectIds (same rule as the mongodb hook's ensure_mongo_run_id): a non-ObjectId id
	# was never created remotely, so create it (POST) and adopt the returned id. An
	# ObjectId id is an existing runner (e.g. passed in through the context): PUT it.
	if not _is_object_id(_id):
		_id = None
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
		# A previous create for this runner failed in a way the endpoint may still have
		# completed (gateway error, read timeout): it may exist remotely under an id we never
		# received. Creating again would duplicate it, so stop syncing this runner instead.
		unconfirmed = self.context.get('api_unconfirmed_creates') or []
		if local_id and local_id in unconfirmed:
			debug('skipped: earlier create unconfirmed', sub='hooks.api', id=local_id, verbose=True)
			return
		# Create new runner (never replayed automatically, see API_RETRY_METHODS)
		try:
			result = _make_request('POST', API_RUNNER_CREATE_ENDPOINT, update)
			if not (isinstance(result, dict) and result.get('id')):
				raise ApiRequestError('POST', API_RUNNER_CREATE_ENDPOINT, reason='response has no runner id')
		except ApiRequestError as e:
			if e.delivered and local_id:
				self.context['api_unconfirmed_creates'] = [*unconfirmed, local_id]
			raise
		_id = result['id']
		self.context[id_key] = _id
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
	return isinstance(value, str) and len(value) == 24 and all(c in '0123456789abcdefABCDEF' for c in value)


@cache
def resolve_workspace(value):
	"""Resolve a workspace name-or-id to (workspace_id, workspace_name) via the API.

	Accepts a 24-char hex ObjectId (looked up by id) or a workspace name (looked up
	in the workspace list, scoped to the configured org). Cached per input value.

	context['workspace_id'] may be a workspace name (runners default it to the
	workspace name when no id is set), so callers re-resolve it here to make sure
	the id sent to the API is always the real ObjectId.
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
	except ApiRequestError:
		raise
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

"""API driver for external integrations.

This driver enables Secator to send runner and finding data to external
API endpoints via HTTP requests. It supports both CREATE and UPDATE
operations for runners and findings.

Configuration:
	- addons.api.enabled: Enable/disable the API driver
	- addons.api.url: Base URL of the external API
	- addons.api.api_key: API key for authentication
	- addons.api.force_ssl: Enable/disable SSL certificate verification
"""

import json
import time
import requests

from functools import cache

from secator.config import CONFIG
from secator.drivers._base import Driver
from secator.output_types import FINDING_TYPES, Error, Info
from secator.serializers.dataclass import DataclassEncoder
from secator.utils import debug
from secator.rich import console


def _make_request(method, endpoint, data=None, api_url=None, api_key=None, api_header_name=None, force_ssl=True, api_timeout=30):  # noqa: E501
	"""Make HTTP request to external API endpoint."""
	url = f"{api_url.rstrip('/')}/{endpoint.lstrip('/')}"
	headers = {"Content-Type": "application/json"}
	if api_key:
		headers["Authorization"] = f"{api_header_name} {api_key}"
	json_data = json.dumps(data, cls=DataclassEncoder) if data else None
	debug(f'API request: {method} {url}', sub='drivers.api', verbose=True)
	response = requests.request(
		method=method,
		url=url,
		data=json_data,
		headers=headers,
		verify=force_ssl,
		timeout=api_timeout
	)
	result = response.json()
	debug('API response', sub='drivers.api', verbose=True, obj=result)
	if not response.ok and result.get('detail'):
		console.print(Error(message=f'API error: {result["detail"]}'))
	response.raise_for_status()
	return result


def get_runner_dbg(runner):
	"""Runner debug object."""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


class ApiDriver(Driver):
	"""API driver. Sends runner and finding data to an external HTTP API."""

	def __init__(
		self,
		url=None,
		api_key=None,
		header_name=None,
		runner_create_endpoint=None,
		runner_update_endpoint=None,
		finding_create_endpoint=None,
		finding_update_endpoint=None,
		workspace_get_endpoint=None,
		force_ssl=None,
		timeout=None,
	):
		self.url = url or CONFIG.addons.api.url
		self.api_key = api_key or CONFIG.addons.api.key
		self.header_name = header_name or CONFIG.addons.api.header_name
		self.runner_create_endpoint = runner_create_endpoint or CONFIG.addons.api.runner_create_endpoint
		self.runner_update_endpoint = runner_update_endpoint or CONFIG.addons.api.runner_update_endpoint
		self.finding_create_endpoint = finding_create_endpoint or CONFIG.addons.api.finding_create_endpoint
		self.finding_update_endpoint = finding_update_endpoint or CONFIG.addons.api.finding_update_endpoint
		self.workspace_get_endpoint = workspace_get_endpoint or CONFIG.addons.api.workspace_get_endpoint
		self.force_ssl = force_ssl if force_ssl is not None else CONFIG.addons.api.force_ssl
		self.timeout = timeout or CONFIG.addons.api.timeout

	@property
	def hooks(self):
		from secator.runners import Scan, Task, Workflow
		return {
			Scan: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_interval': [self.update_runner],
				'on_item': [self.update_finding],
				'on_duplicate': [self.update_finding],
				'on_end': [self.update_runner],
			},
			Workflow: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_interval': [self.update_runner],
				'on_item': [self.update_finding],
				'on_duplicate': [self.update_finding],
				'on_end': [self.update_runner],
			},
			Task: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_interval': [self.update_runner],
				'on_item': [self.update_finding],
				'on_duplicate': [self.update_finding],
				'on_end': [self.update_runner],
			}
		}

	def check(self) -> bool:
		return bool(self.url)

	def _request(self, method, endpoint, data=None):
		return _make_request(
			method, endpoint, data=data,
			api_url=self.url,
			api_key=self.api_key,
			api_header_name=self.header_name,
			force_ssl=self.force_ssl,
			api_timeout=self.timeout,
		)

	def get_workspace_name(self, workspace_id):
		"""Get workspace name from API."""
		if not self.workspace_get_endpoint:
			return None
		if workspace_id == 'default':
			raise Exception('Workspace `default` cannot be used for API integration: please use a valid workspace ID using `-ws <workspace_id>` (CLI) or `context.workspace_id = <workspace_id>` (Python API).')  # noqa: E501
		if not workspace_id:
			raise Exception('No workspace ID provided: please use a valid workspace ID using `-ws <workspace_id>` (CLI) or `context.workspace_id = <workspace_id>` (Python API).')  # noqa: E501
		result = self._request('GET', f'{self.workspace_get_endpoint.format(workspace_id=workspace_id)}')
		if result and result.get('name'):
			name = result['name']
			console.print(Info(message=f'Loaded workspace "{name}" from remote API [id: {workspace_id}]'))
			return name
		return None

	def update_runner(self, runner):
		if 'api' not in runner.context.get('drivers', []):
			runner.context.setdefault('drivers', []).append('api')
		runner_type = runner.config.type
		update = runner.toDict()
		chunk = update.get('chunk')
		_id = runner.context.get(f'{runner_type}_chunk_id') if chunk else runner.context.get(f'{runner_type}_id')
		workspace_name = self.get_workspace_name(runner.context.get('workspace_id'))
		if workspace_name:
			runner.context['workspace_name'] = workspace_name
		debug(
			'to_update',
			sub='drivers.api',
			id=_id,
			obj=get_runner_dbg(runner),
			obj_after=True,
			obj_breaklines=False,
			verbose=True
		)
		start_time = time.time()
		if _id:
			result = self._request('PUT', f'{self.runner_update_endpoint.format(runner_id=_id)}', update)
			elapsed = time.time() - start_time
			debug(
				f'[dim gold4]updated in {elapsed:.4f}s[/]',
				sub='drivers.api',
				id=_id,
				obj=get_runner_dbg(runner),
				obj_after=False,
			)
			runner.last_updated_db = start_time
		else:
			result = self._request('POST', self.runner_create_endpoint, update)
			if result and result.get('id'):
				_id = result.get('id')
				if chunk:
					runner.context[f'{runner_type}_chunk_id'] = _id
				else:
					runner.context[f'{runner_type}_id'] = _id
				elapsed = time.time() - start_time
				debug(
					f'in {elapsed:.4f}s',
					sub='drivers.api',
					id=_id,
					obj=get_runner_dbg(runner),
					obj_after=False,
				)

	def update_finding(self, runner, item):
		"""Update finding state via API."""
		if 'api' not in runner.context.get('drivers', []):
			runner.context.setdefault('drivers', []).append('api')
		if type(item) not in FINDING_TYPES:
			return item
		start_time = time.time()
		update = item.toDict()
		in_api = update.get('_context', {}).get('api', False)
		_type = item._type
		_uuid = item._uuid if hasattr(item, '_uuid') else None
		workspace_name = self.get_workspace_name(runner.context.get('workspace_id'))
		if workspace_name:
			runner.context['workspace_name'] = workspace_name
			update['_context']['workspace_name'] = workspace_name
			update['_context']['workspace_id'] = runner.context.get('workspace_id')
		if not in_api:
			update['_context']['api'] = True
			result = self._request('POST', self.finding_create_endpoint, update)
			if result and result.get('id'):
				item._uuid = result.get('id')
				item._context['api'] = True
				status = 'CREATED'
			else:
				status = 'FAILED'
		else:
			result = self._request('PUT', f'{self.finding_update_endpoint.format(finding_id=_uuid)}', update)
			status = 'UPDATED'
		elapsed = time.time() - start_time
		debug_obj = {
			_type: status,
			'type': 'finding',
			'class': runner.__class__.__name__,
			'caller': runner.config.name,
			**runner.context
		}
		debug(
			f'in {elapsed:.4f}s',
			sub='drivers.api',
			id=str(getattr(item, '_uuid', 'unknown')),
			obj=debug_obj,
			obj_after=False
		)
		return item

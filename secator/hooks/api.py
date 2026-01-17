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

from secator.config import CONFIG
from secator.output_types import FINDING_TYPES
from secator.runners import Scan, Task, Workflow
from secator.serializers.dataclass import DataclassEncoder
from secator.utils import debug

API_URL = CONFIG.addons.api.url
API_KEY = CONFIG.addons.api.key
API_HEADER_NAME = CONFIG.addons.api.header_name
API_RUNNER_CREATE_ENDPOINT = CONFIG.addons.api.runner_create_endpoint
API_RUNNER_UPDATE_ENDPOINT = CONFIG.addons.api.runner_update_endpoint
API_FINDING_CREATE_ENDPOINT = CONFIG.addons.api.finding_create_endpoint
API_FINDING_UPDATE_ENDPOINT = CONFIG.addons.api.finding_update_endpoint
FORCE_SSL = CONFIG.addons.api.force_ssl


def get_runner_dbg(runner):
	"""Runner debug object"""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


def _make_request(method, endpoint, data=None):
	"""Make HTTP request to external API endpoint."""
	url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
	headers = {
		"Content-Type": "application/json"
	}
	if API_KEY:
		headers["Authorization"] = f"{API_HEADER_NAME} {API_KEY}"
	verify = FORCE_SSL
	debug(f'API request: {method} {url}', sub='hooks.api', verbose=True)
	debug('API headers', sub='hooks.api', verbose=True, obj=headers)
	debug('API verify', sub='hooks.api', verbose=True, obj=verify)
	debug('API timeout', sub='hooks.api', verbose=True, obj=30)
	json_data = json.dumps(data, cls=DataclassEncoder) if data else None
	debug('API data', sub='hooks.api', verbose=True, obj=json_data)

	response = requests.request(
		method=method,
		url=url,
		data=json_data,
		headers=headers,
		verify=verify,
		timeout=30
	)
	response.raise_for_status()
	result = response.json()
	debug('API response', sub='hooks.api', verbose=True, obj=result)
	return result


def update_runner(self):
	runner_type = self.config.type
	update = self.toDict()
	chunk = update.get('chunk')
	_id = self.context.get(f'{runner_type}_chunk_id') if chunk else self.context.get(f'{runner_type}_id')

	debug(
		'to_update',
		sub='hooks.api',
		id=_id,
		obj=get_runner_dbg(self),
		obj_after=True,
		obj_breaklines=False,
		verbose=True
	)

	start_time = time.time()

	if _id:
		# Update existing runner
		result = _make_request('PUT', f'{API_RUNNER_UPDATE_ENDPOINT.format(runner_id=_id)}', update)
		_log_runner_api_time(
			self,
			start_time, '[dim gold4]updated in ', 's[/]', _id
		)
		self.last_updated_db = start_time
	else:
		# Create new runner
		result = _make_request('POST', API_RUNNER_CREATE_ENDPOINT, update)
		if result and result.get('status'):
			_id = result.get('id')
			if chunk:
				self.context[f'{runner_type}_chunk_id'] = _id
			else:
				self.context[f'{runner_type}_id'] = _id
			_log_runner_api_time(self, start_time, 'in ', 's', _id)


def update_finding(self, item):
	"""Update finding state via API."""
	if type(item) not in FINDING_TYPES:
		return item

	start_time = time.time()
	update = item.toDict()
	_type = item._type
	_uuid = item._uuid if hasattr(item, '_uuid') else None

	if _uuid:
		# Update existing finding
		result = _make_request('PUT', f'{API_FINDING_UPDATE_ENDPOINT.format(finding_id=_uuid)}', update)
		status = 'UPDATED'
	else:
		# Create new finding
		result = _make_request('POST', API_FINDING_CREATE_ENDPOINT, update)
		if result and result.get('status'):
			item._uuid = result.get('id')
			status = 'CREATED'
		else:
			status = 'FAILED'

	end_time = time.time()
	elapsed = end_time - start_time

	debug_obj = {
		_type: status,
		'type': 'finding',
		'class': self.__class__.__name__,
		'caller': self.config.name,
		**self.context
	}
	debug(
		f'in {elapsed:.4f}s',
		sub='hooks.api',
		id=str(getattr(item, '_uuid', 'unknown')),
		obj=debug_obj,
		obj_after=False
	)

	return item


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
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner]
	}
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

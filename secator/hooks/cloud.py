"""Secator Cloud driver for sending scan status and findings to Secator Cloud API.

Usage: First authenticate with `secator login`, then use `--driver cloud` with any runner.
"""
import logging
import time
import json
from pathlib import Path

import requests
from retry import retry

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

CLOUD_AUTH_URL = CONFIG.addons.cloud.auth_url
CLOUD_API_URL = CONFIG.addons.cloud.api_url
CLOUD_ORG_ID = CONFIG.addons.cloud.org_id
CLOUD_RETRIES = CONFIG.addons.cloud.retries
CLOUD_DEFAULT_WORKSPACE = CONFIG.addons.cloud.default_workspace
TOKEN_FILE = Path(CONFIG.dirs.data) / 'cloud_token.json'

logger = logging.getLogger(__name__)

_session = None
_workspace_cache = {}


def get_session():
	"""Get or create authenticated session with cloud API."""
	global _session
	if _session is None:
		_session = requests.Session()
		token = load_token()
		if token:
			_session.cookies.set('sAccessToken', token)
	return _session


def load_token():
	"""Load authentication token from file."""
	if TOKEN_FILE.exists():
		try:
			with open(TOKEN_FILE, 'r') as f:
				data = json.load(f)
				return data.get('token')
		except Exception as e:
			debug(f'Failed to load token: {e}', sub='hooks.cloud')
	return None


def save_token(token):
	"""Save authentication token to file."""
	try:
		TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
		with open(TOKEN_FILE, 'w') as f:
			json.dump({'token': token, 'timestamp': time.time()}, f)
	except Exception as e:
		debug(f'Failed to save token: {e}', sub='hooks.cloud')


def get_runner_dbg(runner):
	"""Runner debug object."""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


@retry(tries=CLOUD_RETRIES, delay=1, backoff=2)
def _api_request(method, url, **kwargs):
	"""Make an API request with retry logic."""
	session = get_session()
	response = session.request(method, url, **kwargs)
	response.raise_for_status()
	return response


def check_authentication():
	"""Check if user is authenticated with valid token."""
	token = load_token()
	if not token:
		return False

	# Validate the token by making a test request
	session = get_session()
	try:
		response = session.get(f'{CLOUD_API_URL}/runners', timeout=5)
		return response.status_code == 200
	except Exception:
		return False


def list_workspaces():
	"""List all workspaces from Secator Cloud."""
	try:
		response = _api_request('GET', f'{CLOUD_API_URL}/workspaces', timeout=10)
		return response.json()
	except Exception as e:
		debug(f'Failed to list workspaces: {e}', sub='hooks.cloud')
		return []


def find_workspace_by_name(workspace_name):
	"""Find workspace by name."""
	# Check cache first
	if workspace_name in _workspace_cache:
		return _workspace_cache[workspace_name]

	workspaces = list_workspaces()
	for workspace in workspaces:
		if workspace.get('name') == workspace_name:
			_workspace_cache[workspace_name] = workspace
			return workspace
	return None


def create_workspace(workspace_name, description=''):
	"""Create a new workspace in Secator Cloud."""
	try:
		payload = {
			'name': workspace_name,
			'description': description
		}
		response = _api_request('POST', f'{CLOUD_API_URL}/workspaces', json=payload, timeout=10)
		workspace = response.json()
		# Cache the newly created workspace
		_workspace_cache[workspace_name] = workspace
		return workspace
	except Exception as e:
		debug(f'Failed to create workspace: {e}', sub='hooks.cloud')
		return None


def get_or_create_workspace(workspace_name):
	"""Get workspace by name, or prompt user to create if it doesn't exist."""
	workspace = find_workspace_by_name(workspace_name)

	if workspace:
		return workspace.get('id')

	# Workspace doesn't exist, prompt user to create it
	from secator.rich import console
	console.print(f'[bold yellow]Workspace "{workspace_name}" not found in Secator Cloud.[/]')

	# Ask user if they want to create it
	try:
		import click
		if click.confirm(f'Do you want to create workspace "{workspace_name}"?', default=True):
			description = click.prompt('Enter workspace description (optional)', default='', show_default=False)
			workspace = create_workspace(workspace_name, description)
			if workspace:
				console.print(f'[bold green]✓ Workspace "{workspace_name}" created successfully.[/]')
				return workspace.get('id')
			else:
				console.print(f'[bold red]✗ Failed to create workspace "{workspace_name}".[/]')
				return None
		else:
			console.print('[bold red]Workspace is required when using cloud driver.[/]')
			return None
	except Exception as e:
		debug(f'Failed to prompt for workspace creation: {e}', sub='hooks.cloud')
		return None


def validate_auth(self):
	"""Validate authentication and workspace before running."""
	from secator.output_types import Error

	# Check authentication
	if not check_authentication():
		error = Error(message='Cloud driver requires authentication. Please run: secator login')
		self.add_result(error, hooks=False)
		raise Exception('Not authenticated with Secator Cloud')

	# Get workspace name from context
	workspace_name = self.context.get('workspace_name')

	# If no workspace provided and no default workspace configured, error
	if not workspace_name and not CLOUD_DEFAULT_WORKSPACE:
		error = Error(message='Cloud driver requires --workspace argument or default_workspace in config')
		self.add_result(error, hooks=False)
		raise Exception('Workspace required for Secator Cloud')

	# Use default workspace if none provided
	if not workspace_name:
		workspace_name = CLOUD_DEFAULT_WORKSPACE
		self.context['workspace_name'] = workspace_name

	# Get or create workspace and store ID in context
	workspace_id = get_or_create_workspace(workspace_name)
	if not workspace_id:
		error = Error(message=f'Failed to get or create workspace: {workspace_name}')
		self.add_result(error, hooks=False)
		raise Exception('Failed to initialize workspace')

	# Store workspace_id in context for use in update_runner and update_finding
	self.context['workspace_id'] = workspace_id
	debug(f'Using workspace: {workspace_name} (id: {workspace_id})', sub='hooks.cloud')


def update_runner(self):
	"""Update runner status in Secator Cloud."""
	type_ = self.config.type
	runner_data = self.toDict()

	# Prepare runner payload according to API spec
	runner_payload = {
		'config': runner_data.get('config', {}),
		'targets': runner_data.get('targets', []),
		'context': {
			'config_id': self.context.get('config_id'),
			'org_id': CLOUD_ORG_ID or self.context.get('org_id'),
			'run_id': self.context.get('run_id'),
			'workspace_id': self.context.get('workspace_id'),
			'workspace_name': self.context.get('workspace_name', 'default'),
			'user_id': self.context.get('user_id'),
			'suggestion_id': self.context.get('suggestion_id'),
		},
		'run_opts': runner_data.get('run_opts', {}),
		'timestamp': int(time.time())
	}

	runner_id = self.context.get(f'{type_}_id')

	debug(
		'to_update', sub='hooks.cloud', id=runner_id, obj=get_runner_dbg(self),
		obj_after=True, obj_breaklines=False, verbose=True
	)

	start_time = time.time()
	try:
		if runner_id:
			# Update existing runner
			url = f'{CLOUD_API_URL}/runner/{runner_id}'
			_api_request('PUT', url, json=runner_payload, timeout=10)
			status = 'UPDATED'
		else:
			# Create new runner
			url = f'{CLOUD_API_URL}/runners'
			response = _api_request('POST', url, json=runner_payload, timeout=10)
			runner_id = response.json().get('id')
			self.context[f'{type_}_id'] = runner_id
			status = 'CREATED'

		end_time = time.time()
		elapsed = end_time - start_time
		debug(f'{status} in {elapsed:.4f}s', sub='hooks.cloud', id=runner_id, obj=get_runner_dbg(self), obj_after=False)
		self.last_updated_db = start_time

	except Exception as e:
		debug(f'Failed to update runner: {e}', sub='hooks.cloud', obj=get_runner_dbg(self))


def update_finding(self, item):
	"""Update finding in Secator Cloud."""
	if type(item) not in OUTPUT_TYPES:
		return item

	start_time = time.time()
	finding_data = item.toDict()
	finding_id = item._uuid if hasattr(item, '_uuid') and item._uuid else None

	# Prepare finding payload
	finding_payload = finding_data

	try:
		if finding_id:
			# Update existing finding
			url = f'{CLOUD_API_URL}/finding/{finding_id}'
			_api_request('PUT', url, json=finding_payload, timeout=10)
			status = 'UPDATED'
		else:
			# Create new finding
			url = f'{CLOUD_API_URL}/findings'
			response = _api_request('POST', url, json=finding_payload, timeout=10)
			item._uuid = response.json().get('id')
			status = 'CREATED'

		end_time = time.time()
		elapsed = end_time - start_time
		debug_obj = {
			item._type: status,
			'type': 'finding',
			'class': self.__class__.__name__,
			'caller': self.config.name,
			**self.context
		}
		debug(f'in {elapsed:.4f}s', sub='hooks.cloud', id=str(item._uuid), obj=debug_obj, obj_after=False)

	except Exception as e:
		debug(f'Failed to update finding: {e}', sub='hooks.cloud')

	return item


HOOKS = {
	Scan: {
		'before_init': [validate_auth],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'before_init': [validate_auth],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'before_init': [validate_auth],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner]
	}
}

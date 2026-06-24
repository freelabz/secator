import os
from collections.abc import MutableMapping
from pathlib import Path
from subprocess import call, DEVNULL
from typing import Any, Dict, List, Optional
from typing_extensions import Annotated, Self

import validators
import shutil
import yaml
from dotenv import find_dotenv, load_dotenv
from dotmap import DotMap
from pydantic import AfterValidator, BaseModel, Field, model_validator, ValidationError

from secator.requests import requests
from secator.rich import console, console_stdout

load_dotenv(find_dotenv(usecwd=True), override=False)

Directory = Annotated[Path, AfterValidator(lambda v: v.expanduser())]
StrExpandHome = Annotated[str, AfterValidator(lambda v: v.replace('~', str(Path.home())))]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'
DATA_FOLDER = os.environ.get('SECATOR_DIRS_DATA') or str(Path.home() / '.secator')

USER_AGENTS = {
	'chrome_134.0_win10': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',  # noqa: E501
	'chrome_134.0_macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',  # noqa: E501
}


class StrictModel(BaseModel, extra='forbid'):
	pass


class Directories(StrictModel):
	bin: Directory = Path.home() / '.local' / 'bin'
	share: Directory = Path.home() / '.local' / 'share'
	data: Directory = Path(DATA_FOLDER)
	templates: Directory = ''
	reports: Directory = ''
	wordlists: Directory = ''
	cves: Directory = ''
	payloads: Directory = ''
	performance: Directory = ''
	revshells: Directory = ''
	queries: Directory = ''
	celery: Directory = ''
	celery_data: Directory = ''
	celery_results: Directory = ''

	@model_validator(mode='after')
	def set_default_folders(self) -> Self:
		"""Set folders to be relative to the data folders if they are unspecified in config."""
		for folder in ['templates', 'reports', 'wordlists', 'cves', 'payloads', 'performance', 'revshells', 'queries', 'celery', 'celery_data', 'celery_results']:  # noqa: E501
			rel_target = '/'.join(folder.split('_'))
			val = getattr(self, folder) or self.data / rel_target
			setattr(self, folder, val)
		return self


class Celery(StrictModel):
	broker_url: str = 'filesystem://'
	broker_pool_limit: int = 10
	broker_connection_timeout: float = 4.0
	broker_visibility_timeout: int = 3600
	broker_transport_options: str = ''
	override_default_logging: bool = True
	result_backend: StrExpandHome = ''
	result_backend_transport_options: str = ''
	result_expires: int = 86400  # 1 day
	task_acks_late: bool = False
	task_send_sent_event: bool = False
	task_reject_on_worker_lost: bool = False
	task_max_timeout: int = -1
	task_memory_limit_mb: int = -1
	worker_max_tasks_per_child: int = 20
	worker_prefetch_multiplier: int = 1
	worker_send_task_events: bool = False
	worker_kill_after_task: bool = False
	worker_kill_after_idle_seconds: int = -1
	worker_command_verbose: bool = False


class Cli(StrictModel):
	github_token: str = os.environ.get('GITHUB_TOKEN', '')
	record: bool = False
	stdin_timeout: int = 1000
	show_http_response_headers: bool = False
	show_command_output: bool = False
	exclude_http_response_headers: List[str] = ['connection', 'content_type', 'content_length', 'date', 'server']
	date_format: str = '%m/%d/%Y'  # US, use "%d/%m/%Y" for EUROPEAN format


class Runners(StrictModel):
	input_chunk_size: int = 100
	progress_update_frequency: int = 20
	stat_update_frequency: int = 20
	backend_update_frequency: int = 5
	poll_frequency: int = 5
	skip_cve_search: bool = False
	skip_exploit_search: bool = False
	skip_cve_low_confidence: bool = False
	remove_duplicates: bool = False
	threads: int = 50
	prompt_timeout: int = 20
	chunk_rate_limit: bool = True


class Security(StrictModel):
	allow_local_file_access: bool = True
	auto_install_commands: bool = True
	force_source_install: bool = False
	prompt_sudo_password: bool = True


class HTTP(StrictModel):
	socks5_proxy: str = 'socks5://127.0.0.1:9050'
	http_proxy: str = 'https://127.0.0.1:9080'
	store_responses: bool = True
	response_max_size_bytes: int = 100000  # 100MB
	proxychains_command: str = 'proxychains'
	freeproxy_timeout: int = 1
	default_header: str = 'User-Agent: ' + USER_AGENTS['chrome_134.0_win10']


class Tasks(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt', 'markdown']
	overrides: Dict[str, Dict[str, Any]] = {}


class Workflows(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt', 'markdown']


class Scans(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt', 'markdown']


class Profiles(StrictModel):
	defaults: List[str] = []


class Drivers(StrictModel):
	defaults: List[str] = []


class Workspace(StrictModel):
	current: str = ''
	routes: Dict[str, List[str]] = {}
	profiles: Dict[str, List[str]] = {}


class Payloads(StrictModel):
	templates: Dict[str, str] = {
		'lse': 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh',
		'linpeas': 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
		'sudo_killer': 'https://github.com/TH3xACE/SUDO_KILLER/archive/refs/heads/V3.zip',
	}


class Wordlists(StrictModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains', 'http_params': 'burp-parameter-names'}
	templates: Dict[str, str] = {
		'bo0m_fuzz': 'https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt',
		'combined_subdomains': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt',  # noqa: E501
		'directory_list_small': 'https://gist.githubusercontent.com/sl4v/c087e36164e74233514b/raw/c51a811c70bbdd87f4725521420cc30e7232b36d/directory-list-2.3-small.txt',  # noqa: E501
		'burp-parameter-names': 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt',  # noqa: E501
	}
	lists: Dict[str, List[str]] = {}


class GoogleDriveAddon(StrictModel):
	enabled: bool = False
	drive_parent_folder_id: str = ''
	credentials_path: str = ''


class GoogleCloudStorageAddon(StrictModel):
	enabled: bool = False
	bucket_name: str = ''
	credentials_path: str = ''


class WorkerAddon(StrictModel):
	enabled: bool = False


class MongodbAddon(StrictModel):
	enabled: bool = False
	url: str = 'mongodb://localhost'
	update_frequency: int = 60
	max_pool_size: int = 10
	server_selection_timeout_ms: int = 5000
	max_items: int = -1
	duplicate_main_copy_fields: List[str] = [
		'screenshot_path',
		'stored_response_path',
		'is_false_positive',
		'is_acknowledged',
		'verified',
		'status',
		'tags',
	]


class SqliteAddon(StrictModel):
	enabled: bool = False
	path: str = ''
	busy_timeout_ms: int = 5000
	max_items: int = -1
	duplicate_main_copy_fields: List[str] = [
		'screenshot_path',
		'stored_response_path',
		'is_false_positive',
		'is_acknowledged',
		'verified',
		'status',
		'tags',
	]


class VulnersAddon(StrictModel):
	enabled: bool = False
	api_key: str = ''


class AiAddon(StrictModel):
	enabled: bool = False
	api_key: str = ''
	api_base: str = ''
	default_model: str = 'claude-sonnet-4-6'
	intent_model: str = 'claude-haiku-4-5'
	temperature: float = 0.7
	max_tokens: int = 30000
	max_tokens_total: int = 100000
	max_results: int = 500
	context_window: int = Field(default=128_000, ge=1)
	user_response_timeout: int = 600
	encrypt_pii: bool = True
	permissions: Dict = {
		'allow': [
			'target({targets})',
			'read({workspace}/*,/dev/null,/tmp/*)',
			'write({workspace}/.outputs/*,/dev/null,/tmp/*)',
			'shell(curl,wget,dig,whois,host,grep,cat,ls,head,tail,jq,wc,find,'
			'cd,git,diff,stat,du,df,tree,sort,uniq,cut,tr,echo,realpath,readlink,'
			'file,strings,xxd,base64,for,while,which,true,timeout,'
			'tee,cp,mv,mkdir,touch,chmod,sed,awk,xargs,docker,printf,'
			'redis-cli,nc,ncat,nmap,sqlmap,nikto,gobuster,feroxbuster,ffuf,'
			'socat,telnet,openssl,ssh,scp,rsync,ping,traceroute,tcpdump,ss,netstat)',
			'task(*)',
			'workflow(*)',
		],
		'deny': [
			'target(169.254.169.254)',
			'target(127.0.0.1)',
			'target(localhost)',
			'read(/etc/shadow)',
			'read(~/.ssh/*)',
			'read(~/.aws/*)',
			'write(/etc/*)',
			'write(/usr/*)',
			'shell(rm -rf /*,dd,mkfs,env,printenv)',
		],
		'ask': [
			'target(*)',
			'shell(python,python3,bash,sh,exec,node,ruby,perl,gcc,g++,make,go,php,java,javac)',
			'read(*)',
			'write(*)',
		],
	}


class Providers(StrictModel):
	defaults: Dict[str, str] = {'cve': 'circl', 'exploit': 'exploitdb', 'ghsa': 'ghsa'}


class DiscordAddon(StrictModel):
	enabled: bool = False
	webhook_url: str = ''
	bot_token: str = ''
	send_runner_updates: bool = True
	send_findings: bool = True
	finding_types: List[str] = ['vulnerability']
	min_severity: str = 'high'


class ApiAddon(StrictModel):
	enabled: bool = False
	url: str = 'https://app.secator.cloud/api'
	key: str = ''
	header_name: str = 'Bearer'
	force_ssl: bool = True
	timeout: int = 60
	org_id: Optional[int] = None  # Override org to query (admins only); defaults to the user's own org
	runner_create_endpoint: str = 'runners'
	runner_get_endpoint: str = 'runner/{runner_id}'
	runner_update_endpoint: str = 'runner/{runner_id}'
	finding_create_endpoint: str = 'findings'
	finding_update_endpoint: str = 'finding/{finding_id}'
	finding_search_endpoint: str = 'findings/_search'
	workspace_list_endpoint: str = 'workspaces'
	workspace_create_endpoint: str = 'workspaces'
	workspace_get_endpoint: str = 'workspace/{workspace_id}'
	workspace_delete_endpoint: str = 'workspace/{workspace_id}'
	runners_list_endpoint: str = 'runners/any'
	runner_delete_endpoint: str = 'runner/{runner_id}?type={runner_type}'


class Addons(StrictModel):
	gdrive: GoogleDriveAddon = GoogleDriveAddon()
	gcs: GoogleCloudStorageAddon = GoogleCloudStorageAddon()
	worker: WorkerAddon = WorkerAddon()
	mongodb: MongodbAddon = MongodbAddon()
	sqlite: SqliteAddon = SqliteAddon()
	vulners: VulnersAddon = VulnersAddon()
	discord: DiscordAddon = DiscordAddon()
	api: ApiAddon = ApiAddon()
	ai: AiAddon = AiAddon()


class SecatorConfig(StrictModel):
	debug: str = ''
	dirs: Directories = Directories()
	celery: Celery = Celery()
	cli: Cli = Cli()
	runners: Runners = Runners()
	http: HTTP = HTTP()
	tasks: Tasks = Tasks()
	workflows: Workflows = Workflows()
	scans: Scans = Scans()
	payloads: Payloads = Payloads()
	wordlists: Wordlists = Wordlists()
	profiles: Profiles = Profiles()
	drivers: Drivers = Drivers()
	workspaces: Workspace = Workspace()
	addons: Addons = Addons()
	security: Security = Security()
	providers: Providers = Providers()
	queries: Dict[str, str] = {}
	offline_mode: bool = False


class Config(DotMap):
	"""Config class.

	Examples:
	>>> config = Config.parse()  						   # get default config.
	>>> config = Config.parse({'dirs': {'data': '/tmp/'})  # get custom config (from dict).
	>>> config = Config.parse(path='/path/to/config.yml')  # get custom config (from YAML file).
	>>> config.print() 									   # print config without defaults.
	>>> config.print(partial=False)  					   # print full config.
	>>> config.set('addons.gdrive.enabled', False)         # set value in config.
	>>> config.save()									   # save config back to disk.
	"""

	_error = False

	def get(self, key=None, print=True):
		"""Retrieve a value from the configuration using a dotted path.

		Args:
			key (str | None): Dotted key path.
			print (bool): Print the resulting value.

		Returns:
			Any: value at key.
		"""
		value = self
		if key:
			for part in key.split('.'):
				value = value[part]
		if value is None:
			console.print(f'[bold red]Key {key} does not exist.[/]')
			return None
		if print:
			if key:
				yaml_str = Config.dump(DotMap({key: value}), partial=False)
			else:
				yaml_str = Config.dump(self, partial=False)
			Config.print_yaml(yaml_str)
		return value

	def set(self, key, value, set_partial=True, strategy=None):
		"""Set a value in the configuration using a dotted path.

		Args:
			key (str | None): Dotted key path.
			value (Any): Value.
			set_partial (bool): Set in partial config.
			strategy (str | None): Strategy for updating list/dict fields.
				None or 'replace': replace the value (default).
				'append': append value to existing list, or add key to existing dict.
				'remove': remove value from existing list, or remove key from existing dict.
		"""
		# Convert dotted key path to the corresponding uppercase key used in _keymap
		map_key = key.upper().replace('.', '_')

		# If key not found in keymap, check if parent path points to a dict field
		# (handles setting/removing keys in a dict, e.g. wordlists.defaults.mykey)
		if map_key not in self._keymap:
			parts = key.split('.')
			if len(parts) > 1:
				parent_parts = parts[:-1]
				dict_subkey = parts[-1]
				try:
					parent_value = self
					for part in parent_parts:
						parent_value = parent_value[part]
					if isinstance(parent_value, dict):
						return self._set_dict_key(parent_parts, dict_subkey, value, set_partial=set_partial, strategy=strategy)
				except (KeyError, TypeError):
					pass
			console.print(f'[bold red]Key "{key}" not found in config keymap[/].')
			return

		# Get existing value
		existing_value = self.get(key, print=False)

		# Traverse to the second last key to handle the setting correctly
		target = self
		partial = self._partial
		for part in self._keymap[map_key][:-1]:
			target = target[part]
			partial = partial[part]

		# Set the value on the final part of the path
		final_key = self._keymap[map_key][-1]

		# Apply strategy for list fields
		if strategy in ('append', 'remove') and isinstance(existing_value, list):
			item = value
			current = list(existing_value)
			if strategy == 'append':
				if item not in current:
					current.append(item)
			elif strategy == 'remove':
				if item in current:
					current.remove(item)
				else:
					console.print(f'[bold orange1]Value "{item}" not found in {key}[/].')
					return
			value = current
		else:
			# Try to convert value to expected type
			try:
				if isinstance(existing_value, list):
					if isinstance(value, str):
						if value.startswith('[') and value.endswith(']'):
							value = value[1:-1]
						if ',' in value:
							value = [c.strip() for c in value.split(',')]
						elif value:
							value = [value]
						else:
							value = []
				elif isinstance(existing_value, dict):
					if isinstance(value, str):
						if value.startswith('{') and value.endswith('}'):
							import json

							value = json.loads(value)
				elif isinstance(existing_value, bool):
					if isinstance(value, str):
						value = value.lower() in ('true', '1', 't')
					elif isinstance(value, (int, float)):
						value = True if value == 1 else False
				elif isinstance(existing_value, int):
					value = int(value)
				elif isinstance(existing_value, float):
					value = float(value)
				elif isinstance(existing_value, Path):
					value = Path(value)
			except ValueError:
				pass

		# Validate profile names before setting
		if key in ('profiles.defaults',):
			profile_names = value if isinstance(value, list) else ([value] if value else [])
			if profile_names and not Config._validate_profile_names(profile_names):
				return

		if set_partial:
			if value is None or value == target[final_key]:
				if final_key in partial:
					del partial[final_key]
				return
			else:
				partial[final_key] = value
		target[final_key] = value

	def _set_dict_key(self, parent_parts, subkey, value, set_partial=True, strategy=None):
		"""Set or remove a key within a dict config field.

		Args:
			parent_parts (list[str]): Path components to the dict field (e.g. ['wordlists', 'defaults']).
			subkey (str | None): Key within the dict to set/remove.
			value (Any): Value to set, or item to remove when strategy='remove'.
			set_partial (bool): Set in partial config.
			strategy (str | None): 'remove' to delete the subkey or remove a list item;
				'append' to append to an existing list value; None to replace.
		"""
		# Navigate to the dict
		existing_dict = self
		for part in parent_parts:
			existing_dict = existing_dict[part]

		if not isinstance(existing_dict, dict):
			console.print(f'[bold red]Path "{".".join(parent_parts)}" is not a dict field[/].')
			return

		updated = dict(existing_dict)
		parent_path = '.'.join(parent_parts)

		if strategy == 'remove':
			if subkey and subkey in updated:
				existing_val = updated[subkey]
				if isinstance(existing_val, list) and value is not None:
					# Remove item from list rather than deleting the key
					if value in existing_val:
						updated[subkey] = [v for v in existing_val if v != value]
					else:
						console.print(f'[bold orange1]Value "{value}" not found in {parent_path}.{subkey}[/].')
						return
				else:
					del updated[subkey]
			elif subkey:
				console.print(f'[bold orange1]Key "{subkey}" not found in {parent_path}[/].')
				return
		elif strategy == 'append':
			if subkey:
				existing_val = updated.get(subkey, [])
				parsed = Config._parse_new_value(value)
				items = parsed if isinstance(parsed, list) else [parsed]
				if isinstance(existing_val, list):
					new_list = list(existing_val)
					for item in items:
						if item not in new_list:
							new_list.append(item)
					updated[subkey] = new_list
				else:
					updated[subkey] = Config._parse_new_value(value)
			elif isinstance(value, dict):
				updated.update(value)
		else:
			if subkey:
				new_val = Config._parse_new_value(value)
				# For workspaces.profiles, always coerce single strings to list
				if parent_path == 'workspaces.profiles' and isinstance(new_val, str):
					new_val = [new_val]
				updated[subkey] = new_val
			elif isinstance(value, dict):
				updated.update(value)

		# Validate profile names when setting workspaces.profiles values
		if parent_path == 'workspaces.profiles' and subkey and subkey in updated and strategy != 'remove':
			new_val = updated[subkey]
			if new_val:
				profile_names = new_val if isinstance(new_val, list) else [new_val]
				if not Config._validate_profile_names(profile_names):
					return

		# Traverse to the parent of the dict to set the updated value
		target = self
		partial = self._partial
		for part in parent_parts[:-1]:
			target = target[part]
			partial = partial[part]
		dict_key = parent_parts[-1]

		if set_partial:
			partial[dict_key] = updated
		target[dict_key] = updated

	def unset(self, key, value=None, set_partial=True):
		"""Unset a value in the configuration using a dotted path.

		Args:
			key (str): Dotted key path.
			value (Any | None): If provided and the field is a list, remove this item from the list.
				If the field is a dict, this is ignored (use the key to specify the dict subkey to remove).
			set_partial (bool): Set in partial config.
		"""
		if value is not None:
			# Remove item from list
			self.set(key, value, set_partial=set_partial, strategy='remove')
			return

		# Check if key points to a dict subkey that should be removed
		map_key = key.upper().replace('.', '_')
		if map_key not in self._keymap:
			parts = key.split('.')
			if len(parts) > 1:
				parent_parts = parts[:-1]
				dict_subkey = parts[-1]
				try:
					parent_value = self
					for part in parent_parts:
						parent_value = parent_value[part]
					if isinstance(parent_value, dict):
						self._set_dict_key(parent_parts, dict_subkey, None, set_partial=set_partial, strategy='remove')
						return
				except (KeyError, TypeError):
					pass
			console.print(f'[bold red]Key "{key}" not found in config keymap[/].')
			return

		self.set(key, None, set_partial=set_partial)

	def save(self, target_path: Path = None, partial=True):
		"""Save config as YAML on disk.

		Args:
			target_path (Path | None): If passed, saves the config to this path.
			partial (bool): Save partial config.
		"""
		if not target_path:
			if not self._path:
				return
			target_path = self._path
		with target_path.open('w') as f:
			f.write(Config.dump(self, partial=partial))
		self._path = target_path

	def print(self, partial=True):
		"""Print config.

		Args:
			partial (bool): Print partial config only.
		"""
		yaml_str = self.dump(self, partial=partial)
		yaml_str = f'# {self._path}\n\n{yaml_str}' if self._path and partial else yaml_str
		Config.print_yaml(yaml_str)

	@staticmethod
	def parse(data: dict = {}, path: Path = None, print_errors: bool = True):
		"""Parse config.

		Args:
			data (dict): Config data.
			path (Path | None): Path to YAML config.
			print_errors (bool): Print validation errors to console.

		Returns:
			Config: instance of Config object.
			None: if the config was not loaded properly or there are validation errors.
		"""
		# Load YAML file
		if path:
			data = Config.read_yaml(path)

		# Backwards compatibility: migrate 'workspace' key to 'workspaces'
		migrated = False
		if 'workspace' in data and 'workspaces' not in data:
			data['workspaces'] = data.pop('workspace')
			if path:
				console.print(f'[bold orange1]Migrating config key "workspace" to "workspaces" in {path}[/]')
			migrated = True

		# Backwards compatibility: migrate 'workspaces.default' to 'workspaces.current'
		ws_data = data.get('workspaces')
		if isinstance(ws_data, dict) and 'default' in ws_data and 'current' not in ws_data:
			data['workspaces']['current'] = data['workspaces'].pop('default')
			if path:
				console.print(f'[bold orange1]Migrating config key "workspaces.default" to "workspaces.current" in {path}[/]')
			migrated = True

		if migrated and path:
			try:
				with path.open('w') as f:
					f.write(yaml.dump({k: v for k, v in data.items() if not k.startswith('_')}, sort_keys=False))
			except Exception as e:
				console.print(f'[bold red]Failed to save migrated config: {e}[/]')

		# Load data
		config = Config.load(SecatorConfig, data, print_errors=print_errors)
		valid = config is not None
		if not valid:
			return None

		# Set extras
		config.set_extras(data, path)

		# Override config values with environment variables
		config.apply_env_overrides(print_errors=print_errors)

		# Validate config
		config.validate(print_errors=print_errors)

		return config

	def validate(self, print_errors=True):
		"""Validate config."""
		return Config.load(SecatorConfig, data=self._partial.toDict(), print_errors=print_errors)

	def set_extras(self, original_data, original_path):
		"""Set extra useful values in config.

		Args:
			original_data (data): Original dict data.
			original_path (pathlib.Path): Original YAML path.
			valid (bool): Boolean indicating if config is valid or not.
		"""
		self._path = original_path
		self._partial = Config(original_data)
		self._keymap = Config.build_key_map(self)

		# HACK: set default result_backend if unset
		if not self.celery.result_backend:
			self.celery.result_backend = f'file://{self.dirs.celery_results}'

	@staticmethod
	def load(schema, data: dict = {}, print_errors=True):
		"""Validate a config using Pydantic.

		Args:
			schema (pydantic.Schema): Pydantic schema.
			data (dict): Input data.
			print_errors (bool): Print validation errors.

		Returns:
			Config|None: instance of Config object or None if invalid.
		"""
		try:
			return Config(schema(**data).model_dump())
		except ValidationError as e:
			if print_errors:
				error_str = str(e).replace('\n', '\n  ')
				console.print(f'[bold red]:x: {error_str}')
			return None

	@staticmethod
	def read_yaml(yaml_path):
		"""Read YAML from path.

		Args:
			yaml_path (Path): path to yaml config.

		Returns:
			dict: Loaded data.
		"""
		if not yaml_path.exists():
			console.print(f'[bold red]Config not found: {yaml_path}.[/]')
			return {}
		try:
			with yaml_path.open('r') as f:
				data = yaml.load(f.read(), Loader=yaml.Loader)
				return data or {}
		except yaml.YAMLError as e:
			console.print(f'[bold red]:x: Error loading {yaml_path} {str(e)}')
			return {}

	@staticmethod
	def print_yaml(string):
		"""Print YAML string using rich.

		Args:
			string (str): YAML string.
		"""
		from rich.syntax import Syntax

		data = Syntax(string, 'yaml', theme='ansi-dark', padding=0, background_color='default')
		console_stdout.print(data)

	@staticmethod
	def dump(config, partial=True):
		"""Safe dump config as yaml:
		- `Path`, `PosixPath` and `WindowsPath` objects are translated to strings.
		- Home directory in paths is replaced with the tilde '~'.

		Returns:
			str: YAML dump.
		"""
		import yaml
		from pathlib import Path, PosixPath, WindowsPath

		# Get home dir
		home = str(Path.home())

		# Custom dumper to add line breaks between items and a path representer to translate paths to strings
		class LineBreakDumper(yaml.SafeDumper):
			def write_line_break(self, data=None):
				super().write_line_break(data)
				if len(self.indents) == 1:
					super().write_line_break()

		def posix_path_representer(dumper, data):
			path = str(data)
			if path.startswith(home):
				path = path.replace(home, '~')
			return dumper.represent_scalar('tag:yaml.org,2002:str', path)

		LineBreakDumper.add_representer(str, posix_path_representer)
		LineBreakDumper.add_representer(Path, posix_path_representer)
		LineBreakDumper.add_representer(PosixPath, posix_path_representer)
		LineBreakDumper.add_representer(WindowsPath, posix_path_representer)

		# Get data dict
		data = config.toDict()

		# HACK: Replace home dir in result_backend
		if isinstance(config, Config):
			data['celery']['result_backend'] = data['celery']['result_backend'].replace(home, '~')
			del data['_path']
			if partial:
				data = data['_partial']
			else:
				del data['_partial']

		data = {k: v for k, v in data.items() if not k.startswith('_')}
		return yaml.dump(data, Dumper=LineBreakDumper, sort_keys=False)

	@staticmethod
	def _parse_new_value(value):
		"""Try to parse a string value into a structured type (int, float, bool, list, or dict)."""
		if not isinstance(value, str):
			return value
		if (value.startswith('{') and value.endswith('}')) or (value.startswith('[') and value.endswith(']')):
			try:
				import json

				return json.loads(value)
			except Exception:
				pass
		if ',' in value:
			return [v.strip() for v in value.split(',')]
		try:
			return int(value)
		except ValueError:
			pass
		try:
			return float(value)
		except ValueError:
			pass
		if value.lower() in ('true', 'false'):
			return value.lower() == 'true'
		return value

	@staticmethod
	def _validate_profile_names(profile_names):
		"""Validate that all profile names exist. Returns True if all valid or validation cannot run."""
		try:
			from secator.loader import get_configs_by_type

			available = [p.name for p in get_configs_by_type('profile')]
			invalid = [p for p in profile_names if p not in available]
			if invalid:
				console.print(f'[bold red]Invalid profile names: {", ".join(invalid)}[/]')
				return False
		except Exception as e:
			import logging

			logging.debug('Profile validation skipped due to exception', exc_info=e)
		return True

	@staticmethod
	def build_key_map(config, base_path=[]):
		key_map = {}
		for key, value in config.items():
			if key.startswith('_'):  # ignore
				continue
			current_path = base_path + [key]
			map_key = '_'.join(current_path).upper()
			if isinstance(value, MutableMapping) and not isinstance(value, str):
				key_map[map_key] = current_path  # include dict itself so sub-keys can be set
				key_map.update(Config.build_key_map(value, current_path))
			else:
				key_map[map_key] = current_path
		return key_map

	def apply_env_overrides(self, print_errors=True):
		"""Override config values from environment variables.

		A variable ``SECATOR_<UPPERCASED_DOTTED_KEY>`` overrides the matching config key (dots replaced
		by underscores), e.g. ``SECATOR_CELERY_BROKER_URL``. Dynamic dict keys are also supported, e.g.
		``SECATOR_TASKS_OVERRIDES_NMAP_MAX_TIMEOUT=500`` maps to ``tasks.overrides.nmap.max_timeout``.
		"""
		prefix = 'SECATOR_'
		for var in os.environ:
			if not var.startswith(prefix):
				continue
			key = var[len(prefix):]  # remove prefix
			path = self._resolve_env_key(key)
			if path is None:
				# Unknown / invalid override key: skip it (don't let one bad env var break the config).
				if print_errors:
					console.print(f'[bold orange1]{var} (unknown config key, ignored)[/]')
				continue
			self.set(path, os.environ[var], set_partial=False)
			if not self.validate(print_errors=False) and print_errors:
				console.print(f'[bold red]{var} (override failed)[/]')

	def _resolve_env_key(self, key):
		"""Resolve an env var key (``SECATOR_`` prefix already stripped) to a dotted config path.

		Returns the dotted path for a direct keymap hit, or for a dynamic key nested inside a dict
		field (e.g. ``TASKS_OVERRIDES_NMAP_MAX_TIMEOUT`` -> ``tasks.overrides.nmap.max_timeout``).
		Returns None when the key does not map to a known config field.

		Args:
			key (str): Env var name with the ``SECATOR_`` prefix removed.

		Returns:
			str | None: Dotted config path, or None.
		"""
		# Direct keymap hit (also covers dynamic keys already present in the loaded config)
		if key in self._keymap:
			return '.'.join(k.lower() for k in self._keymap[key])

		# Otherwise, find the longest keymap prefix that resolves to a *dynamic* dict field (one typed
		# as a Dict in the schema, e.g. tasks.overrides / wordlists.defaults), then resolve the
		# remaining dynamic segments under it. Typed sub-models (e.g. addons, celery) are dicts at
		# runtime too, but have a fixed schema (extra='forbid'): an unknown sub-key there is invalid
		# and must be skipped, not written (else it would clobber the typed model with a plain dict).
		best = None
		for map_key, path_parts in self._keymap.items():
			if not key.startswith(map_key + '_'):
				continue
			if not Config._is_dynamic_dict_path(path_parts):
				continue
			if best is None or len(map_key) > len(best[0]):
				best = (map_key, path_parts)
		if best is None:
			return None

		map_key, path_parts = best
		remainder = key[len(map_key) + 1:].lower()  # e.g. 'nmap_max_timeout'
		dotted_prefix = '.'.join(p.lower() for p in path_parts)

		# tasks.overrides maps a task name -> {attr: value}. The task name may itself contain
		# underscores (e.g. search_vulns), so disambiguate it against the known task list.
		if [p.lower() for p in path_parts] == ['tasks', 'overrides']:
			task_name = Config._match_task_name(remainder)
			if not task_name or remainder == task_name:
				return None
			attr = remainder[len(task_name) + 1:]
			return f'{dotted_prefix}.{task_name}.{attr}'

		# Generic single-level dynamic dict (e.g. wordlists.defaults): the remainder is the leaf key.
		return f'{dotted_prefix}.{remainder}'

	@staticmethod
	def _is_dynamic_dict_path(path_parts):
		"""Return True if a config path points to a dynamic ``Dict`` field in the schema.

		Walks the ``SecatorConfig`` field annotations along ``path_parts``. A path resolves to a
		dynamic dict (arbitrary keys allowed, e.g. ``tasks.overrides`` / ``wordlists.defaults``) when
		its annotation is a typing ``Dict``; it resolves to a typed sub-model (fixed schema, e.g.
		``addons``) when its annotation is a ``BaseModel`` subclass. Unknown keys are not dynamic.

		Args:
			path_parts (list[str]): Dotted config path components (e.g. ['tasks', 'overrides']).

		Returns:
			bool: True if the path is a dynamic ``Dict`` field.
		"""
		import typing
		model = SecatorConfig
		annotation = None
		for part in path_parts:
			fields = getattr(model, 'model_fields', None)
			if not fields or part not in fields:
				return False
			annotation = fields[part].annotation
			if isinstance(annotation, type) and issubclass(annotation, BaseModel):
				model = annotation
			else:
				model = None  # leaf or container; no further sub-models to walk
		return typing.get_origin(annotation) is dict

	@staticmethod
	def _match_task_name(remainder):
		"""Return the longest task name that prefixes an underscored remainder, else None.

		Task names are read from the ``secator/tasks`` package directory (filenames match task class
		names by convention), avoiding any task imports at config-load time.

		Args:
			remainder (str): Lowercased underscored remainder, e.g. 'search_vulns_input_chunk_size'.

		Returns:
			str | None: Matching task name, e.g. 'search_vulns'.
		"""
		tasks_dir = Path(__file__).parent / 'tasks'
		if not tasks_dir.is_dir():
			return None
		candidates = [
			f.stem for f in tasks_dir.glob('*.py')
			if not f.stem.startswith('_') and (remainder == f.stem or remainder.startswith(f.stem + '_'))
		]
		return max(candidates, key=len) if candidates else None


def download_files(data: dict, target_folder: Path, offline_mode: bool, type: str):
	"""Download remote files to target folder, clone git repos, or symlink local files.

	Args:
		data (dict): Dict of name to url or local path prefixed with 'git+' for Git repos.
		target_folder (Path): Target folder for storing files or repos.
		type (str): Type of files to handle.
		offline_mode (bool): Offline mode.
	"""
	for name, url_or_path in data.items():
		target_path = download_file(url_or_path, target_folder, offline_mode, type, name=name)
		if target_path:
			data[name] = target_path


def download_file(url_or_path, target_folder: Path, offline_mode: bool, type: str, name: str = None):
	"""Download remote file to target folder, clone git repos, or symlink local files.

	Args:
		data (dict): Dict of name to url or local path prefixed with 'git+' for Git repos.
		target_folder (Path): Target folder for storing files or repos.
		offline_mode (bool): Offline mode.
		type (str): Type of files to handle.
		name (str, Optional): Name of object.

	Returns:
		path (Path): Path to downloaded file / folder.
	"""
	from secator.output_types import Info, Error

	if url_or_path.startswith('git+'):
		# Clone Git repository
		git_url = url_or_path[4:]  # remove 'git+' prefix
		repo_name = git_url.split('/')[-1]
		if repo_name.endswith('.git'):
			repo_name = repo_name[:-4]
		target_path = target_folder / repo_name
		if not target_path.exists():
			console.print(repr(Info(message=f'[bold turquoise4]Cloning git {type} [bold magenta]{repo_name}[/] ...[/] ')), highlight=False, end='')  # noqa: E501
			if offline_mode:
				console.print('[bold orange1]skipped [dim][offline[/].[/]')
				return
			try:
				call(['git', 'clone', git_url, str(target_path)], stderr=DEVNULL, stdout=DEVNULL)
				console.print('[bold green]ok.[/]')
			except Exception as e:
				error = Error.from_exception(e)
				console.print(f'[bold red]failed ({str(e)}).[/]')
				console.print(error)
		return target_path.resolve()
	elif Path(url_or_path).exists():
		# Move local file to target folder
		local_path = Path(url_or_path)
		target_path = target_folder / local_path.name
		if not name:
			name = url_or_path.split('/')[-1]
		try:
			local_path.resolve().relative_to(CONFIG.dirs.data.resolve())
		except ValueError:
			if not CONFIG.security.allow_local_file_access:
				console.print(Error(message=f'File {local_path.resolve()} is not in {CONFIG.dirs.data} and security.allow_local_file_access is disabled.'))  # noqa: E501
				return None
			from secator.output_types import Info

			console.print(repr(Info(message=f'[bold turquoise4]Copying {type} [bold magenta]{name}[/] to {target_folder} ...[/] ')), highlight=False, end='')  # noqa: E501
			shutil.copyfile(local_path, target_folder / name)
			target_path = target_folder / local_path.name
			console.print('[bold green]ok.[/]')
		return target_path.resolve()
	elif validators.url(url_or_path):
		# Download file from URL
		ext = url_or_path.split('.')[-1]
		if not name:
			name = url_or_path.split('/')[-1]
		filename = f'{name}.{ext}' if not name.endswith(ext) else name
		target_path = target_folder / filename
		try:
			if offline_mode:
				return
			if target_path.exists():
				return target_path.resolve()
			console.print(repr(Info(message=f'[bold turquoise4]Downloading {type} [bold magenta]{filename}[/] ...[/] ')), highlight=False, end='')  # noqa: E501
			resp = requests.get(url_or_path, timeout=3)
			resp.raise_for_status()
			with open(target_path, 'wb') as f:
				f.write(resp.content)
			console.print('[bold green]ok.[/]')
		except requests.RequestException as e:
			console.print(f'[bold red]failed ({str(e)}).[/]')
			return
		return target_path.resolve()
	else:
		console.print(Error(message=f'Invalid {type} [bold magenta]{url_or_path}[/]: not a valid git repository, URL or local path.'))  # noqa: E501
		return None


# Load default_config
default_config = Config.parse(print_errors=False)

# Load user config
data_root = default_config.dirs.data
config_path = data_root / 'config.yml'
if not config_path.exists():
	if not data_root.exists():
		console.print(f'[bold turquoise4]Creating directory [bold magenta]{data_root}[/] ... [/]', end='')
		data_root.mkdir(parents=False)
		console.print('[bold green]ok.[/]')
	console.print(f'[bold turquoise4]Creating user conf [bold magenta]{config_path}[/]... [/]', end='')
	config_path.touch()
	console.print('[bold green]ok.[/]')
CONFIG = Config.parse(path=config_path)

# Fallback to default if invalid user config
if not CONFIG:
	console.print(f'[bold orange1]Invalid user config {config_path}. Falling back to default config.')
	CONFIG = default_config

# Create directories if they don't exist already
for name, dir in CONFIG.dirs.items():
	if not dir.exists():
		console.print(f'[bold turquoise4]Creating directory [bold magenta]{dir}[/] ... [/]', end='')
		dir.mkdir(parents=True)
		console.print('[bold green]ok.[/]')

# Download wordlists and payloads
# download_files(CONFIG.wordlists.templates, CONFIG.dirs.wordlists, CONFIG.offline_mode, 'wordlist')
# download_files(CONFIG.payloads.templates, CONFIG.dirs.payloads, CONFIG.offline_mode, 'payload')

# Print config
if 'config' in CONFIG.debug:
	CONFIG.print()

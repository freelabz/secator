import os
from pathlib import Path
from subprocess import call, DEVNULL
from typing import Any, Dict, List, Optional
from typing_extensions import Annotated, Self

import validators
import shutil
import yaml
from dotenv import find_dotenv, load_dotenv
from pydantic import AfterValidator, BaseModel, PrivateAttr, SecretStr, model_validator, ValidationError

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
	def items(self):
		for field_name in type(self).model_fields:
			yield field_name, getattr(self, field_name)

	def values(self):
		for field_name in type(self).model_fields:
			yield getattr(self, field_name)

	def keys(self):
		return type(self).model_fields.keys()


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
	github_token: SecretStr = SecretStr(os.environ.get('GITHUB_TOKEN', ''))
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
	default: str = ''
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
	url: SecretStr = SecretStr('mongodb://localhost')
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
		'tags',
	]


class VulnersAddon(StrictModel):
	enabled: bool = False
	api_key: SecretStr = SecretStr('')


class AiAddon(StrictModel):
	enabled: bool = False
	api_key: SecretStr = SecretStr('')
	api_base: str = ''
	default_model: str = 'claude-sonnet-4-6'
	intent_model: str = 'claude-haiku-4-5'
	temperature: float = 0.7
	max_tokens: int = 30000
	max_tokens_total: int = 100000
	max_results: int = 500
	user_response_timeout: int = 600
	encrypt_pii: bool = True
	permissions: Dict = {
		"allow": [
			"target({targets})",
			"read({workspace}/*,/dev/null,/tmp/*)",
			"write({workspace}/.outputs/*,/dev/null,/tmp/*)",
			"shell(curl,wget,dig,whois,host,grep,cat,ls,head,tail,jq,wc,find,"
			"cd,git,diff,stat,du,df,tree,sort,uniq,cut,tr,echo,realpath,readlink,"
			"file,strings,xxd,base64,for,while,which,true,timeout,"
			"tee,cp,mv,mkdir,touch,chmod,sed,awk,xargs,docker,printf,"
			"redis-cli,nc,ncat,nmap,sqlmap,nikto,gobuster,feroxbuster,ffuf,"
			"socat,telnet,openssl,ssh,scp,rsync,ping,traceroute,tcpdump,ss,netstat)",
			"task(*)",
			"workflow(*)",
		],
		"deny": [
			"target(169.254.169.254)",
			"target(127.0.0.1)",
			"target(localhost)",
			"read(/etc/shadow)",
			"read(~/.ssh/*)",
			"read(~/.aws/*)",
			"write(/etc/*)",
			"write(/usr/*)",
			"shell(rm -rf /*,dd,mkfs,env,printenv)",
		],
		"ask": [
			"target(*)",
			"shell(python,python3,bash,sh,exec,node,ruby,perl,gcc,g++,make,go,php,java,javac)",
			"read(*)",
			"write(*)",
		],
	}


class Providers(StrictModel):
	defaults: Dict[str, str] = {'cve': 'circl', 'exploit': 'exploitdb', 'ghsa': 'ghsa'}


class DiscordAddon(StrictModel):
	enabled: bool = False
	webhook_url: SecretStr = SecretStr('')
	bot_token: SecretStr = SecretStr('')
	send_runner_updates: bool = True
	send_findings: bool = True
	finding_types: List[str] = ['vulnerability']
	min_severity: str = 'high'


class ApiAddon(StrictModel):
	enabled: bool = False
	url: str = 'https://app.secator.cloud/api'
	key: SecretStr = SecretStr('')
	header_name: str = 'Bearer'
	force_ssl: bool = True
	timeout: int = 60
	runner_create_endpoint: str = 'runners'
	runner_update_endpoint: str = 'runner/{runner_id}'
	finding_create_endpoint: str = 'findings'
	finding_update_endpoint: str = 'finding/{finding_id}'
	finding_search_endpoint: str = 'findings/_search'
	workspace_get_endpoint: str = 'workspace/{workspace_id}'
	workspace_delete_endpoint: str = 'workspace/{workspace_id}'
	runner_delete_endpoint: str = '{runner_type}/{runner_id}'


class Addons(StrictModel):
	gdrive: GoogleDriveAddon = GoogleDriveAddon()
	gcs: GoogleCloudStorageAddon = GoogleCloudStorageAddon()
	worker: WorkerAddon = WorkerAddon()
	mongodb: MongodbAddon = MongodbAddon()
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
	workspace: Workspace = Workspace()
	addons: Addons = Addons()
	security: Security = Security()
	providers: Providers = Providers()
	queries: Dict[str, str] = {}
	offline_mode: bool = False


def _get_secret_paths(model_class, prefix=''):
	"""Get all dotted paths to SecretStr fields in a Pydantic model."""
	paths = []
	if not hasattr(model_class, 'model_fields'):
		return paths
	for field_name, field_info in model_class.model_fields.items():
		annotation = field_info.annotation
		if annotation is None:
			continue
		field_path = f'{prefix}.{field_name}' if prefix else field_name
		if annotation is SecretStr:
			paths.append(field_path)
		elif hasattr(annotation, 'model_fields'):
			paths.extend(_get_secret_paths(annotation, field_path))
	return paths


SECRET_PATHS = _get_secret_paths(SecatorConfig)


def _mask_secret_data(data, current_path=''):
	"""Recursively mask SecretStr values and secret path strings in a dict."""
	if isinstance(data, SecretStr):
		return '***' if data else ''
	if isinstance(data, dict):
		return {
			k: _mask_secret_data(v, f'{current_path}.{k}' if current_path else k)
			for k, v in data.items()
		}
	if current_path in SECRET_PATHS and isinstance(data, str) and data:
		return '***'
	return data


class Config(SecatorConfig):
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

	_path: Optional[Path] = PrivateAttr(default=None)
	_partial: dict = PrivateAttr(default_factory=dict)
	_keymap: dict = PrivateAttr(default_factory=dict)
	_error: bool = PrivateAttr(default=False)

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
				if isinstance(value, BaseModel):
					value = getattr(value, part)
				elif isinstance(value, dict):
					value = value[part]
				else:
					value = None
					break
		if value is None:
			console.print(f'[bold red]Key {key} does not exist.[/]')
			return None
		if print:
			if key:
				yaml_str = Config.dump({key: value}, partial=False, mask_secrets=True)
			else:
				yaml_str = Config.dump(self, partial=False, mask_secrets=True)
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
		map_key = key.upper().replace('.', '_')

		if map_key not in self._keymap:
			parts = key.split('.')
			if len(parts) > 1:
				current = self
				model_parts = []
				for i, part in enumerate(parts):
					if isinstance(current, BaseModel):
						try:
							current = getattr(current, part)
							model_parts.append(part)
						except AttributeError:
							break
					elif isinstance(current, dict):
						dict_remaining = parts[i:]
						subkey = dict_remaining[0]
						inner_parts = dict_remaining[1:]
						if not inner_parts:
							return self._set_dict_key(model_parts, subkey, value, set_partial=set_partial, strategy=strategy)
						parsed_value = Config._parse_new_value(value) if isinstance(value, str) else value
						nested_val = parsed_value
						for k in reversed(inner_parts):
							nested_val = {k: nested_val}
						existing_subval = current.get(subkey, {})
						if isinstance(existing_subval, dict) and isinstance(nested_val, dict):
							merged = {**existing_subval, **nested_val}
						else:
							merged = nested_val
						return self._set_dict_key(model_parts, subkey, merged, set_partial=set_partial, strategy=strategy)
			console.print(f'[bold red]Key "{key}" not found in config keymap[/].')
			return

		existing_value = self.get(key, print=False)

		target = self
		partial = self._partial
		for part in self._keymap[map_key][:-1]:
			if isinstance(target, BaseModel):
				target = getattr(target, part)
			else:
				target = target[part]
			partial = partial.setdefault(part, {})

		final_key = self._keymap[map_key][-1]

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
				elif isinstance(existing_value, SecretStr):
					if not isinstance(value, SecretStr):
						value = SecretStr(value) if value is not None else SecretStr('')
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
			current_val = getattr(target, final_key) if isinstance(target, BaseModel) else target.get(final_key)
			if value is None or value == current_val:
				if final_key in partial:
					del partial[final_key]
				return
			else:
				partial_value = value.get_secret_value() if isinstance(value, SecretStr) else value
				partial[final_key] = partial_value

		if isinstance(target, BaseModel):
			setattr(target, final_key, value)
		else:
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
		existing_dict = self
		for part in parent_parts:
			if isinstance(existing_dict, BaseModel):
				existing_dict = getattr(existing_dict, part)
			else:
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
				# For workspace.profiles, always coerce single strings to list
				if parent_path == 'workspace.profiles' and isinstance(new_val, str):
					new_val = [new_val]
				updated[subkey] = new_val
			elif isinstance(value, dict):
				updated.update(value)

		if parent_path == 'workspace.profiles' and subkey and subkey in updated and strategy != 'remove':
			new_val = updated[subkey]
			if new_val:
				profile_names = new_val if isinstance(new_val, list) else [new_val]
				if not Config._validate_profile_names(profile_names):
					return

		target = self
		partial = self._partial
		for part in parent_parts[:-1]:
			if isinstance(target, BaseModel):
				target = getattr(target, part)
			else:
				target = target[part]
			partial = partial.setdefault(part, {})
		dict_key = parent_parts[-1]

		if set_partial:
			partial[dict_key] = updated
		if isinstance(target, BaseModel):
			setattr(target, dict_key, updated)
		else:
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
			self.set(key, value, set_partial=set_partial, strategy='remove')
			return

		map_key = key.upper().replace('.', '_')
		if map_key not in self._keymap:
			parts = key.split('.')
			if len(parts) > 1:
				parent_parts = parts[:-1]
				dict_subkey = parts[-1]
				try:
					parent_value = self
					for part in parent_parts:
						if isinstance(parent_value, BaseModel):
							parent_value = getattr(parent_value, part)
						else:
							parent_value = parent_value[part]
					if isinstance(parent_value, dict):
						self._set_dict_key(parent_parts, dict_subkey, None, set_partial=set_partial, strategy='remove')
						return
				except (AttributeError, KeyError, TypeError):
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
		yaml_str = self.dump(self, partial=partial, mask_secrets=True)
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
		if path:
			data = Config.read_yaml(path)

		config = Config.load(data, print_errors=print_errors)
		if config is None:
			return None

		config.set_extras(data, path)
		config.apply_env_overrides(print_errors=print_errors)
		config.validate(print_errors=print_errors)

		return config

	def validate(self, print_errors=True):
		"""Validate config."""
		return Config.load(data=self._partial, print_errors=print_errors)

	def set_extras(self, original_data, original_path):
		"""Set extra useful values in config.

		Args:
			original_data (data): Original dict data.
			original_path (pathlib.Path): Original YAML path.
		"""
		self._path = original_path
		self._partial = dict(original_data) if original_data else {}
		self._keymap = Config.build_key_map(self)

		# HACK: set default result_backend if unset
		if not self.celery.result_backend:
			self.celery.result_backend = f'file://{self.dirs.celery_results}'

	@staticmethod
	def _to_plain_dict(obj):
		"""Recursively convert Pydantic models to plain dicts, preserving SecretStr objects."""
		if isinstance(obj, BaseModel):
			return {k: Config._to_plain_dict(getattr(obj, k)) for k in type(obj).model_fields}
		elif isinstance(obj, dict):
			return {k: Config._to_plain_dict(v) for k, v in obj.items()}
		return obj

	@staticmethod
	def load(data: dict = {}, print_errors=True):
		"""Validate a config using Pydantic.

		Args:
			data (dict): Input data.
			print_errors (bool): Print validation errors.

		Returns:
			Config|None: instance of Config object or None if invalid.
		"""
		try:
			return Config(**data)
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
	def dump(config, partial=True, mask_secrets=False):
		"""Safe dump config as yaml:
		- `Path`, `PosixPath` and `WindowsPath` objects are translated to strings.
		- Home directory in paths is replaced with the tilde '~'.
		- `SecretStr` values are serialized as their actual string values (use mask_secrets=True for display).

		Args:
			mask_secrets (bool): When True, replace non-empty secret values with '***'.

		Returns:
			str: YAML dump.
		"""
		import yaml
		from pathlib import Path, PosixPath, WindowsPath

		home = str(Path.home())

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

		def secret_str_representer(dumper, data):
			return posix_path_representer(dumper, data.get_secret_value())

		LineBreakDumper.add_representer(str, posix_path_representer)
		LineBreakDumper.add_representer(Path, posix_path_representer)
		LineBreakDumper.add_representer(PosixPath, posix_path_representer)
		LineBreakDumper.add_representer(WindowsPath, posix_path_representer)
		LineBreakDumper.add_representer(SecretStr, secret_str_representer)

		if isinstance(config, Config):
			if partial:
				data = dict(config._partial)
			else:
				data = Config._to_plain_dict(config)
				rb = data.get('celery', {}).get('result_backend', '')
				if rb:
					data['celery']['result_backend'] = rb.replace(home, '~')
		elif isinstance(config, BaseModel):
			data = Config._to_plain_dict(config)
		else:
			data = Config._to_plain_dict(config) if isinstance(config, dict) else {}

		data = {k: v for k, v in data.items() if not k.startswith('_')}

		if mask_secrets:
			data = _mask_secret_data(data)

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
	def build_key_map(obj, base_path=[]):
		key_map = {}
		if isinstance(obj, BaseModel):
			for key in type(obj).model_fields:
				value = getattr(obj, key)
				current_path = base_path + [key]
				if isinstance(value, BaseModel):
					key_map.update(Config.build_key_map(value, current_path))
				else:
					key_map['_'.join(current_path).upper()] = current_path
		elif isinstance(obj, dict):
			for key, value in obj.items():
				if key.startswith('_'):
					continue
				current_path = base_path + [key]
				if isinstance(value, BaseModel):
					key_map.update(Config.build_key_map(value, current_path))
				else:
					key_map['_'.join(current_path).upper()] = current_path
		return key_map

	def apply_env_overrides(self, print_errors=True):
		"""Override config values from environment variables."""
		prefix = 'SECATOR_'
		for var in os.environ:
			if var.startswith(prefix):
				key = var[len(prefix):]  # remove prefix
				if key in self._keymap:
					path = '.'.join(k.lower() for k in self._keymap[key])
					value = os.environ[var]
					self.set(path, value, set_partial=False)
					if not self.validate(print_errors=False) and print_errors:
						console.print(f'[bold red]{var} (override failed)[/]')
				# elif print_errors:
				# 	console.print(f'[bold red]{var} (override failed: key not found)[/]')


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
# Load .env from data dir (lower priority than CWD .env and OS env vars)
load_dotenv(data_root / '.env', override=False)
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

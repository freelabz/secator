import os
from pathlib import Path
from subprocess import call, DEVNULL
from typing import Dict, List
from typing_extensions import Annotated, Self

import requests
import yaml
from dotenv import find_dotenv, load_dotenv
from dotmap import DotMap
from pydantic import AfterValidator, BaseModel, model_validator, ValidationError

from secator.rich import console, console_stdout

load_dotenv(find_dotenv(usecwd=True), override=False)

Directory = Annotated[Path, AfterValidator(lambda v: v.expanduser())]
StrExpandHome = Annotated[str, AfterValidator(lambda v: v.replace('~', str(Path.home())))]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'
DATA_FOLDER = os.environ.get('SECATOR_DIRS_DATA') or str(Path.home() / '.secator')


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
	celery: Directory = ''
	celery_data: Directory = ''
	celery_results: Directory = ''

	@model_validator(mode='after')
	def set_default_folders(self) -> Self:
		"""Set folders to be relative to the data folders if they are unspecified in config."""
		for folder in ['templates', 'reports', 'wordlists', 'cves', 'payloads', 'performance', 'revshells', 'celery', 'celery_data', 'celery_results']:  # noqa: E501
			rel_target = '/'.join(folder.split('_'))
			val = getattr(self, folder) or self.data / rel_target
			setattr(self, folder, val)
		return self


class Debug(StrictModel):
	level: int = 0
	component: str = ''


class Celery(StrictModel):
	broker_url: str = 'filesystem://'
	broker_pool_limit: int = 10
	broker_connection_timeout: float = 4.0
	broker_visibility_timeout: int = 3600
	broker_transport_options: str = ""
	override_default_logging: bool = True
	result_backend: StrExpandHome = ''
	result_backend_transport_options: str = ""
	result_expires: int = 86400  # 1 day
	task_acks_late: bool = False
	task_send_sent_event: bool = False
	task_reject_on_worker_lost: bool = False
	worker_max_tasks_per_child: int = 20
	worker_prefetch_multiplier: int = 1
	worker_send_task_events: bool = False
	worker_kill_after_task: bool = False
	worker_kill_after_idle_seconds: int = -1


class Cli(StrictModel):
	github_token: str = os.environ.get('GITHUB_TOKEN', '')
	record: bool = False
	stdin_timeout: int = 1000


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
	show_chunk_progress: bool = False


class Security(StrictModel):
	allow_local_file_access: bool = True
	auto_install_commands: bool = True
	force_source_install: bool = False


class HTTP(StrictModel):
	socks5_proxy: str = 'socks5://127.0.0.1:9050'
	http_proxy: str = 'https://127.0.0.1:9080'
	store_responses: bool = False
	response_max_size_bytes: int = 100000  # 100MB
	proxychains_command: str = 'proxychains'
	freeproxy_timeout: int = 1


class Tasks(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt']


class Workflows(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt']


class Scans(StrictModel):
	exporters: List[str] = ['json', 'csv', 'txt']


class Payloads(StrictModel):
	templates: Dict[str, str] = {
		'lse': 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh',
		'linpeas': 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
		'sudo_killer': 'https://github.com/TH3xACE/SUDO_KILLER/archive/refs/heads/V3.zip'
	}


class Wordlists(StrictModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains'}
	templates: Dict[str, str] = {
		'bo0m_fuzz': 'https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt',
		'combined_subdomains': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt',  # noqa: E501
		'directory_list_small': 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/directory-list-2.3-small.txt',  # noqa: E501
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


class Addons(StrictModel):
	gdrive: GoogleDriveAddon = GoogleDriveAddon()
	gcs: GoogleCloudStorageAddon = GoogleCloudStorageAddon()
	worker: WorkerAddon = WorkerAddon()
	mongodb: MongodbAddon = MongodbAddon()


class SecatorConfig(StrictModel):
	dirs: Directories = Directories()
	debug: Debug = Debug()
	celery: Celery = Celery()
	cli: Cli = Cli()
	runners: Runners = Runners()
	http: HTTP = HTTP()
	tasks: Tasks = Tasks()
	workflows: Workflows = Workflows()
	scans: Scans = Scans()
	payloads: Payloads = Payloads()
	wordlists: Wordlists = Wordlists()
	addons: Addons = Addons()
	security: Security = Security()
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

	def set(self, key, value, set_partial=True):
		"""Set a value in the configuration using a dotted path.

		Args:
			key (str | None): Dotted key path.
			value (Any): Value.
			set_partial (bool): Set in partial config.
		"""
		# Get existing value
		existing_value = self.get(key, print=False)

		# Convert dotted key path to the corresponding uppercase key used in _keymap
		map_key = key.upper().replace('.', '_')

		# Check if map key exists
		if map_key not in self._keymap:
			console.print(f'[bold red]Key "{key}" not found in config keymap[/].')
			return

		# Traverse to the second last key to handle the setting correctly
		target = self
		partial = self._partial
		for part in self._keymap[map_key][:-1]:
			target = target[part]
			partial = partial[part]

		# Set the value on the final part of the path
		final_key = self._keymap[map_key][-1]

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
					value = value.lower() in ("true", "1", "t")
				elif isinstance(value, (int, float)):
					value = True if value == 1 else False
			elif isinstance(existing_value, int):
				value = int(value)
			elif isinstance(existing_value, float):
				value = float(value)
			elif isinstance(existing_value, Path):
				value = Path(value)
		except ValueError:
			# from secator.utils import debug
			# debug(f'Could not cast value {value} to expected type {type(existing_value).__name__}: {str(e)}', sub='config')
			pass
		finally:
			target[final_key] = value
			if set_partial:
				partial[final_key] = value

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
		return Config.load(
			SecatorConfig,
			data=self._partial.toDict(),
			print_errors=print_errors)

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
	def build_key_map(config, base_path=[]):
		key_map = {}
		for key, value in config.items():
			if key.startswith('_'):  # ignore
				continue
			current_path = base_path + [key]
			if isinstance(value, dict):
				key_map.update(Config.build_key_map(value, current_path))
			else:
				key_map['_'.join(current_path).upper()] = current_path
		return key_map

	def apply_env_overrides(self, print_errors=True):
		"""Override config values from environment variables."""
		prefix = "SECATOR_"
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
	if url_or_path.startswith('git+'):
		# Clone Git repository
		git_url = url_or_path[4:]  # remove 'git+' prefix
		repo_name = git_url.split('/')[-1]
		if repo_name.endswith('.git'):
			repo_name = repo_name[:-4]
		target_path = target_folder / repo_name
		if not target_path.exists():
			console.print(f'[bold turquoise4]Cloning git {type} [bold magenta]{repo_name}[/] ...[/] ', end='')
			if offline_mode:
				console.print('[bold orange1]skipped [dim][offline[/].[/]')
				return
			try:
				call(['git', 'clone', git_url, str(target_path)], stderr=DEVNULL, stdout=DEVNULL)
				console.print('[bold green]ok.[/]')
			except Exception as e:
				console.print(f'[bold red]failed ({str(e)}).[/]')
		return target_path.resolve()
	elif Path(url_or_path).exists():
		# Create a symbolic link for a local file
		local_path = Path(url_or_path)
		target_path = target_folder / local_path.name
		if not name:
			name = url_or_path.split('/')[-1]
		if not CONFIG.security.allow_local_file_access:
			console.print(f'[bold red]Cannot reference local file {url_or_path}(disabled for security reasons)[/]')
			return
		if not target_path.exists():
			console.print(f'[bold turquoise4]Symlinking {type} [bold magenta]{name}[/] ...[/] ', end='')
			try:
				target_path.symlink_to(local_path)
				console.print('[bold green]ok.[/]')
			except Exception as e:
				console.print(f'[bold red]failed ({str(e)}).[/]')
		return target_path.resolve()
	else:
		# Download file from URL
		ext = url_or_path.split('.')[-1]
		if not name:
			name = url_or_path.split('/')[-1]
		filename = f'{name}.{ext}' if not name.endswith(ext) else name
		target_path = target_folder / filename
		if not target_path.exists():
			try:
				console.print(f'[bold turquoise4]Downloading {type} [bold magenta]{filename}[/] ...[/] ', end='')
				if offline_mode:
					console.print('[bold orange1]skipped [dim](offline)[/].[/]')
					return
				resp = requests.get(url_or_path, timeout=3)
				resp.raise_for_status()
				with open(target_path, 'wb') as f:
					f.write(resp.content)
				console.print('[bold green]ok.[/]')
			except requests.RequestException as e:
				console.print(f'[bold red]failed ({str(e)}).[/]')
				return
		return target_path.resolve()


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
	console.print(
		f'[bold turquoise4]Creating user conf [bold magenta]{config_path}[/]... [/]', end='')
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
		dir.mkdir(parents=False)
		console.print('[bold green]ok.[/]')

# Download wordlists and payloads
download_files(CONFIG.wordlists.templates, CONFIG.dirs.wordlists, CONFIG.offline_mode, 'wordlist')
download_files(CONFIG.payloads.templates, CONFIG.dirs.payloads, CONFIG.offline_mode, 'payload')

# Print config
if CONFIG.debug.component == 'config':
	CONFIG.print()

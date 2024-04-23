import os
from pathlib import Path
from subprocess import call, DEVNULL
from typing import Dict, List
from typing_extensions import Annotated, Self

import requests
import yaml
from dotmap import DotMap
from pydantic import AfterValidator, BaseModel, model_validator, ValidationError, Extra

from secator.rich import console, console_stdout

Directory = Annotated[Path, AfterValidator(lambda v: v.expanduser())]
StrExpandHome = Annotated[str, AfterValidator(lambda v: v.replace('~', str(Path.home())))]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'


class StrictModel(BaseModel, extra=Extra.forbid):
	pass


class Directories(StrictModel):
	bin: Directory = Path.home() / '.local' / 'bin'
	data: Directory = Path.home() / '.secator'
	templates: Directory = ''
	reports: Directory = ''
	wordlists: Directory = ''
	cves: Directory = ''
	payloads: Directory = ''
	revshells: Directory = ''
	celery: Directory = ''
	celery_data: Directory = ''
	celery_results: Directory = ''

	@model_validator(mode='after')
	def set_default_folders(self) -> Self:
		"""Set folders to be relative to the data folders if they are unspecified in config."""
		for folder in ['templates', 'reports', 'wordlists', 'cves', 'payloads', 'revshells', 'celery', 'celery_data', 'celery_results']:  # noqa: E501
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
	override_default_logging: bool = True
	result_backend: StrExpandHome = ''


class Cli(StrictModel):
	github_token: str = ''
	record: bool = False
	stdin_timeout: int = 1000


class Runners(StrictModel):
	input_chunk_size: int = 1000
	progress_update_frequency: int = 60
	skip_cve_search: bool = False


class HTTP(StrictModel):
	socks5_proxy: str = 'socks5://127.0.0.1:9050'
	http_proxy: str = 'https://127.0.0.1:9080'
	store_responses: bool = False
	proxychains_command: str = 'proxychains'
	freeproxy_timeout: int = 1


class Tasks(StrictModel):
	exporters: List[str] = ['json', 'csv']


class Workflows(StrictModel):
	exporters: List[str] = ['json', 'csv']


class Scans(StrictModel):
	exporters: List[str] = ['json', 'csv']


class Payloads(StrictModel):
	templates: Dict[str, str] = {
		'lse': 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh',
		'linpeas': 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
		'sudo_killer': 'git+https://github.com/TH3xACE/SUDO_KILLER'
	}


class Wordlists(StrictModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains'}
	templates: Dict[str, str] = {
		'bo0m_fuzz': 'https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt',
		'combined_subdomains': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt'  # noqa: E501
	}
	lists: Dict[str, List[str]] = {}


class GoogleAddon(StrictModel):
	enabled: bool = False
	drive_parent_folder_id: str = ''
	credentials_path: str = ''


class WorkerAddon(StrictModel):
	enabled: bool = False


class MongodbAddon(StrictModel):
	enabled: bool = False
	url: str = 'mongodb://localhost'
	update_frequency: int = 60


class Addons(StrictModel):
	google: GoogleAddon = GoogleAddon()
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
	offline_mode: bool = False


class Config(DotMap):
	"""Config class.

	Examples:
	>>> config = Config.parse()  						   # get default config.
	>>> config = Config.parse({'dirs': {'data': '/tmp/'})  # get custom config (from dict).
	>>> config = Config.parse(path='/path/to/config.yml')  # get custom config (from YAML file).
	>>> config.print() 									   # print config without defaults.
	>>> config.print(partial=False)  					   # print full config.
	>>> config.set('addons.google.enabled', False)         # set value in config.
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
			partial (bool): Also set value in partial config (written to disk).

		Returns:
			bool: Success boolean.
		"""
		# Get existing value
		existing_value = self.get(key, print=False)

		# Convert dotted key path to the corresponding uppercase key used in _keymap
		map_key = key.upper().replace('.', '_')
		success = False
		if map_key in self._keymap:
			# Traverse to the second last key to handle the setting correctly
			target = self
			partial = self._partial
			for part in self._keymap[map_key][:-1]:
				target = target[part]
				if set_partial:
					partial = partial[part]

			# Set the value on the final part of the path
			final_key = self._keymap[map_key][-1]

			# Convert the value to the correct type based on the current value type
			try:
				if isinstance(existing_value, bool):
					if isinstance(value, str):
						value = value.lower() in ("true", "1", "t")
					elif isinstance(value, (int, float)):
						value = True if value == 1 else False
				elif isinstance(existing_value, int):
					value = int(value)
				elif isinstance(existing_value, float):
					value = float(value)
				if existing_value != value:
					target[final_key] = value
					if set_partial:
						partial[final_key] = value
				success = True
			except ValueError:
				success = False
				# console.print(f'[bold red]{key}: cannot cast value "{value}" to {type(existing_value).__name__}')
		else:
			console.print(f'[bold red]Key "{key}" not found in config keymap[/].')
		return success

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
	def parse(data: dict = {}, path: Path = None, env_overrides: bool = False):
		"""Parse config.

		Args:
			data (dict): Config data.
			path (Path | None): Path to YAML config.
			env_overrides (bool): Apply env overrides.

		Returns:
			Config: instance of Config object.
			None: if the config was not loaded properly or there are validation errors.
		"""
		if path:
			data = Config.read_yaml(path)

		# Load data
		try:
			config = Config.load(SecatorConfig, data)
			config._valid = True

			# HACK: set default result_backend if unset
			if not config.celery.result_backend:
				config.celery.result_backend = f'file://{config.dirs.celery_results}'

		except ValidationError as e:
			error_str = str(e).replace('\n', '\n  ')
			if path:
				error_str.replace('SecatorConfig', f'SecatorConfig ({path})')
			console.print(f'[bold red]:x: {error_str}')
			# console.print('[bold green]Using default config.[/]')
			config = Config.parse()
			config._valid = False

		# Set hidden attributes
		keymap = Config.build_key_map(config)
		partial = Config(data)
		config._partial = partial
		config._path = path
		config._keymap = keymap

		# Override config values with environment variables
		if env_overrides:
			config.apply_env_overrides()
			data = {k: v for k, v in config.toDict().items() if not k.startswith('_')}
			config = Config.parse(data, env_overrides=False)  # re-validate config
			config._partial = partial
			config._path = path

		return config

	@staticmethod
	def load(schema, data: dict = {}):
		"""Validate a config using Pydantic.

		Args:
			data (dict): Config dict.

		Returns:
			Config: instance of Config object.
		"""
		return Config(schema(**data).model_dump())

	@staticmethod
	def read_yaml(yaml_path):
		"""Read YAML from path.

		Args:
			yaml_path (Path): path to yaml config.

		Returns:
			dict: Loaded data.
		"""
		with yaml_path.open('r') as f:
			data = yaml.load(f.read(), Loader=yaml.Loader)
			return data or {}

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

	def apply_env_overrides(self):
		"""Override config values from environment variables."""
		# Build a map of keys from the config
		key_map = Config.build_key_map(self)

		# Prefix for environment variables to target
		prefix = "SECATOR_"

		# Loop through environment variables
		for var in os.environ:
			if var.startswith(prefix):
				# Remove prefix and get the path from the key map
				key = var[len(prefix):]
				if key in key_map:
					path = '.'.join(k.lower() for k in key_map[key])
					value = os.environ[var]

					# Set the new value recursively
					success = self.set(path, value, set_partial=False)
					if success:
						console.print(f'[bold green4]{var} (override success)[/]')
					else:
						console.print(f'[bold red]{var} (override failed: cannot update value)[/]')
				else:
					console.print(f'[bold red]{var} (override failed: key not found in config)[/]')


def download_files(data: dict, target_folder: Path, offline_mode: bool, type: str):
	"""Download remote files to target folder, clone git repos, or symlink local files.

	Args:
		data (dict): Dict of name to url or local path prefixed with 'git+' for Git repos.
		target_folder (Path): Target folder for storing files or repos.
		type (str): Type of files to handle.
		offline_mode (bool): Offline mode.
	"""
	for name, url_or_path in data.items():
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
					continue
				try:
					call(['git', 'clone', git_url, str(target_path)], stderr=DEVNULL, stdout=DEVNULL)
					console.print('[bold green]ok.[/]')
				except Exception as e:
					console.print(f'[bold red]failed ({str(e)}).[/]')
			data[name] = target_path.resolve()
		elif Path(url_or_path).exists():
			# Create a symbolic link for a local file
			local_path = Path(url_or_path)
			target_path = target_folder / local_path.name
			if not target_path.exists():
				console.print(f'[bold turquoise4]Symlinking {type} [bold magenta]{local_path.name}[/] ...[/] ', end='')
				try:
					target_path.symlink_to(local_path)
					console.print('[bold green]ok.[/]')
				except Exception as e:
					console.print(f'[bold red]failed ({str(e)}).[/]')
			data[name] = target_path.resolve()
		else:
			# Download files from URL
			filename = url_or_path.split('/')[-1]
			target_path = target_folder / filename
			if not target_path.exists():
				try:
					console.print(f'[bold turquoise4]Downloading {type} [bold magenta]{filename}[/] ...[/] ', end='')
					if offline_mode:
						console.print('[bold orange1]skipped [dim](offline)[/].[/]')
						continue
					resp = requests.get(url_or_path, timeout=3)
					resp.raise_for_status()
					with open(target_path, 'wb') as f:
						f.write(resp.content)
					console.print('[bold green]ok.[/]')
				except requests.RequestException as e:
					console.print(f'[bold red]failed ({str(e)}).[/]')
					continue
			data[name] = target_path.resolve()


# Load configs
default_config = Config.parse()
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
CONFIG = Config.parse(path=config_path, env_overrides=True)

# Create directories if they don't exist already
for name, dir in CONFIG.dirs.items():
	if not dir.exists():
		console.print(f'[bold turquoise4]Creating directory [bold magenta]{dir}[/] ... [/]', end='')
		dir.mkdir(parents=False)
		console.print('[bold green]ok.[/]')


# Download wordlists and set defaults
download_files(CONFIG.wordlists.templates, CONFIG.dirs.wordlists, CONFIG.offline_mode, 'wordlist')
for category, name in CONFIG.wordlists.defaults.items():
	if name in CONFIG.wordlists.templates.keys():
		CONFIG.wordlists.defaults[category] = str(CONFIG.wordlists.templates[name])


# Download payloads
download_files(CONFIG.payloads.templates, CONFIG.dirs.payloads, CONFIG.offline_mode, 'payload')

# Print config
if CONFIG.debug.component == 'config':
	CONFIG.print()

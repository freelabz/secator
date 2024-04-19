import sys

from datetime import datetime
from pathlib import Path
from subprocess import call, DEVNULL
from typing import Dict, List
from typing_extensions import Annotated, Self

import requests
import yaml
from dotmap import DotMap
from piny import MatcherWithDefaults, PydanticV2Validator, YamlLoader, errors
from pydantic import AfterValidator, BaseModel, model_validator

from secator.rich import console

Directory = Annotated[Path, AfterValidator(lambda v: v.expanduser())]
StrExpandHome = Annotated[str, AfterValidator(lambda v: v.replace('~', str(Path.home())))]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'


class Directories(BaseModel):
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


class Debug(BaseModel):
	level: int = 0
	component: str = ''


class Celery(BaseModel):
	broker_url: str = 'filesystem://'
	broker_pool_limit: int = 10
	broker_connection_timeout: float = 4.0
	broker_visibility_timeout: int = 3600
	override_default_logging: bool = True
	result_backend: StrExpandHome = ''


class Cli(BaseModel):
	github_token: str = ''
	record: bool = False
	stdin_timeout: int = 1000


class Runners(BaseModel):
	input_chunk_size: int = 1000
	progress_update_frequency: int = 60
	skip_cve_search: bool = False


class HTTP(BaseModel):
	socks5_proxy: str = 'socks5://127.0.0.1:9050'
	http_proxy: str = 'https://127.0.0.1:9080'
	store_responses: bool = False
	proxychains_command: str = 'proxychains'
	freeproxy_timeout: int = 1


class Tasks(BaseModel):
	exporters: List[str] = ['json', 'csv']


class Workflows(BaseModel):
	exporters: List[str] = ['json', 'csv']


class Scans(BaseModel):
	exporters: List[str] = ['json', 'csv']


class Payloads(BaseModel):
	templates: Dict[str, str] = {
		'lse': 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh',
		'linpeas': 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
		'sudo_killer': 'git+https://github.com/TH3xACE/SUDO_KILLER'
	}


class Wordlists(BaseModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains'}
	templates: Dict[str, str] = {
		'bo0m_fuzz': 'https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt',
		'combined_subdomains': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt'  # noqa: E501
	}
	lists: Dict[str, List[str]] = {}


class GoogleAddon(BaseModel):
	enabled: bool = False
	drive_parent_folder_id: str = ''
	credentials_path: str = ''


class WorkerAddon(BaseModel):
	enabled: bool = False


class MongodbAddon(BaseModel):
	enabled: bool = False
	url: str = 'mongodb://localhost'
	update_frequency: int = 60


class Addons(BaseModel):
	google: GoogleAddon = GoogleAddon()
	worker: WorkerAddon = WorkerAddon()
	mongodb: MongodbAddon = MongodbAddon()


class ConfigModel(BaseModel):
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


class Config(DotMap):

	_error = False

	@staticmethod
	def parse(yaml_path: Path = None):

		# Write temp config
		temp = not yaml_path
		yaml_path = yaml_path or Config.create_empty_config()

		# Save original config
		with yaml_path.open('r') as f:
			original_config = yaml.load(f.read(), Loader=yaml.Loader)

		# Load and validate config
		config_dict = YamlLoader(
				yaml_path,
				matcher=MatcherWithDefaults,
				validator=PydanticV2Validator,
				schema=ConfigModel
		).load()
		config = Config(config_dict)
		config._path = yaml_path
		config._partial = DotMap(original_config)
		config._keymap = Config.build_key_map(config)
		if config._created:
			del config._created

		# HACK: set default result_backend if unset
		if not config.celery.result_backend:
			config.celery.result_backend = f'file://{config.dirs.celery_results}'

		# Override config values with environment variables
		# config.apply_env_overrides()

		# Delete tmp config
		yaml_path.unlink() if temp else None

		return config

	@staticmethod
	def create_empty_config(yaml_path=None):
		current_time = datetime.now().isoformat()
		if not yaml_path:
			yaml_path = Path(f'tmp_{current_time}.yml')
		yaml_path.touch()
		with yaml_path.open('w') as f:
			f.write(f'_created: {current_time}')
		return yaml_path

	def print(self, partial=True):
		yaml_str = Config.dump(self, partial=partial)
		if not str(self._path).startswith('tmp'):
			yaml_str = f'# {self._path}\n\n{yaml_str}'
		Config.print_yaml(yaml_str)

	@staticmethod
	def print_yaml(string):
		from rich.syntax import Syntax
		data = Syntax(string, 'yaml', theme='ansi-dark', padding=0, background_color='default')
		console.print(data)

	def save(self, target_path: Path = None, partial=True):
		if not target_path:
			target_path = self._path
		with target_path.open('w') as f:
			f.write(Config.dump(self, partial=partial))
		self._path = target_path

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

		if isinstance(config, Config):
			# HACK: Replace home dir in result_backend
			data['celery']['result_backend'] = data['celery']['result_backend'].replace(home, '~')

			# Render either partial or full config
			if partial:
				data = data['_partial']
			else:
				del data['_path']
				del data['_partial']
				del data['_keymap']
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

	def get(self, key=None, print=True):
		"""Retrieve a value from the configuration using a dotted path."""
		value = self
		if key:
			for part in key.split('.'):
				value = value[part]
		if value is None:
			console.print(f'[bold red]Key {key} does not exist.[/]')
			return None
		if print:
			if key:
				yaml_str = Config.dump(DotMap({key: value}))
			else:
				yaml_str = Config.dump(self, partial=False)
			Config.print_yaml(yaml_str)
		return value

	def set(self, key, value):
		"""Set a value in the configuration using a dotted path."""
		# Convert dotted key path to the corresponding uppercase key used in _keymap
		existing_value = self.get(key, print=False)
		map_key = key.upper().replace('.', '_')
		success = False
		if map_key in self._keymap:
			# Traverse to the second last key to handle the setting correctly
			target = self
			partial = self._partial
			for part in self._keymap[map_key][:-1]:
				target = target[part]
				partial = partial[part]

			# Set the value on the final part of the path
			final_key = self._keymap[map_key][-1]

			# Convert the value to the correct type based on the current value type
			if isinstance(existing_value, bool):
				value = value.lower() in ("true", "1", "t")
			elif isinstance(existing_value, int):
				value = int(value)
			elif isinstance(existing_value, float):
				value = float(value)

			target[final_key] = value
			partial[final_key] = value
			self.get(key)
			success = True
		else:
			console.print(f'[bold red]{key} not found in configuration.[/]')
		return success

	# def apply_env_overrides(self):
	# 	"""Override config values from environment variables."""
	# 	# Build a map of keys from the config
	# 	key_map = Config.build_key_map(self)

	# 	# Prefix for environment variables to target
	# 	prefix = "SECATOR_"

	# 	# Loop through environment variables
	# 	for var in os.environ:
	# 		if var.startswith(prefix):
	# 			# Remove prefix and get the path from the key map
	# 			key = var[len(prefix):]
	# 			if key in key_map:
	# 				path = key_map[key]
	# 				value = os.environ[var]

	# 				# Set the new value recursively
	# 				self.set(path, value)
	# 				print(f"Config updated: {'.'.join(path)} set to {config[path[0]]}")
	# 			else:
	# 				print(f"No config path found for {var}")


def download_files(data: dict, target_folder: Path, type: str):
	"""Download remote files to target folder, clone git repos, or symlink local files.

	Args:
		data (dict): Dict of name to url or local path prefixed with 'git+' for Git repos.
		target_folder (Path): Target folder for storing files or repos.
		type (str): Type of files to handle.
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
try:
	default_config = Config.parse()
	user_config_path = default_config.dirs.data / 'config.yml'
	if not user_config_path.exists():
		default_config.dirs.data.mkdir(parents=False)
		Config.create_empty_config(user_config_path)
	config = Config.parse(user_config_path)
except errors.ValidationError as e:
	print(str(e))
	sys.exit(0)


# Create directories if they don't exist already
for name, dir in config.dirs.items():
	if not dir.exists():
		console.print(f'[bold turquoise4]Creating directory [bold magenta]{name}[/] ... [/]', end='')
		dir.mkdir(parents=False)
		console.print('[bold green]ok. [/]')


# Download wordlists and set defaults
download_files(config.wordlists.templates, config.dirs.wordlists, 'wordlist')
for category, name in config.wordlists.defaults.items():
	if name in config.wordlists.templates.keys():
		config.wordlists.defaults[category] = str(config.wordlists.templates[name])


# Download payloads
download_files(config.payloads.templates, config.dirs.payloads, 'payload')

# Print config
if config.debug.component == 'config':
	config.print()

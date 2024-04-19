import os
import sys
from pathlib import Path
from typing import Dict, List
from typing_extensions import Annotated, Self

import requests
from dotmap import DotMap
from piny import MatcherWithDefaults, PydanticV2Validator, YamlLoader, errors
from pydantic import AfterValidator, BaseModel, model_validator

from secator.rich import console

Directory = Annotated[Path, AfterValidator(lambda v: v.expanduser())]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'


class Directories(BaseModel):
	bin: Directory = Path.home() / '.local' / 'bin'
	data: Directory = Path.home() / '.secator'
	configs: Directory = ''
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
		for folder in ['configs', 'reports', 'wordlists', 'cves', 'payloads', 'revshells', 'celery', 'celery_data', 'celery_results']:  # noqa: E501
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
	result_backend: str = ''


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
		'sudo_killer': 'https://github.com/TH3xACE/SUDO_KILLER'
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

	@staticmethod
	def parse(yaml_path: Path):
		config_dict = YamlLoader(
				yaml_path,
				matcher=MatcherWithDefaults,
				validator=PydanticV2Validator,
				schema=ConfigModel
		).load()
		config = Config(config_dict)
		config._path = yaml_path

		# HACK: set default result_backend
		if not config.celery.result_backend:
			config.celery.result_backend = f'file://{config.dirs.celery_results}'
		return config

	def __repr__(self):
		from rich.syntax import Syntax
		console.print(Syntax(self.dump(), 'yaml'))
		return ''

	def save(self, target_path=None):
		if not target_path:
			target_path = self._path
		with target_path.open('w') as f:
			f.write(self.dump())

	def edit(self, key, value):
		pass

	def dump(self):
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
		data = self.toDict()

		# HACK: Replace home dir in result_backend
		data['celery']['result_backend'] = data['celery']['result_backend'].replace(home, '~')

		# HACK: remove _path from config
		del data['_path']

		# Dump YAML to string
		return yaml.dump(data, Dumper=LineBreakDumper, sort_keys=False)


def download_remote_files(data: dict, target_folder: Path, type: str):
	"""Download remote files to target folder.

	Args:
		data (dict): Dict of name to url.
		target_folder (pathlib.Path): Target folder.
		type (str): Type of files to download.
	"""
	for name, url in data.items():
		filename = url.split('/')[-1]
		target_path = target_folder / filename
		if not target_path.exists():
			try:
				console.print(f'[bold turquoise4]Downloading {type} [bold magenta]{filename}[/] ...[/] ', end='')
				resp = requests.get(url, timeout=3)
				resp.raise_for_status()
				target_path.touch()
				with target_path.open('w') as f:
					f.write(resp.text)
				console.print('[bold green]ok.[/]')
				data[name] = target_path.resolve()
			except requests.RequestException as e:
				console.print(f'[bold green]failed ({type(e).__name__}).[/]')
				pass
		else:
			data[name] = target_path.resolve()


# Load configs
try:
	default_config_path = LIB_FOLDER / 'configs' / 'config.yml'
	default_config = Config.parse(default_config_path)
	default_config_path = default_config._path
	config = default_config

	# Override with user configs
	user_configs = [
		config.dirs.data / 'config.yml',
		Path.cwd() / 'config.yml'
	]
	for config_path in user_configs:
		if config_path.exists():
			config = Config.parse(config_path)
	console.print(f'[bold green]Loaded config [/]{config._path}')

	# Save default config to configs/ folder
	if os.environ.get('SAVE_DEFAULT_CONFIG', '0') == '1':
		console.print(f'[bold green]Saved default config to [/]{default_config_path}')
		default_config.save()

except errors.ValidationError as e:
	print(str(e))
	sys.exit(0)


# Create folders if they don't exist already
for name, dir in config.dirs.items():
	if not dir.exists():
		console.print(f'[bold turquoise4]Creating folder {dir} ...[/] ', end='')
		dir.mkdir(parents=False)
		console.print('[bold green]ok.[/]')


# Download wordlists and set defaults
download_remote_files(config.wordlists.files, config.dirs.wordlists, 'wordlist')
for category, name in config.wordlists.defaults.items():
	if name in config.wordlists.files.keys():
		config.wordlists.defaults[category] = str(config.wordlists.files[name])


# Download payloads
download_remote_files(config.wordlists.files, config.dirs.wordlists, 'payload')

if config.debug.component == 'config':
	console.print(config)

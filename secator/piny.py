import sys
from pathlib import Path
from typing import Dict, List, Union
from typing_extensions import Annotated

import requests
from dotmap import DotMap
from piny import MatcherWithDefaults, PydanticV2Validator, YamlLoader, errors
from pydantic import AfterValidator, BaseModel, computed_field
from pydantic.types import PathType

from secator.rich import console

expand_home = AfterValidator(lambda v: v.expanduser())
PotentialDirectoryPath = Union[
	Annotated[Path, expand_home, PathType('dir')],
	Annotated[Path, expand_home, PathType('new')]
]

ROOT_FOLDER = Path(__file__).parent.parent
LIB_FOLDER = ROOT_FOLDER / 'secator'
CONFIGS_FOLDER = LIB_FOLDER / 'configs'


class Folders(BaseModel):
	bin: PotentialDirectoryPath = Path.home() / '.local' / 'bin'
	data: PotentialDirectoryPath = Path.home() / '.secator'

	@computed_field
	def extra_configs(self) -> PotentialDirectoryPath:
		return self.data / 'configs'

	@computed_field
	def reports(self) -> PotentialDirectoryPath:
		return self.data / 'reports'

	@computed_field
	def wordlists(self) -> PotentialDirectoryPath:
		return self.data / 'wordlists'

	@computed_field
	def cves(self) -> PotentialDirectoryPath:
		return self.data / 'cves'

	@computed_field
	def payloads(self) -> PotentialDirectoryPath:
		return self.data / 'payloads'

	@computed_field
	def revshells(self) -> PotentialDirectoryPath:
		return self.data / 'revshells'

	@computed_field
	def celery(self) -> PotentialDirectoryPath:
		return self.data / 'celery'

	@computed_field
	def celery_data(self) -> PotentialDirectoryPath:
		return self.celery / 'data'

	@computed_field
	def celery_results(self) -> PotentialDirectoryPath:
		return self.celery / 'results'


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
	files: Dict[str, str] = {
		'lse': 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh',
		'linpeas': 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
		'sudo_killer': 'https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/V3/SUDO_KILLERv3.sh'
	}


class Wordlists(BaseModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains'}
	files: Dict[str, str] = {
		'bo0m_fuzz': 'https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt',
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
	folders: Folders = Folders()
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


# Load configs
try:
	default_config_path = LIB_FOLDER / 'configs' / 'config.yml'
	default_config = YamlLoader(
		default_config_path,
		matcher=MatcherWithDefaults,
		validator=PydanticV2Validator,
		schema=ConfigModel,
	).load()

	# Convert to dotmap for easier access
	config = DotMap(default_config)

	# Load user configs
	user_configs = [
		config.folders.data / 'config.yml',
		Path.cwd() / 'config.yml'
	]
	for config_path in user_configs:
		if config_path.exists():
			config = YamlLoader(
				config_path,
				matcher=MatcherWithDefaults,
				validator=PydanticV2Validator,
				schema=ConfigModel
			).load()
			console.print(f'Using custom config at {config_path}')

	# Set default Celery backend
	if not config.celery.result_backend:
		config.celery.result_backend = f'file://{config.folders.celery_results}'

	# Save default config to configs/ folder
	import os
	if os.environ.get('SAVE_DEFAULT_CONFIG', '0') == '1':
		console.print(f'Saving default config to {default_config_path}')
		import yaml
		from pathlib import Path, PosixPath, WindowsPath
		home = str(Path.home())
		config.celery.result_backend = config.celery.result_backend.replace(home, '~')

		def posix_path_representer(dumper, data):
			path = str(data)
			if path.startswith(home):
				path = path.replace(home, '~')
			return dumper.represent_scalar('tag:yaml.org,2002:str', path)

		class LineBreakDumper(yaml.SafeDumper):
			def write_line_break(self, data=None):
				super().write_line_break(data)
				if len(self.indents) == 1:
					super().write_line_break()

		LineBreakDumper.add_representer(Path, posix_path_representer)
		LineBreakDumper.add_representer(PosixPath, posix_path_representer)
		LineBreakDumper.add_representer(WindowsPath, posix_path_representer)

		with default_config_path.open('w') as f:
			f.write(yaml.dump(default_config, Dumper=LineBreakDumper, sort_keys=False))

except errors.ValidationError as e:
	print(str(e))
	sys.exit(0)


# Create folders if they don't exist already
for name, dir in config.folders.items():
	if not dir.exists():
		console.print(f'[bold turquoise4]Creating folder {dir} ...[/] ', end='')
		dir.mkdir(parents=False)
		console.print('[bold green]ok.[/]')

# Download wordlists
for name, url in config.wordlists.files.items():
	filename = url.split('/')[-1]
	target_path = config.folders.wordlists / filename
	if not target_path.exists():
		try:
			console.print(f'[bold turquoise4]Downloading wordlist [bold magenta]{filename}[/] ...[/] ', end='')
			resp = requests.get(url)
			target_path.touch()
			with target_path.open('w') as f:
				f.write(resp.text)
			console.print('[bold green]ok.[/]')
			config.wordlists.files[name] = target_path.resolve()
		except requests.exceptions.RequestException as e:
			console.print(f'[bold green]failed ({type(e).__name__}).[/]')
			pass
	else:
		config.wordlists.files[name] = target_path.resolve()

# Set default wordlists
for category, name in config.wordlists.defaults.items():
	if name in config.wordlists.files.keys():
		config.wordlists.defaults[category] = str(config.wordlists.files[name])

# Download default payloads
for name, url in config.payloads.files.items():
	filename = url.split('/')[-1]
	target_path = config.folders.payloads / filename
	if not target_path.exists():
		try:
			console.print(f'[bold turquoise4]Downloading payload [bold magenta]{filename}[/] ...[/] ', end='')
			resp = requests.get(url)
			target_path.touch()
			with target_path.open('w') as f:
				f.write(resp.text)
			console.print('[bold green]ok.[/]')
			config.wordlists.files[name] = target_path.resolve()
		except requests.exceptions.RequestException as e:
			console.print(f'[bold green]failed ({type(e).__name__}).[/]')
			pass
	else:
		config.payloads.files[name] = target_path.resolve()

# console.print(config.toDict())

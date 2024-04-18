from pydantic import BaseModel, DirectoryPath, NewPath, computed_field, validator
from piny import PydanticV2Validator, MatcherWithDefaults, YamlLoader, errors
import sys
from typing import Union, List, Dict
from secator.rich import console
from pathlib import Path
import requests

PotentialDirectoryPath = Union[DirectoryPath, NewPath]

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
	print_start: bool = False
	print_item: bool = False
	print_line: bool = False
	print_errors: bool = False
	print_item_count: bool = False
	print_cmd: bool = False
	print_run_opts: bool = False
	print_fmt_opts: bool = False
	print_input_file: bool = False
	print_hooks: bool = False
	print_progress: bool = False
	print_remote_status: bool = False
	print_run_summary: bool = False
	print_json: bool = False
	print_raw: bool = False
	raise_on_error: bool = False
	exporters: List[str] = ['json', 'csv']


class Workflows(BaseModel):
	print_start: bool = False
	print_item: bool = False
	print_line: bool = False
	print_errors: bool = False
	print_item_count: bool = False
	print_cmd: bool = False
	print_run_opts: bool = False
	print_fmt_opts: bool = False
	print_input_file: bool = False
	print_hooks: bool = False
	print_progress: bool = False
	print_remote_status: bool = False
	print_run_summary: bool = False
	print_json: bool = False
	print_raw: bool = False
	raise_on_error: bool = False
	exporters: List[str] = ['json', 'csv']


class Scans(BaseModel):
	print_start: bool = False
	print_item: bool = False
	print_line: bool = False
	print_errors: bool = False
	print_item_count: bool = False
	print_cmd: bool = False
	print_run_opts: bool = False
	print_fmt_opts: bool = False
	print_input_file: bool = False
	print_hooks: bool = False
	print_progress: bool = False
	print_remote_status: bool = False
	print_run_summary: bool = False
	print_json: bool = False
	print_raw: bool = False
	raise_on_error: bool = False
	exporters: List[str] = ['json', 'csv']


class Wordlists(BaseModel):
	defaults: Dict[str, str] = {'http': 'bo0m_fuzz', 'dns': 'combined_subdomains'}
	files: Dict[str, str] = {'bo0m_fuzz': 'https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt', 'combined_subdomains': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt'}
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


class Payloads(BaseModel):
	templates: List[str] = []


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
	wordlists: Wordlists = Wordlists()
	payloads: Payloads = Payloads()
	addons: Addons = Addons()


try:
	config = YamlLoader(
		f'{LIB_FOLDER}/configs/config.yml',
		matcher=MatcherWithDefaults,
		validator=PydanticV2Validator,
		schema=ConfigModel,
	).load()

	# Convert to dotmap for easier access
	from dotmap import DotMap
	config = DotMap(config)


	# Create folders if they don't exist already
	for name, dir in config.folders.items():
		if not dir.exists():
			console.print(f'[bold turquoise4]Creating folder {dir} ...[/] ', end='')
			dir.mkdir(parents=False)
			console.print('[bold green]ok.[/]')

	# Set default Celery backend
	if not config.celery.result_backend:
		config.celery.result_backend = f'file://{config.folders.celery_results}'

	# Download default wordlists
	wordlist = config.folders.wordlists
	for name, url in config.wordlists.files.items():
		name_txt = f'{name}.txt'
		target_path = wordlist / name_txt
		if not target_path.exists():
			try:
				console.print(f'[bold turquoise4]Downloading wordlist [bold magenta]{name_txt}[/] ...[/] ', end='')
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
	for category, name in config.wordlists.defaults.items():
		if name in config.wordlists.files.keys():
			config.wordlists.defaults[category] = str(config.wordlists.files[name])

except errors.ValidationError as e:
	print(str(e))
	sys.exit(0)

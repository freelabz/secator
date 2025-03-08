import json
import os
import re
import shutil
import sys

from pathlib import Path
from stat import S_ISFIFO

import rich_click as click
from dotmap import DotMap
from fp.fp import FreeProxy
from jinja2 import Template
from rich.live import Live
from rich.markdown import Markdown
from rich.rule import Rule
from rich.table import Table

from secator.config import CONFIG, ROOT_FOLDER, Config, default_config, config_path
from secator.decorators import OrderedGroup, register_runner
from secator.definitions import ADDONS_ENABLED, ASCII, DEV_PACKAGE, OPT_NOT_SUPPORTED, VERSION, STATE_COLORS
from secator.installer import ToolInstaller, fmt_health_table_row, get_health_table, get_version_info, get_distro_config
from secator.output_types import FINDING_TYPES, Info, Warning, Error
from secator.report import Report
from secator.rich import console
from secator.runners import Command, Runner
from secator.serializers.dataclass import loads_dataclass
from secator.template import TemplateLoader
from secator.utils import (
	debug, detect_host, discover_tasks, flatten, print_version, get_file_date,
	sort_files_by_date, get_file_timestamp, list_reports, get_info_from_report_path, human_to_timedelta
)

click.rich_click.USE_RICH_MARKUP = True

ALL_TASKS = discover_tasks()
ALL_CONFIGS = TemplateLoader.load_all()
ALL_WORKFLOWS = ALL_CONFIGS.workflow
ALL_SCANS = ALL_CONFIGS.scan
FINDING_TYPES_LOWER = [c.__name__.lower() for c in FINDING_TYPES]


#-----#
# CLI #
#-----#

@click.group(cls=OrderedGroup, invoke_without_command=True)
@click.option('--version', '-version', is_flag=True, default=False)
@click.pass_context
def cli(ctx, version):
	"""Secator CLI."""
	ctx.obj = {
		'piped_input': S_ISFIFO(os.fstat(0).st_mode),
		'piped_output': not sys.stdout.isatty()
	}
	if not ctx.obj['piped_output']:
		console.print(ASCII, highlight=False)
	if ctx.invoked_subcommand is None:
		if version:
			print_version()
		else:
			ctx.get_help()


#------#
# TASK #
#------#

@cli.group(aliases=['x', 't'])
@click.pass_context
def task(ctx):
	"""Run a task."""
	pass


for cls in ALL_TASKS:
	config = TemplateLoader(input={'name': cls.__name__, 'type': 'task'})
	register_runner(task, config)

#----------#
# WORKFLOW #
#----------#


@cli.group(cls=OrderedGroup, aliases=['w'])
@click.pass_context
def workflow(ctx):
	"""Run a workflow."""
	pass


for config in sorted(ALL_WORKFLOWS, key=lambda x: x['name']):
	register_runner(workflow, config)


#------#
# SCAN #
#------#

@cli.group(cls=OrderedGroup, aliases=['s'])
@click.pass_context
def scan(ctx):
	"""Run a scan."""
	pass


for config in sorted(ALL_SCANS, key=lambda x: x['name']):
	register_runner(scan, config)


#--------#
# WORKER #
#--------#

@cli.command(name='worker', context_settings=dict(ignore_unknown_options=True), aliases=['wk'])
@click.option('-n', '--hostname', type=str, default='runner', help='Celery worker hostname (unique).')
@click.option('-c', '--concurrency', type=int, default=100, help='Number of child processes processing the queue.')
@click.option('-r', '--reload', is_flag=True, help='Autoreload Celery on code changes.')
@click.option('-Q', '--queue', type=str, default='', help='Listen to a specific queue.')
@click.option('-P', '--pool', type=str, default='eventlet', help='Pool implementation.')
@click.option('--check', is_flag=True, help='Check if Celery worker is alive.')
@click.option('--dev', is_flag=True, help='Start a worker in dev mode (celery multi).')
@click.option('--stop', is_flag=True, help='Stop a worker in dev mode (celery multi).')
@click.option('--show', is_flag=True, help='Show command (celery multi).')
def worker(hostname, concurrency, reload, queue, pool, check, dev, stop, show):
	"""Run a worker."""

	# Check Celery addon is installed
	if not ADDONS_ENABLED['worker']:
		console.print(Error(message='Missing worker addon: please run "secator install addons worker".'))
		sys.exit(1)

	# Check broken / backend addon is installed
	broker_protocol = CONFIG.celery.broker_url.split('://')[0]
	backend_protocol = CONFIG.celery.result_backend.split('://')[0]
	if CONFIG.celery.broker_url:
		if (broker_protocol == 'redis' or backend_protocol == 'redis') and not ADDONS_ENABLED['redis']:
			console.print(Error(message='Missing redis addon: please run "secator install addons redis".'))
			sys.exit(1)

	# Debug Celery config
	from secator.celery import app, is_celery_worker_alive
	debug('conf', obj=dict(app.conf), obj_breaklines=True, sub='celery.app')
	debug('registered tasks', obj=list(app.tasks.keys()), obj_breaklines=True, sub='celery.app')

	if check:
		is_celery_worker_alive()
		return

	if not queue:
		queue = 'io,cpu,poll,' + ','.join(set([r['queue'] for r in app.conf.task_routes.values()]))

	app_str = 'secator.celery.app'
	celery = f'{sys.executable} -m celery'

	if dev:
		subcmd = 'stop' if stop else 'show' if show else 'start'
		logfile = '%n.log'
		pidfile = '%n.pid'
		queues = '-Q:1 celery -Q:2 io -Q:3 cpu'
		concur = '-c:1 10 -c:2 100 -c:3 4'
		pool = 'eventlet'
		cmd = f'{celery} -A {app_str} multi {subcmd} 3 {queues} -P {pool} {concur} --logfile={logfile} --pidfile={pidfile}'
	else:
		cmd = f'{celery} -A {app_str} worker -n {hostname} -Q {queue}'

	cmd += f' -P {pool}' if pool else ''
	cmd += f' -c {concurrency}' if concurrency else ''

	if reload:
		patterns = "celery.py;tasks/*.py;runners/*.py;serializers/*.py;output_types/*.py;hooks/*.py;exporters/*.py"
		cmd = f'watchmedo auto-restart --directory=./ --patterns="{patterns}" --recursive -- {cmd}'

	ret = Command.execute(cmd, name='secator_worker')
	sys.exit(ret.return_code)


#-------#
# UTILS #
#-------#


@cli.group(aliases=['u'])
def util():
	"""Run a utility."""
	pass


@util.command()
@click.option('--timeout', type=float, default=0.2, help='Proxy timeout (in seconds)')
@click.option('--number', '-n', type=int, default=1, help='Number of proxies')
def proxy(timeout, number):
	"""Get random proxies from FreeProxy."""
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		return
	proxy = FreeProxy(timeout=timeout, rand=True, anonym=True)
	for _ in range(number):
		url = proxy.get()
		console.print(url)


@util.command()
@click.argument('name', type=str, default=None, required=False)
@click.option('--host', '-h', type=str, default=None, help='Specify LHOST for revshell, otherwise autodetected.')
@click.option('--port', '-p', type=int, default=9001, show_default=True, help='Specify PORT for revshell')
@click.option('--interface', '-i', type=str, help='Interface to use to detect IP')
@click.option('--listen', '-l', is_flag=True, default=False, help='Spawn netcat listener on specified port')
@click.option('--force', is_flag=True)
def revshell(name, host, port, interface, listen, force):
	"""Show reverse shell source codes and run netcat listener (-l)."""
	if host is None:  # detect host automatically
		host = detect_host(interface)
		if not host:
			console.print(Error(message=f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of available interfaces'))  # noqa: E501
			return
		else:
			console.print(Info(message=f'Detected host IP: {host}'))

	# Download reverse shells JSON from repo
	revshells_json = f'{CONFIG.dirs.revshells}/revshells.json'
	if not os.path.exists(revshells_json) or force:
		if CONFIG.offline_mode:
			console.print(Error(message='Cannot run this command in offline mode'))
			return
		ret = Command.execute(
			f'wget https://raw.githubusercontent.com/freelabz/secator/main/scripts/revshells.json && mv revshells.json {CONFIG.dirs.revshells}',  # noqa: E501
			cls_attributes={'shell': True}
		)
		if not ret.return_code == 0:
			sys.exit(1)

	# Parse JSON into shells
	with open(revshells_json) as f:
		shells = json.loads(f.read())
		for sh in shells:
			sh['alias'] = '_'.join(sh['name'].lower()
				.replace('-c', '')
				.replace('-e', '')
				.replace('-i', '')
				.replace('c#', 'cs')
				.replace('#', '')
				.replace('(', '')
				.replace(')', '')
				.strip()
				.split(' ')).replace('_1', '')
			cmd = re.sub(r"\s\s+", "", sh.get('command', ''), flags=re.UNICODE)
			cmd = cmd.replace('\n', ' ')
			sh['cmd_short'] = (cmd[:30] + '..') if len(cmd) > 30 else cmd

	shell = [
		shell for shell in shells if shell['name'] == name or shell['alias'] == name
	]
	if not shell:
		console.print('Available shells:', style='bold yellow')
		shells_str = [
			'[bold magenta]{alias:<20}[/][dim white]{name:<20}[/][dim gold3]{cmd_short:<20}[/]'.format(**sh)
			for sh in shells
		]
		console.print('\n'.join(shells_str))
	else:
		shell = shell[0]
		command = shell['command'].replace('[', r'\[')
		alias = shell['alias']
		name = shell['name']
		command_str = Template(command).render(ip=host, port=port, shell='bash')
		console.print(Rule(f'[bold gold3]{alias}[/] - [bold red]{name} REMOTE SHELL', style='bold red', align='left'))
		lang = shell.get('lang') or 'sh'
		if len(command.splitlines()) == 1:
			console.print(command_str, style='cyan', highlight=False, soft_wrap=True)
		else:
			md = Markdown(f'```{lang}\n{command_str}\n```')
			console.print(md)
			console.print(f'Save this script as rev.{lang} and run it on your target', style='dim italic')
		console.print()
		console.print(Rule(style='bold red'))

	if listen:
		console.print(Info(message=f'Starting netcat listener on port {port} ...'))
		cmd = f'nc -lvnp {port}'
		Command.execute(cmd)


@util.command()
@click.option('--directory', '-d', type=str, default=CONFIG.dirs.payloads, help='HTTP server directory')
@click.option('--host', '-h', type=str, default=None, help='HTTP host')
@click.option('--port', '-p', type=int, default=9001, help='HTTP server port')
@click.option('--interface', '-i', type=str, default=None, help='Interface to use to auto-detect host IP')
def serve(directory, host, port, interface):
	"""Run HTTP server to serve payloads."""
	console.print(Rule())
	console.print(f'Available payloads in {directory}: ', style='bold yellow')
	for fname in os.listdir(directory):
		if not host:
			host = detect_host(interface)
			if not host:
				console.print(Error(message=f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of interfaces.'))  # noqa: E501
				return
		console.print(f'{fname} [dim][/]', style='bold magenta')
		console.print(f'wget http://{host}:{port}/{fname}', style='dim italic')
		console.print('')
	console.print(Rule())
	console.print(f'Started HTTP server on port {port}, waiting for incoming connections ...', style='bold yellow')
	Command.execute(f'{sys.executable} -m http.server {port}', cwd=directory)


@util.command()
@click.argument('record_name', type=str, default=None)
@click.option('--script', '-s', type=str, default=None, help='Script to run. See scripts/stories/ for examples.')
@click.option('--interactive', '-i', is_flag=True, default=False, help='Interactive record.')
@click.option('--width', '-w', type=int, default=None, help='Recording width')
@click.option('--height', '-h', type=int, default=None, help='Recording height')
@click.option('--output-dir', type=str, default=f'{ROOT_FOLDER}/images')
def record(record_name, script, interactive, width, height, output_dir):
	"""Record secator session using asciinema."""
	# 120 x 30 is a good ratio for GitHub
	width = width or console.size.width
	height = height or console.size.height
	attrs = {
		'shell': False,
		'env': {
			'RECORD': '1',
			'LINES': str(height),
			'PS1': '$ ',
			'COLUMNS': str(width),
			'TERM': 'xterm-256color'
		}
	}
	output_cast_path = f'{output_dir}/{record_name}.cast'
	output_gif_path = f'{output_dir}/{record_name}.gif'

	# Run automated 'story' script with asciinema-automation
	if script:
		# If existing cast file, remove it
		if os.path.exists(output_cast_path):
			os.unlink(output_cast_path)
			console.print(Info(message=f'Removed existing {output_cast_path}'))

		with console.status(Info(message='Recording with asciinema ...')):
			Command.execute(
				f'asciinema-automation -aa "-c /bin/sh" {script} {output_cast_path} --timeout 200',
				cls_attributes=attrs,
				raw=True,
			)
			console.print(f'Generated {output_cast_path}', style='bold green')
	elif interactive:
		os.environ.update(attrs['env'])
		Command.execute(f'asciinema rec -c /bin/bash --stdin --overwrite {output_cast_path}')

	# Resize cast file
	if os.path.exists(output_cast_path):
		with console.status('[bold gold3]Cleaning up .cast and set custom settings ...'):
			with open(output_cast_path, 'r') as f:
				lines = f.readlines()
			updated_lines = []
			for ix, line in enumerate(lines):
				tmp_line = json.loads(line)
				if ix == 0:
					tmp_line['width'] = width
					tmp_line['height'] = height
					tmp_line['env']['SHELL'] = '/bin/sh'
					lines[0] = json.dumps(tmp_line) + '\n'
					updated_lines.append(json.dumps(tmp_line) + '\n')
				elif tmp_line[2].endswith(' \r'):
					tmp_line[2] = tmp_line[2].replace(' \r', '')
					updated_lines.append(json.dumps(tmp_line) + '\n')
				else:
					updated_lines.append(line)
			with open(output_cast_path, 'w') as f:
				f.writelines(updated_lines)
			console.print('')

		# Edit cast file to reduce long timeouts
		with console.status('[bold gold3] Editing cast file to reduce long commands ...'):
			Command.execute(
				f'asciinema-edit quantize --range 1 {output_cast_path} --out {output_cast_path}.tmp',
				cls_attributes=attrs,
				raw=True,
			)
			if os.path.exists(f'{output_cast_path}.tmp'):
				os.replace(f'{output_cast_path}.tmp', output_cast_path)
			console.print(f'Edited {output_cast_path}', style='bold green')

	# Convert to GIF
	with console.status(f'[bold gold3]Converting to {output_gif_path} ...[/]'):
		Command.execute(
			f'agg {output_cast_path} {output_gif_path}',
			cls_attributes=attrs,
		)
		console.print(Info(message=f'Generated {output_gif_path}'))


@util.command('build')
@click.option('--version', type=str, help='Override version specified in pyproject.toml')
def build(version):
	"""Build secator PyPI package."""
	if not DEV_PACKAGE:
		console.print(Error(message='You MUST use a development version of secator to make builds'))
		sys.exit(1)
	if not ADDONS_ENABLED['build']:
		console.print(Error(message='Missing build addon: please run "secator install addons build"'))
		sys.exit(1)

	# Update version in pyproject.toml if --version is explicitely passed
	if version:
		pyproject_toml_path = Path.cwd() / 'pyproject.toml'
		if not pyproject_toml_path.exists():
			console.print(Error(message='You must be in the secator root directory to make builds with --version'))
			sys.exit(1)
		console.print(Info(message=f'Updating version in pyproject.toml to {version}'))
		with open(pyproject_toml_path, "r") as file:
			content = file.read()
		updated_content = re.sub(r'^\s*version\s*=\s*".*?"', f'version = "{version}"', content, flags=re.MULTILINE)
		with open(pyproject_toml_path, "w") as file:
			file.write(updated_content)

	with console.status('[bold gold3]Building PyPI package...[/]'):
		ret = Command.execute(f'{sys.executable} -m hatch build', name='hatch build', cwd=ROOT_FOLDER)
		sys.exit(ret.return_code)


@util.command('publish')
def publish():
	"""Publish secator PyPI package."""
	if not DEV_PACKAGE:
		console.print(Error(message='You MUST use a development version of secator to publish builds.'))
		sys.exit(1)
	if not ADDONS_ENABLED['build']:
		console.print(Error(message='Missing build addon: please run "secator install addons build"'))
		sys.exit(1)
	os.environ['HATCH_INDEX_USER'] = '__token__'
	hatch_token = os.environ.get('HATCH_INDEX_AUTH')
	if not hatch_token:
		console.print(Error(message='Missing PyPI auth token (HATCH_INDEX_AUTH env variable).'))
		sys.exit(1)
	with console.status('[bold gold3]Publishing PyPI package...[/]'):
		ret = Command.execute(f'{sys.executable} -m hatch publish', name='hatch publish', cwd=ROOT_FOLDER)
		sys.exit(ret.return_code)


#--------#
# CONFIG #
#--------#

@cli.group(aliases=['c'])
def config():
	"""View or edit config."""
	pass


@config.command('get')
@click.option('--full', is_flag=True, help='Show full config (with defaults)')
@click.argument('key', required=False)
def config_get(full, key=None):
	"""Get config value."""
	if key is None:
		partial = not full and CONFIG != default_config
		CONFIG.print(partial=partial)
		return
	CONFIG.get(key)


@config.command('set')
@click.argument('key')
@click.argument('value')
def config_set(key, value):
	"""Set config value."""
	CONFIG.set(key, value)
	config = CONFIG.validate()
	if config:
		CONFIG.get(key)
		saved = CONFIG.save()
		if not saved:
			return
		console.print(f'[bold green]:tada: Saved config to [/]{CONFIG._path}')
	else:
		console.print(Error(message='Invalid config, not saving it.'))


@config.command('edit')
@click.option('--resume', is_flag=True)
def config_edit(resume):
	"""Edit config."""
	tmp_config = CONFIG.dirs.data / 'config.yml.patch'
	if not tmp_config.exists() or not resume:
		shutil.copyfile(config_path, tmp_config)
	click.edit(filename=tmp_config)
	config = Config.parse(path=tmp_config)
	if config:
		config.save(config_path)
		console.print(f'\n[bold green]:tada: Saved config to [/]{config_path}.')
		tmp_config.unlink()
	else:
		console.print('\n[bold green]Hint:[/] Run "secator config edit --resume" to edit your patch and fix issues.')


@config.command('default')
@click.option('--save', type=str, help='Save default config to file.')
def config_default(save):
	"""Get default config."""
	default_config.print(partial=False)
	if save:
		default_config.save(target_path=Path(save), partial=False)
		console.print(f'\n[bold green]:tada: Saved default config to [/]{save}.')


# TODO: implement reset method
# @_config.command('reset')
# @click.argument('key')
# def config_reset(key):
# 	"""Reset config value to default."""
# 	success = CONFIG.set(key, None)
# 	if success:
# 		CONFIG.print()
# 		CONFIG.save()
# 		console.print(f'\n[bold green]:tada: Saved config to [/]{CONFIG._path}')

#-----------#
# WORKSPACE #
#-----------#
@cli.group(aliases=['ws'])
def workspace():
	"""Workspaces."""
	pass


@workspace.command('list')
def workspace_list():
	"""List workspaces."""
	workspaces = {}
	json_reports = []
	for root, _, files in os.walk(CONFIG.dirs.reports):
		for file in files:
			if file.endswith('report.json'):
				path = Path(root) / file
				json_reports.append(path)
	json_reports = sorted(json_reports, key=lambda x: x.stat().st_mtime, reverse=False)
	for path in json_reports:
		ws, runner_type, number = str(path).split('/')[-4:-1]
		if ws not in workspaces:
			workspaces[ws] = {'count': 0, 'path': '/'.join(str(path).split('/')[:-3])}
		workspaces[ws]['count'] += 1

	# Build table
	table = Table()
	table.add_column("Workspace name", style="bold gold3")
	table.add_column("Run count", overflow='fold')
	table.add_column("Path")
	for workspace, config in workspaces.items():
		table.add_row(workspace, str(config['count']), config['path'])
	console.print(table)


#--------#
# REPORT #
#--------#


@cli.group(aliases=['r'])
def report():
	"""Reports."""
	pass


@report.command('show')
@click.argument('report_query', required=False)
@click.option('-o', '--output', type=str, default='console', help='Exporters')
@click.option('-r', '--runner-type', type=str, default=None, help='Filter by runner type. Choices: task, workflow, scan')  # noqa: E501
@click.option('-d', '--time-delta', type=str, default=None, help='Keep results newer than time delta. E.g: 26m, 1d, 1y')  # noqa: E501
@click.option('-t', '--type', type=str, default='', help=f'Filter by output type. Choices: {FINDING_TYPES_LOWER}')
@click.option('-q', '--query', type=str, default=None, help='Query results using a Python expression')
@click.option('-w', '-ws', '--workspace', type=str, default=None, help='Filter by workspace name')
@click.option('-u', '--unified', is_flag=True, default=False, help='Show unified results (merge reports and de-duplicates results)')  # noqa: E501
def report_show(report_query, output, runner_type, time_delta, type, query, workspace, unified):
	"""Show report results and filter on them."""

	# Get extractors
	otypes = [o.__name__.lower() for o in FINDING_TYPES]
	extractors = []
	if type:
		type = type.split(',')
		for typedef in type:
			if typedef:
				if '.' in typedef:
					_type, _field = tuple(typedef.split('.'))
				else:
					_type = typedef
					_field = None
				extractors.append({
					'type': _type,
					'field': _field,
					'condition': query or 'True'
				})
	elif query:
		query = query.split(';')
		for part in query:
			_type = part.split('.')[0]
			if _type in otypes:
				part = part.replace(_type, 'item')
				extractor = {
					'type': _type,
					'condition': part or 'True'
				}
				extractors.append(extractor)

	# Build runner instance
	current = get_file_timestamp()
	runner = DotMap({
		"config": {
			"name": f"consolidated_report_{current}"
		},
		"name": "runner",
		"workspace_name": "_consolidated",
		"reports_folder": Path.cwd(),
	})
	exporters = Runner.resolve_exporters(output)

	# Build report queries from fuzzy input
	paths = []
	if report_query:
		report_query = report_query.split(',')
	else:
		report_query = []

	# Load all report paths
	load_all_reports = any([not Path(p).exists() for p in report_query])
	all_reports = []
	if load_all_reports or workspace:
		all_reports = list_reports(workspace=workspace, type=runner_type, timedelta=human_to_timedelta(time_delta))
	if not report_query:
		report_query = all_reports

	for query in report_query:
		query = str(query)
		if not query.endswith('/'):
			query += '/'
		path = Path(query)
		if not path.exists():
			matches = []
			for path in all_reports:
				if query in str(path):
					matches.append(path)
			if not matches:
				console.print(
					f'[bold orange3]Query {query} did not return any matches. [/][bold green]Ignoring.[/]')
			paths.extend(matches)
		else:
			paths.append(path)
	paths = sort_files_by_date(paths)

	# Load reports, extract results
	all_results = []
	for ix, path in enumerate(paths):
		if unified:
			console.print(rf'Loading {path} \[[bold yellow4]{ix + 1}[/]/[bold yellow4]{len(paths)}[/]] \[results={len(all_results)}]...')  # noqa: E501
		with open(path, 'r') as f:
			data = loads_dataclass(f.read())
			try:
				info = get_info_from_report_path(path)
				runner_type = info.get('type', 'unknowns')[:-1]
				runner.results = flatten(list(data['results'].values()))
				if unified:
					all_results.extend(runner.results)
					continue
				report = Report(runner, title=f"Consolidated report - {current}", exporters=exporters)
				report.build(extractors=extractors if not unified else [])
				file_date = get_file_date(path)
				runner_name = data['info']['name']
				console.print(
					f'\n{path} ([bold blue]{runner_name}[/] [dim]{runner_type}[/]) ([dim]{file_date}[/]):')
				if report.is_empty():
					if len(paths) == 1:
						console.print(Warning(message='No results in report.'))
					else:
						console.print(Warning(message='No new results since previous scan.'))
					continue
				report.send()
			except json.decoder.JSONDecodeError as e:
				console.print(Error(message=f'Could not load {path}: {str(e)}'))

	if unified:
		console.print(f'\n:wrench: [bold gold3]Building report by crunching {len(all_results)} results ...[/]')
		console.print(':coffee: [dim]Note that this can take a while when the result count is high...[/]')
		runner.results = all_results
		report = Report(runner, title=f"Consolidated report - {current}", exporters=exporters)
		report.build(extractors=extractors, dedupe=True)
		report.send()


@report.command('list')
@click.option('-ws', '-w', '--workspace', type=str)
@click.option('-r', '--runner-type', type=str, default=None, help='Filter by runner type. Choices: task, workflow, scan')  # noqa: E501
@click.option('-d', '--time-delta', type=str, default=None, help='Keep results newer than time delta. E.g: 26m, 1d, 1y')  # noqa: E501
def report_list(workspace, runner_type, time_delta):
	"""List all secator reports."""
	paths = list_reports(workspace=workspace, type=runner_type, timedelta=human_to_timedelta(time_delta))
	paths = sorted(paths, key=lambda x: x.stat().st_mtime, reverse=False)

	# Build table
	table = Table()
	table.add_column("Workspace", style="bold gold3")
	table.add_column("Path", overflow='fold')
	table.add_column("Name")
	table.add_column("Id")
	table.add_column("Date")
	table.add_column("Status", style="green")

	# Load each report
	for path in paths:
		try:
			info = get_info_from_report_path(path)
			with open(path, 'r') as f:
				content = json.loads(f.read())
			data = {
				'workspace': info['workspace'],
				'name': f"[bold blue]{content['info']['name']}[/]",
				'status': content['info'].get('status', ''),
				'id': info['type'] + '/' + info['id'],
				'date': get_file_date(path),  # Assuming get_file_date returns a readable date
			}
			status_color = STATE_COLORS[data['status']] if data['status'] in STATE_COLORS else 'white'

			# Update table
			table.add_row(
				data['workspace'],
				str(path),
				data['name'],
				data['id'],
				data['date'],
				f"[{status_color}]{data['status']}[/]"
			)
		except json.JSONDecodeError as e:
			console.print(Error(message=f'Could not load {path}: {str(e)}'))

	if len(paths) > 0:
		console.print(table)
	else:
		console.print(Error(message='No results found.'))


@report.command('export')
@click.argument('json_path', type=str)
@click.option('--output-folder', '-of', type=str)
@click.option('-output', '-o', type=str)
def report_export(json_path, output_folder, output):
	with open(json_path, 'r') as f:
		data = loads_dataclass(f.read())

	runner_instance = DotMap({
		"config": {
			"name": data['info']['name']
		},
		"workspace_name": json_path.split('/')[-4],
		"reports_folder": output_folder or Path.cwd(),
		"data": data,
		"results": flatten(list(data['results'].values()))
	})
	exporters = Runner.resolve_exporters(output)
	report = Report(runner_instance, title=data['info']['title'], exporters=exporters)
	report.data = data
	report.send()


#--------#
# DEPLOY #
#--------#

# TODO: work on this
# @cli.group(aliases=['d'])
# def deploy():
# 	"""Deploy secator."""
# 	pass

# @deploy.command()
# def docker_compose():
# 	"""Deploy secator on docker-compose."""
# 	pass

# @deploy.command()
# @click.option('-t', '--target', type=str, default='minikube', help='Deployment target amongst minikube, gke')
# def k8s():
# 	"""Deploy secator on Kubernetes."""
# 	pass


#--------#
# HEALTH #
#--------#

@cli.command(name='health')
@click.option('--json', '-json', is_flag=True, default=False, help='JSON lines output')
@click.option('--debug', '-debug', is_flag=True, default=False, help='Debug health output')
@click.option('--strict', '-strict', is_flag=True, default=False, help='Fail if missing tools')
def health(json, debug, strict):
	"""[dim]Get health status.[/]"""
	tools = ALL_TASKS
	status = {'secator': {}, 'languages': {}, 'tools': {}, 'addons': {}}

	# Check secator
	console.print(':wrench: [bold gold3]Checking secator ...[/]')
	info = get_version_info('secator', '-version', 'freelabz/secator')
	table = get_health_table()
	with Live(table, console=console):
		row = fmt_health_table_row(info)
		table.add_row(*row)
	status['secator'] = info

	# Check addons
	console.print('\n:wrench: [bold gold3]Checking installed addons ...[/]')
	table = get_health_table()
	with Live(table, console=console):
		for addon, installed in ADDONS_ENABLED.items():
			info = {
				'name': addon,
				'version': None,
				'status': 'ok' if installed else 'missing',
				'latest_version': None,
				'installed': installed,
				'location': None
			}
			row = fmt_health_table_row(info, 'addons')
			table.add_row(*row)
			status['addons'][addon] = info

	# Check languages
	console.print('\n:wrench: [bold gold3]Checking installed languages ...[/]')
	version_cmds = {'go': 'version', 'python3': '--version', 'ruby': '--version'}
	table = get_health_table()
	with Live(table, console=console):
		for lang, version_flag in version_cmds.items():
			info = get_version_info(lang, version_flag)
			row = fmt_health_table_row(info, 'langs')
			table.add_row(*row)
			status['languages'][lang] = info

	# Check tools
	console.print('\n:wrench: [bold gold3]Checking installed tools ...[/]')
	table = get_health_table()
	with Live(table, console=console):
		for tool in tools:
			info = get_version_info(
				tool.cmd.split(' ')[0],
				tool.version_flag or f'{tool.opt_prefix}version',
				tool.install_github_handle,
				tool.install_cmd
			)
			row = fmt_health_table_row(info, 'tools')
			table.add_row(*row)
			status['tools'][tool.__name__] = info
	console.print('')

	# Print JSON health
	if json:
		import json as _json
		print(_json.dumps(status))

	# Strict mode
	if strict:
		error = False
		for tool, info in status['tools'].items():
			if not info['installed']:
				console.print(Error(message=f'{tool} not installed and strict mode is enabled.'))
				error = True
		if error:
			sys.exit(1)
		console.print(Info(message='Strict healthcheck passed !'))


#---------#
# INSTALL #
#---------#


def run_install(title=None, cmd=None, packages=None, next_steps=None):
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		return
	with console.status(f'[bold yellow] Installing {title}...'):
		if cmd:
			from secator.installer import SourceInstaller
			status = SourceInstaller.install(cmd)
		elif packages:
			from secator.installer import PackageInstaller
			status = PackageInstaller.install(packages)
		return_code = 1
		if status.is_ok():
			return_code = 0
			if next_steps:
				console.print('[bold gold3]:wrench: Next steps:[/]')
				for ix, step in enumerate(next_steps):
					console.print(f'   :keycap_{ix}: {step}')
		sys.exit(return_code)


@cli.group()
def install():
	"""[dim]Install langs, tools and addons.[/]"""
	pass


@install.group()
def addons():
	"Install addons."
	pass


@addons.command('worker')
def install_worker():
	"Install Celery worker addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[worker]',
		title='Celery worker addon',
		next_steps=[
			'Run [bold green4]secator worker[/] to run a Celery worker using the file system as a backend and broker.',
			'Run [bold green4]secator x httpx testphp.vulnweb.com[/] to admire your task running in a worker.',
			r'[dim]\[optional][/dim] Run [bold green4]secator install addons redis[/] to setup Redis backend / broker.'
		]
	)


@addons.command('gdrive')
def install_gdrive():
	"Install Google Drive addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[google]',
		title='Google Drive addon',
		next_steps=[
			'Run [bold green4]secator config set addons.gdrive.credentials_path <VALUE>[/].',
			'Run [bold green4]secator config set addons.gdrive.drive_parent_folder_id <VALUE>[/].',
			'Run [bold green4]secator x httpx testphp.vulnweb.com -o gdrive[/] to send reports to Google Drive.'
		]
	)


@addons.command('gcs')
def install_gcs():
	"Install Google Cloud Storage addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[gcs]',
		title='Google Cloud Storage addon',
		next_steps=[
			'Run [bold green4]secator config set addons.gcs.credentials_path <VALUE>[/].',
		]
	)


@addons.command('mongodb')
def install_mongodb():
	"Install MongoDB addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[mongodb]',
		title='MongoDB addon',
		next_steps=[
			r'[dim]\[optional][/] Run [bold green4]docker run --name mongo -p 27017:27017 -d mongo:latest[/] to run a local MongoDB instance.',  # noqa: E501
			'Run [bold green4]secator config set addons.mongodb.url mongodb://<URL>[/].',
			'Run [bold green4]secator x httpx testphp.vulnweb.com -driver mongodb[/] to save results to MongoDB.'
		]
	)


@addons.command('redis')
def install_redis():
	"Install Redis addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[redis]',
		title='Redis addon',
		next_steps=[
			r'[dim]\[optional][/] Run [bold green4]docker run --name redis -p 6379:6379 -d redis[/] to run a local Redis instance.',  # noqa: E501
			'Run [bold green4]secator config set celery.broker_url redis://<URL>[/]',
			'Run [bold green4]secator config set celery.result_backend redis://<URL>[/]',
			'Run [bold green4]secator worker[/] to run a worker.',
			'Run [bold green4]secator x httpx testphp.vulnweb.com[/] to run a test task.'
		]
	)


@addons.command('dev')
def install_dev():
	"Install dev addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[dev]',
		title='dev addon',
		next_steps=[
			'Run [bold green4]secator test lint[/] to run lint tests.',
			'Run [bold green4]secator test unit[/] to run unit tests.',
			'Run [bold green4]secator test integration[/] to run integration tests.',
		]
	)


@addons.command('trace')
def install_trace():
	"Install trace addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[trace]',
		title='trace addon',
		next_steps=[
		]
	)


@addons.command('build')
def install_build():
	"Install build addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[build]',
		title='build addon',
		next_steps=[
			'Run [bold green4]secator u build pypi[/] to build the PyPI package.',
			'Run [bold green4]secator u publish pypi[/] to publish the PyPI package.',
			'Run [bold green4]secator u build docker[/] to build the Docker image.',
			'Run [bold green4]secator u publish docker[/] to publish the Docker image.',
		]
	)


@install.group()
def langs():
	"Install languages."
	pass


@langs.command('go')
def install_go():
	"""Install Go."""
	run_install(
		cmd='wget -O - https://raw.githubusercontent.com/freelabz/secator/main/scripts/install_go.sh | sudo sh',
		title='Go',
		next_steps=[
			'Add ~/go/bin to your $PATH'
		]
	)


@langs.command('ruby')
def install_ruby():
	"""Install Ruby."""
	run_install(
		packages={
			'apt': ['ruby-full', 'rubygems'],
			'apk': ['ruby', 'ruby-dev'],
			'pacman': ['ruby', 'ruby-dev'],
			'brew': ['ruby']
		},
		title='Ruby'
	)


@install.command('tools')
@click.argument('cmds', required=False)
@click.option('--cleanup', is_flag=True, default=False)
def install_tools(cmds, cleanup):
	"""Install supported tools."""
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		return
	if cmds is not None:
		cmds = cmds.split(',')
		tools = [cls for cls in ALL_TASKS if cls.__name__ in cmds]
	else:
		tools = ALL_TASKS
	tools.sort(key=lambda x: x.__name__)
	return_code = 0
	if not tools:
		cmd_str = ' '.join(cmds)
		console.print(Error(message=f'No tools found for {cmd_str}.'))
		return
	for ix, cls in enumerate(tools):
		with console.status(f'[bold yellow][{ix + 1}/{len(tools)}] Installing {cls.__name__} ...'):
			status = ToolInstaller.install(cls)
			if not status.is_ok():
				return_code = 1
		console.print()
	if cleanup:
		distro = get_distro_config()
		cleanup_cmds = [
			'go clean -cache',
			'go clean -modcache',
			'pip cache purge',
			'gem cleanup --user-install',
			'gem clean --user-install',
		]
		if distro.pm_finalizer:
			cleanup_cmds.append(f'sudo {distro.pm_finalizer}')
		cmd = ' && '.join(cleanup_cmds)
		Command.execute(cmd, cls_attributes={'shell': True}, quiet=False)
	sys.exit(return_code)


#--------#
# UPDATE #
#--------#

@cli.command('update')
@click.option('--all', '-a', is_flag=True, help='Update all secator dependencies (addons, tools, ...)')
def update(all):
	"""[dim]Update to latest version.[/]"""
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		sys.exit(1)

	# Check current and latest version
	info = get_version_info('secator', '-version', 'freelabz/secator', version=VERSION)
	latest_version = info['latest_version']
	do_update = True

	# Skip update if latest
	if info['status'] == 'latest':
		console.print(Info(message=f'secator is already at the newest version {latest_version} !'))
		do_update = False

	# Fail if unknown latest
	if not latest_version:
		console.print(Error(message='Could not fetch latest secator version.'))
		sys.exit(1)

	# Update secator
	if do_update:
		console.print(f'[bold gold3]:wrench: Updating secator from {VERSION} to {latest_version} ...[/]')
		if 'pipx' in sys.executable:
			ret = Command.execute(f'pipx install secator=={latest_version} --force')
		else:
			ret = Command.execute(f'pip install secator=={latest_version}')
		if not ret.return_code == 0:
			sys.exit(1)

	# Update tools
	if all:
		return_code = 0
		for cls in ALL_TASKS:
			cmd = cls.cmd.split(' ')[0]
			version_flag = cls.version_flag or f'{cls.opt_prefix}version'
			version_flag = None if cls.version_flag == OPT_NOT_SUPPORTED else version_flag
			info = get_version_info(cmd, version_flag, cls.install_github_handle)
			if not info['installed'] or info['status'] == 'outdated' or not info['latest_version']:
				with console.status(f'[bold yellow]Installing {cls.__name__} ...'):
					status = ToolInstaller.install(cls)
					if not status.is_ok():
						return_code = 1
		sys.exit(return_code)

#-------#
# ALIAS #
#-------#


@cli.group()
def alias():
	"""[dim]Configure aliases.[/]"""
	pass


@alias.command('enable')
@click.pass_context
def enable_aliases(ctx):
	"""Enable aliases."""
	fpath = f'{CONFIG.dirs.data}/.aliases'
	aliases = ctx.invoke(list_aliases, silent=True)
	aliases_str = '\n'.join(aliases)
	with open(fpath, 'w') as f:
		f.write(aliases_str)
	console.print('')
	console.print(f':file_cabinet: Alias file written to {fpath}', style='bold green')
	console.print('To load the aliases, run:')
	md = f"""
```sh
source {fpath}                     # load the aliases in the current shell
echo "source {fpath} >> ~/.bashrc" # or add this line to your ~/.bashrc to load them automatically
```
"""
	console.print(Markdown(md))
	console.print()


@alias.command('disable')
@click.pass_context
def disable_aliases(ctx):
	"""Disable aliases."""
	fpath = f'{CONFIG.dirs.data}/.unalias'
	aliases = ctx.invoke(list_aliases, silent=True)
	aliases_str = ''
	for alias in aliases:
		aliases_str += alias.split('=')[0].replace('alias', 'unalias') + '\n'
	console.print(f':file_cabinet: Unalias file written to {fpath}', style='bold green')
	console.print('To unload the aliases, run:')
	with open(fpath, 'w') as f:
		f.write(aliases_str)
	md = f"""
```sh
source {fpath}
```
"""
	console.print(Markdown(md))
	console.print()


@alias.command('list')
@click.option('--silent', is_flag=True, default=False, help='No print')
def list_aliases(silent):
	"""List aliases"""
	aliases = []
	aliases.extend([
		f'alias {task.__name__}="secator x {task.__name__}"'
		for task in ALL_TASKS
	])
	aliases.extend([
		f'alias {workflow.alias}="secator w {workflow.name}"'
		for workflow in ALL_WORKFLOWS
	])
	aliases.extend([
		f'alias {workflow.name}="secator w {workflow.name}"'
		for workflow in ALL_WORKFLOWS
	])
	aliases.extend([
		f'alias scan_{scan.name}="secator s {scan.name}"'
		for scan in ALL_SCANS
	])
	aliases.append('alias listx="secator x"')
	aliases.append('alias listw="secator w"')
	aliases.append('alias lists="secator s"')

	if silent:
		return aliases
	console.print('Aliases:')
	for alias in aliases:
		alias_split = alias.split('=')
		alias_name, alias_cmd = alias_split[0].replace('alias ', ''), alias_split[1].replace('"', '')
		console.print(f'[bold magenta]{alias_name:<15}-> {alias_cmd}')

	return aliases


#------#
# TEST #
#------#


@cli.group(cls=OrderedGroup)
def test():
	"""[dim]Run tests."""
	if not DEV_PACKAGE:
		console.print(Error(message='You MUST use a development version of secator to run tests.'))
		sys.exit(1)
	if not ADDONS_ENABLED['dev']:
		console.print(Error(message='Missing dev addon: please run "secator install addons dev"'))
		sys.exit(1)
	pass


def run_test(cmd, name):
	"""Run a test and return the result.

	Args:
		cmd: Command to run.
		name: Name of the test.
	"""
	result = Command.execute(cmd, name=name + ' tests', cwd=ROOT_FOLDER)
	if result.return_code == 0:
		console.print(f':tada: {name.capitalize()} tests passed !', style='bold green')
	sys.exit(result.return_code)


@test.command()
def lint():
	"""Run lint tests."""
	cmd = f'{sys.executable} -m flake8 secator/'
	run_test(cmd, 'lint')


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
def unit(tasks, workflows, scans, test):
	"""Run unit tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_OFFLINE_MODE'] = "1"
	os.environ['SECATOR_HTTP_STORE_RESPONSES'] = '0'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	import shutil
	shutil.rmtree('/tmp/.secator', ignore_errors=True)
	cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.unit -m pytest -s -v tests/unit'
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'unit')


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
def integration(tasks, workflows, scans, test):
	"""Run integration tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	import shutil
	shutil.rmtree('/tmp/.secator', ignore_errors=True)

	cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.integration -m pytest -s -v tests/integration'  # noqa: E501
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'integration')


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
def performance(tasks, workflows, scans, test):
	"""Run integration tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	# import shutil
	# shutil.rmtree('/tmp/.secator', ignore_errors=True)

	cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.performance -m pytest -s -v tests/performance'  # noqa: E501
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'performance')


@test.command()
@click.option('--unit-only', '-u', is_flag=True, default=False, help='Only generate coverage for unit tests')
@click.option('--integration-only', '-i', is_flag=True, default=False, help='Only generate coverage for integration tests')  # noqa: E501
def coverage(unit_only, integration_only):
	"""Run coverage combine + coverage report."""
	cmd = f'{sys.executable} -m coverage report -m --omit=*/site-packages/*,*/tests/*,*/templates/*'
	if unit_only:
		cmd += ' --data-file=.coverage.unit'
	elif integration_only:
		cmd += ' --data-file=.coverage.integration'
	else:
		Command.execute(f'{sys.executable} -m coverage combine --keep', name='coverage combine', cwd=ROOT_FOLDER)
	run_test(cmd, 'coverage')

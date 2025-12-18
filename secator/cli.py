import json
import os
import re
import shutil
import subprocess
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

from secator.config import CONFIG, ROOT_FOLDER, Config, default_config, config_path, download_files
from secator.click import OrderedGroup
from secator.cli_helper import register_runner
from secator.definitions import ADDONS_ENABLED, ASCII, DEV_PACKAGE, VERSION, STATE_COLORS
from secator.installer import ToolInstaller, fmt_health_table_row, get_health_table, get_version_info, get_distro_config
from secator.output_types import FINDING_TYPES, Info, Warning, Error
from secator.report import Report
from secator.rich import console
from secator.runners import Command, Runner
from secator.serializers.dataclass import loads_dataclass
from secator.loader import get_configs_by_type, discover_tasks
from secator.utils import (
	debug, detect_host, flatten, print_version, get_file_date,
	sort_files_by_date, get_file_timestamp, list_reports, get_info_from_report_path, human_to_timedelta
)
from contextlib import nullcontext


click.rich_click.USE_RICH_MARKUP = True
click.rich_click.STYLE_ARGUMENT = ""
click.rich_click.STYLE_OPTION_HELP = ""


FINDING_TYPES_LOWER = [c.__name__.lower() for c in FINDING_TYPES]
CONTEXT_SETTINGS = dict(help_option_names=['-h', '-help', '--help'])
TASKS = get_configs_by_type('task')
WORKFLOWS = get_configs_by_type('workflow')
SCANS = get_configs_by_type('scan')
PROFILES = get_configs_by_type('profile')


#-----#
# CLI #
#-----#


@click.group(cls=OrderedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('--version', '-version', '-v', is_flag=True, default=False)
@click.option('--quiet', '-quiet', '-q', is_flag=True, default=False)
@click.pass_context
def cli(ctx, version, quiet):
	"""Secator CLI."""
	ctx.obj = {
		'piped_input': S_ISFIFO(os.fstat(0).st_mode),
		'piped_output': not sys.stdout.isatty()
	}
	if not ctx.obj['piped_output'] and not quiet:
		console.print(ASCII, highlight=False)
	if ctx.invoked_subcommand is None:
		if version:
			print_version()
		else:
			ctx.get_help()


#------#
# TASK #
#------#

@cli.group(aliases=['x', 't', 'tasks'], invoke_without_command=True)
@click.pass_context
def task(ctx):
	"""Run a task."""
	if ctx.invoked_subcommand is None:
		ctx.get_help()


for config in TASKS:
	register_runner(task, config)

#----------#
# WORKFLOW #
#----------#


@cli.group(cls=OrderedGroup, aliases=['w', 'workflows'], invoke_without_command=True)
@click.pass_context
def workflow(ctx):
	"""Run a workflow."""
	if ctx.invoked_subcommand is None:
		ctx.get_help()


for config in WORKFLOWS:
	register_runner(workflow, config)


#------#
# SCAN #
#------#

@cli.group(cls=OrderedGroup, aliases=['s', 'scans'], invoke_without_command=True)
@click.pass_context
def scan(ctx):
	"""Run a scan."""
	if ctx.invoked_subcommand is None:
		ctx.get_help()


for config in SCANS:
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
@click.option('--quiet', is_flag=True, default=False, help='Quiet mode.')
@click.option('--loglevel', type=str, default='INFO', help='Log level.')
@click.option('--check', is_flag=True, help='Check if Celery worker is alive.')
@click.option('--dev', is_flag=True, help='Start a worker in dev mode (celery multi).')
@click.option('--stop', is_flag=True, help='Stop a worker in dev mode (celery multi).')
@click.option('--show', is_flag=True, help='Show command (celery multi).')
@click.option('--use-command-runner', is_flag=True, default=False, help='Use command runner to run the command.')
@click.option('--without-gossip', is_flag=True)
@click.option('--without-mingle', is_flag=True)
@click.option('--without-heartbeat', is_flag=True)
def worker(hostname, concurrency, reload, queue, pool, quiet, loglevel, check, dev, stop, show, use_command_runner, without_gossip, without_mingle, without_heartbeat):  # noqa: E501
	"""Run a worker."""

	# Check Celery addon is installed
	if not ADDONS_ENABLED['worker']:
		console.print(Error(message='Missing worker addon: please run "secator install addons worker".'))
		sys.exit(1)

	# Check broken / backend addon is installed
	broker_protocol = CONFIG.celery.broker_url.split('://')[0]
	backend_protocol = CONFIG.celery.result_backend.split('://')[0]
	if CONFIG.celery.broker_url and \
	   (broker_protocol == 'redis' or backend_protocol == 'redis') and \
	   not ADDONS_ENABLED['redis']:
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
	if quiet:
		celery += ' --quiet'

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
	cmd += f' -l {loglevel}' if loglevel else ''
	cmd += ' --without-mingle' if without_mingle else ''
	cmd += ' --without-gossip' if without_gossip else ''
	cmd += ' --without-heartbeat' if without_heartbeat else ''

	if reload:
		patterns = "celery.py;tasks/*.py;runners/*.py;serializers/*.py;output_types/*.py;hooks/*.py;exporters/*.py"
		cmd = f'watchmedo auto-restart --directory=./ --patterns="{patterns}" --recursive -- {cmd}'

	if use_command_runner:
		ret = Command.execute(cmd, name='secator_worker')
		sys.exit(ret.return_code)
	else:
		console.print(f'[bold red]{cmd}[/]')
		ret = os.system(cmd)
		sys.exit(os.waitstatus_to_exitcode(ret))


#-------#
# UTILS #
#-------#


@cli.group(aliases=['u'])
def util():
	"""Run a utility."""
	pass


@util.command()
@click.option('--timeout', type=float, default=3, help='Proxy timeout (in seconds)')
@click.option('--number', '-n', type=int, default=1, help='Number of proxies')
def proxy(timeout, number):
	"""Get random proxies from FreeProxy."""
	import requests
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		sys.exit(1)
	proxy = FreeProxy(timeout=timeout, rand=True, anonym=True)
	proxy_str = 'proxy' if number == 1 else 'proxies'
	console.print(f"Searching for {number} {proxy_str} ...")
	for _ in range(number):
		proxy_ok = False
		attempts = 0
		while not proxy_ok and attempts < 5:
			attempts += 1
			url = proxy.get()
			console.print(f"Testing proxy {url} ...")
			try:
				req = requests.get('https://httpbin.org/ip', proxies={'http': url, 'https': url}, timeout=5)
				if not req.ok:
					continue
			except requests.exceptions.ProxyError:
				continue
			except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
				continue
			proxy_ok = True
			console.print(f'Proxy {url} tested successfully !')
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
			sys.exit(1)
		else:
			console.print(Info(message=f'Detected host IP: {host}'))

	# Download reverse shells JSON from repo
	revshells_json = f'{CONFIG.dirs.revshells}/revshells.json'
	if not os.path.exists(revshells_json) or force:
		if CONFIG.offline_mode:
			console.print(Error(message='Cannot run this command in offline mode'))
			sys.exit(1)
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
	fnames = list(os.listdir(directory))
	if not fnames:
		console.print(Warning(message=f'No payloads found in {directory}.'))
		download_files(CONFIG.payloads.templates, CONFIG.dirs.payloads, CONFIG.offline_mode, 'payload')
		fnames = list(os.listdir(directory))

	console.print(Rule())
	console.print(f'Available payloads in {directory}: ', style='bold yellow')
	fnames.sort()
	for fname in fnames:
		if not host:
			host = detect_host(interface)
			if not host:
				console.print(Error(message=f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of interfaces.'))  # noqa: E501
				return
		console.print(f'{fname} [dim][/]', style='bold magenta')
		console.print(f'wget http://{host}:{port}/{fname}', style='dim italic')
		console.print('')
	console.print(Rule())
	console.print(Info(message=f'[bold yellow]Started HTTP server on port {port}, waiting for incoming connections ...[/]'))  # noqa: E501
	Command.execute(f'{sys.executable} -m http.server {port}', cwd=directory)


@util.command('completion')
@click.option('--shell', type=click.Choice(['bash', 'zsh', 'fish']), default='bash', help='Shell type')
@click.option('--install', is_flag=True, help='Install completion to shell config file')
def completion(shell, install):
	"""Show or install shell completion for secator."""
	# Get completion script
	env_var = '_SECATOR_COMPLETE'
	completion_cmd = f'{env_var}={shell}_source secator'

	try:
		result = subprocess.run(
			completion_cmd,
			shell=True,
			capture_output=True,
			text=True,
			env=os.environ.copy()
		)
		completion_script = result.stdout

		if not completion_script:
			console.print(Error(message=f'Failed to generate completion script for {shell}'))
			sys.exit(1)

	except Exception as e:
		console.print(Error(message=f'Error generating completion: {str(e)}'))
		sys.exit(1)

	if install:
		# Determine shell config file
		shell_configs = {
			'bash': os.path.expanduser('~/.bashrc'),
			'zsh': os.path.expanduser('~/.zshrc'),
			'fish': os.path.expanduser('~/.config/fish/completions/secator.fish')
		}

		config_file = shell_configs.get(shell)
		if not config_file:
			console.print(Error(message=f'Unsupported shell: {shell}'))
			sys.exit(1)

		# For fish, write directly to completion file
		if shell == 'fish':
			os.makedirs(os.path.dirname(config_file), exist_ok=True)
			with open(config_file, 'w') as f:
				f.write(completion_script)
			console.print(Info(message=f'Completion installed to {config_file}'))
		else:
			# For bash/zsh, add eval command to rc file
			eval_line = f'eval "$({env_var}={shell}_source secator)"'

			# Check if already installed
			if os.path.exists(config_file):
				with open(config_file, 'r') as f:
					content = f.read()
				if eval_line in content:
					console.print(Info(message=f'Completion already installed in {config_file}'))
					return

			# Add completion to config file
			with open(config_file, 'a') as f:
				f.write(f'\n# secator shell completion\n{eval_line}\n')
			console.print(Info(message=f'Completion installed to {config_file}'))
			console.print(Warning(message=f'Run "source {config_file}" or restart your shell to enable completion'))
	else:
		# Just print the completion script
		console.print(completion_script)


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
@click.option('--user/--full', is_flag=True, help='Show config (user/full)')
@click.argument('key', required=False)
def config_get(user, key=None):
	"""Get config value."""
	if key is None:
		partial = user and default_config != CONFIG
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


@config.command('unset')
@click.argument('key')
def config_unset(key):
	"""Unset a config value."""
	CONFIG.unset(key)
	config = CONFIG.validate()
	if config:
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
@cli.group(aliases=['ws', 'workspaces'])
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


#----------#
# PROFILES #
#----------#

@cli.group(aliases=['p', 'profiles'])
@click.pass_context
def profile(ctx):
	"""Profiles"""
	pass


@profile.command('list')
def profile_list():
	table = Table()
	table.add_column("Profile name", style="bold gold3")
	table.add_column("Description", overflow='fold')
	table.add_column("Options", overflow='fold')
	for profile in PROFILES:
		opts_str = ', '.join(f'[yellow3]{k}[/]=[dim yellow3]{v}[/]' for k, v in profile.opts.items())
		table.add_row(profile.name, profile.description or '', opts_str)
	console.print(table)


#-------#
# ALIAS #
#-------#

@cli.group(aliases=['a', 'aliases'])
def alias():
	"""Aliases."""
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
		alias_name = alias.split('=')[0]
		if alias.strip().startswith('alias'):
			alias_name = 'un' + alias_name
			aliases_str += alias_name + '\n'
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
	aliases.append('\n# Global commands')
	aliases.append('alias x="secator tasks"')
	aliases.append('alias w="secator workflows"')
	aliases.append('alias s="secator scans"')
	aliases.append('alias wk="secator worker"')
	aliases.append('alias ut="secator util"')
	aliases.append('alias c="secator config"')
	aliases.append('alias ws="secator workspaces"')
	aliases.append('alias p="secator profiles"')
	aliases.append('alias a="secator alias"')
	aliases.append('alias r="secator reports"')
	aliases.append('alias h="secator health"')
	aliases.append('alias i="secator install"')
	aliases.append('alias update="secator update"')
	aliases.append('alias t="secator test"')
	aliases.append('alias cs="secator cheatsheet"')
	aliases.append('\n# Tasks')
	for task in [t for t in discover_tasks()]:
		alias_str = f'alias {task.__name__}="secator task {task.__name__}"'
		if task.__external__:
			alias_str += ' # external'
		aliases.append(alias_str)

	if silent:
		return aliases
	console.print('[bold gold3]:wrench: Aliases:[/]')
	for alias in aliases:
		alias_split = alias.split('=')
		if len(alias_split) != 2:
			console.print(f'[bold magenta]{alias}')
			continue
		alias_name, alias_cmd = alias_split[0].replace('alias ', ''), alias_split[1].replace('"', '')
		if '# external' in alias_cmd:
			alias_cmd = alias_cmd.replace('# external', ' [bold red]# external[/]')
		console.print(f'[bold gold3]{alias_name:<15}[/] [dim]->[/] [bold green]{alias_cmd}[/]')

	return aliases


#--------#
# REPORT #
#--------#


@cli.group(aliases=['r', 'reports'])
def report():
	"""Reports."""
	pass


def process_query(query, fields=None):
	if fields is None:
		fields = []
	otypes = [o.__name__.lower() for o in FINDING_TYPES]
	extractors = []

	# Process fields
	fields_filter = {}
	if fields:
		for field in fields:
			parts = field.split('.')
			if len(parts) == 2:
				_type, field = parts
			else:
				_type = parts[0]
				field = None
			if _type not in otypes:
				console.print(Error(message='Invalid output type: ' + _type))
				sys.exit(1)
			fields_filter[_type] = field

	# No query
	if not query:
		if fields:
			extractors = [{'type': field_type, 'field': field, 'condition': 'True', 'op': 'or'} for field_type, field in fields_filter.items()]  # noqa: E501
		return extractors

	# Get operator
	operator = '||'
	if '&&' in query and '||' in query:
		console.print(Error(message='Cannot mix && and || in the same query'))
		sys.exit(1)
	elif '&&' in query:
		operator = '&&'
	elif '||' in query:
		operator = '||'

	# Process query
	query = query.split(operator)
	for part in query:
		part = part.strip()
		split_part = part.split('.')
		_type = split_part[0]
		if _type not in otypes:
			console.print(Error(message='Invalid output type: ' + _type))
			sys.exit(1)
		if fields and _type not in fields_filter:
			console.print(Warning(message='Type not allowed by --filter field: ' + _type + ' (allowed: ' + ', '.join(fields_filter.keys()) + '). Ignoring extractor.'))  # noqa: E501
			continue
		extractor = {
			'type': _type,
			'condition': part or 'True',
			'op': 'and' if operator == '&&' else 'or'
		}
		field = fields_filter.get(_type)
		if field:
			extractor['field'] = field
		extractors.append(extractor)
	return extractors


@report.command('show')
@click.argument('report_query', required=False)
@click.option('-o', '--output', type=str, default='console', help='Exporters')
@click.option('-r', '--runner-type', type=str, default=None, help='Filter by runner type. Choices: task, workflow, scan')  # noqa: E501
@click.option('-d', '--time-delta', type=str, default=None, help='Keep results newer than time delta. E.g: 26m, 1d, 1y')  # noqa: E501
@click.option('-f', '--format', "_format", type=str, default='', help=f'Format output, comma-separated of: <output_type> or <output_type>.<field>. [bold]Allowed output types[/]: {", ".join(FINDING_TYPES_LOWER)}')  # noqa: E501
@click.option('-q', '--query', type=str, default=None, help='Query results using a Python expression')
@click.option('-w', '-ws', '--workspace', type=str, default=None, help='Filter by workspace name')
@click.option('-u', '--unified', is_flag=True, default=False, help='Show unified results (merge reports and de-duplicates results)')  # noqa: E501
@click.pass_context
def report_show(ctx, report_query, output, runner_type, time_delta, _format, query, workspace, unified):
	"""Show report results and filter on them."""

	# Get report query from piped input
	if ctx.obj['piped_input']:
		report_query = ','.join(sys.stdin.read().splitlines())
		unified = True

	# Get extractors
	extractors = process_query(query, fields=_format.split(',') if _format else [])
	if extractors:
		console.print(':wrench: [bold gold3]Showing query summary[/]')
		op = extractors[0]['op']
		console.print(f':carousel_horse: [bold blue]Op[/] [bold orange3]->[/] [bold green]{op.upper()}[/]')
		for extractor in extractors:
			console.print(f':zap: [bold blue]{extractor["type"].title()}[/] [bold orange3]->[/] [bold green]{extractor["condition"]}[/]', highlight=False)  # noqa: E501

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
	report_query = report_query.split(',') if report_query else []
	load_all_reports = not report_query or any([not Path(p).exists() for p in report_query])  # fuzzy query, need to load all reports  # noqa: E501
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
			if ix == 0:
				console.print(f'\n:wrench: [bold gold3]Loading {len(paths)} reports ...[/]')
			console.print(rf':file_cabinet: Loading {path} \[[bold yellow4]{ix + 1}[/]/[bold yellow4]{len(paths)}[/]] \[results={len(all_results)}]...')  # noqa: E501
		with open(path, 'r') as f:
			try:
				data = loads_dataclass(f.read())
				info = get_info_from_report_path(path)
				runner_type = info.get('type', 'unknowns')[:-1]
				runner.results = flatten(list(data['results'].values()))
				if unified:
					all_results.extend(runner.results)
					continue
				report = Report(runner, title=f"Consolidated report - {current}", exporters=exporters)
				report.build(extractors=extractors if not unified else [], dedupe=unified)
				file_date = get_file_date(path)
				runner_name = data['info']['name']
				if not report.is_empty():
					console.print(
						f'\n{path} ([bold blue]{runner_name}[/] [dim]{runner_type}[/]) ([dim]{file_date}[/]):')
				if report.is_empty():
					if len(paths) == 1:
						console.print(Warning(message='No results in report.'))
					continue
				report.send()
			except json.decoder.JSONDecodeError as e:
				console.print(Error(message=f'Could not load {path}: {str(e)}'))

	if unified:
		console.print(f'\n:wrench: [bold gold3]Building report by crunching {len(all_results)} results ...[/]', end='')
		console.print(' (:coffee: [dim]this can take a while ...[/])')
		runner.results = all_results
		report = Report(runner, title=f"Consolidated report - {current}", exporters=exporters)
		report.build(extractors=extractors, dedupe=True)
		report.send()


@report.command('list')
@click.option('-ws', '-w', '--workspace', type=str)
@click.option('-r', '--runner-type', type=str, default=None, help='Filter by runner type. Choices: task, workflow, scan')  # noqa: E501
@click.option('-d', '--time-delta', type=str, default=None, help='Keep results newer than time delta. E.g: 26m, 1d, 1y')  # noqa: E501
@click.pass_context
def report_list(ctx, workspace, runner_type, time_delta):
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

	# Print paths if piped
	if ctx.obj['piped_output']:
		if not paths:
			console.print(Error(message='No reports found.'))
			return
		for path in paths:
			print(path)
		return

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
		console.print(Info(message=f'Found {len(paths)} reports.'))
	else:
		console.print(Error(message='No reports found.'))


@report.command('export')
@click.argument('json_path', type=str)
@click.option('--output-folder', '-of', type=str)
@click.option('--output', '-o', type=str, required=True)
def report_export(json_path, output_folder, output):
	with open(json_path, 'r') as f:
		data = loads_dataclass(f.read())

	split = json_path.split('/')
	workspace_name = '/'.join(split[:-4]) if len(split) > 4 else '_default'
	runner_instance = DotMap({
		"config": {
			"name": data['info']['name']
		},
		"workspace_name": workspace_name,
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

@cli.command(name='health', aliases=['h'])
@click.option('--json', '-json', 'json_', is_flag=True, default=False, help='JSON lines output')
@click.option('--debug', '-debug', is_flag=True, default=False, help='Debug health output')
@click.option('--strict', '-strict', is_flag=True, default=False, help='Fail if missing tools')
@click.option('--bleeding', '-bleeding', is_flag=True, default=False, help='Check bleeding edge version of tools')
def health(json_, debug, strict, bleeding):
	"""Get health status."""
	tools = discover_tasks()
	upgrade_cmd = ''
	results = []
	messages = []

	# Abort if offline mode is enabled
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		sys.exit(1)

	# Check secator
	console.print(':wrench: [bold gold3]Checking secator ...[/]') if not json_ else None
	info = get_version_info('secator', '-version', 'freelabz/secator')
	info['_type'] = 'core'
	if info['outdated']:
		messages.append(f'secator is outdated (latest:{info["latest_version"]}).')
	results.append(info)
	table = get_health_table()
	contextmanager = Live(table, console=console) if not json_ else nullcontext()
	with contextmanager:
		row = fmt_health_table_row(info)
		table.add_row(*row)

	# Check addons
	console.print('\n:wrench: [bold gold3]Checking addons ...[/]') if not json_ else None
	table = get_health_table()
	contextmanager = Live(table, console=console) if not json_ else nullcontext()
	with contextmanager:
		for addon, installed in ADDONS_ENABLED.items():
			info = {
				'name': addon,
				'version': None,
				'status': 'ok' if installed else 'missing_ok',
				'latest_version': None,
				'installed': installed,
				'location': None
			}
			info['_type'] = 'addon'
			results.append(info)
			row = fmt_health_table_row(info, 'addons')
			table.add_row(*row)
			if json_:
				print(json.dumps(info))

	# Check languages
	console.print('\n:wrench: [bold gold3]Checking languages ...[/]') if not json_ else None
	version_cmds = {'go': 'version', 'python3': '--version', 'ruby': '--version'}
	table = get_health_table()
	contextmanager = Live(table, console=console) if not json_ else nullcontext()
	with contextmanager:
		for lang, version_flag in version_cmds.items():
			info = get_version_info(lang, version_flag)
			row = fmt_health_table_row(info, 'langs')
			table.add_row(*row)
			info['_type'] = 'lang'
			results.append(info)
			if json_:
				print(json.dumps(info))

	# Check tools
	console.print('\n:wrench: [bold gold3]Checking tools ...[/]') if not json_ else None
	table = get_health_table()
	error = False
	contextmanager = Live(table, console=console) if not json_ else nullcontext()
	upgrade_cmd = 'secator install tools'
	with contextmanager:
		for tool in tools:
			if hasattr(tool, 'cmd'):
				info = get_version_info(
					tool.cmd.split(' ')[0],
					tool.version_flag or f'{tool.opt_prefix}version',
					tool.github_handle,
					tool.install_github_version_prefix,
					tool.install_cmd,
					tool.install_version,
					bleeding=bleeding
				)
				info['_name'] = tool.__name__
				info['_type'] = 'tool'
				row = fmt_health_table_row(info, 'tools')
				table.add_row(*row)
				if not info['installed']:
					messages.append(f'{tool.__name__} is not installed.')
					info['next_version'] = tool.install_version
					error = True
				elif info['outdated']:
					msg = 'latest' if bleeding else 'supported'
					message = (
						f'{tool.__name__} is outdated (current:{info["version"]}, {msg}:{info["latest_version"]}).'
					)
					messages.append(message)
					info['upgrade'] = True
					info['next_version'] = info['latest_version']

				elif info['bleeding']:
					msg = 'latest' if bleeding else 'supported'
					message = (
						f'{tool.__name__} is bleeding edge (current:{info["version"]}, {msg}:{info["latest_version"]}).'
					)
					messages.append(message)
					info['downgrade'] = True
					info['next_version'] = info['latest_version']
			else:
				info = {
					'name': tool.__name__,
					'_type': 'python',
					'version': None,
					'status': 'ok',
					'latest_version': None,
					'installed': False,
					'location': None
				}
				row = fmt_health_table_row(info, 'python')
				table.add_row(*row)
			results.append(info)
			if json_:
				print(json.dumps(info))
	console.print('') if not json_ else None

	if not json_ and messages:
		console.print('\n[bold red]Issues found:[/]')
		for message in messages:
			console.print(Warning(message=message))

	# Strict mode
	if strict:
		if error:
			sys.exit(1)
		console.print(Info(message='Strict healthcheck passed !')) if not json_ else None

	# Build upgrade command
	cmds = []
	tool_cmd = ''
	for info in results:
		if info['_type'] == 'core' and info['outdated']:
			cmds.append('secator update')
		elif info['_type'] == 'tool' and info.get('next_version'):
			tool_cmd += f',{info["_name"]}=={info["next_version"]}'

	if tool_cmd:
		tool_cmd = f'secator install tools {tool_cmd.lstrip(",")}'
		cmds.append(tool_cmd)
	upgrade_cmd = ' && '.join(cmds)
	console.print('') if not json_ else None
	if upgrade_cmd:
		console.print(Info(message='Run the following to upgrade secator and tools:')) if not json_ else None
		if json_:
			print(json.dumps({'upgrade_cmd': upgrade_cmd}))
		else:
			print(upgrade_cmd)
	else:
		console.print(Info(message='Everything is up to date !')) if not json_ else None


#------------#
# CHEATSHEET #
#------------#

@cli.command(name='cheatsheet', aliases=['cs'])
def cheatsheet():
	"""Display a cheatsheet of secator commands."""
	from rich.panel import Panel
	from rich import box
	kwargs = {
		'box': box.ROUNDED,
		'title_align': 'left',
		# 'style': 'bold blue3',
		'border_style': 'green',
		'padding': (0, 1, 0, 1),
		'highlight': False,
		'expand': False,
	}
	title_style = 'bold green'

	panel1 = Panel(r"""
[dim bold]:left_arrow_curving_right: Secator basic commands to get you started.[/]

secator [orange3]x[/]      [dim]# list tasks[/]
secator [orange3]w[/]      [dim]# list workflows[/]
secator [orange3]s[/]      [dim]# list scans[/]
secator [orange3]p[/]      [dim]# manage profiles[/]
secator [orange3]r[/]      [dim]# manage reports[/]
secator [orange3]c[/]      [dim]# manage configuration[/]
secator [orange3]ws[/]     [dim]# manage workspaces[/]
secator [orange3]update[/] [dim]# update secator[/]

[dim]# Running tasks, workflows or scans...[/]
secator \[[orange3]x[/]|[orange3]w[/]|[orange3]s[/]] [NAME] [OPTIONS] [INPUTS]   [dim]# run a task ([bold orange3]x[/]), workflow ([bold orange3]w[/]) or scan ([bold orange3]s[/])[/]
secator [orange3]x[/] [red]httpx[/] example.com                 [dim]# run an [bold red]httpx[/] task ([bold orange3]x[/] is for e[bold orange3]x[/]ecute)[/]
secator [orange3]w[/] [red]url_crawl[/] https://example.com     [dim]# run a [bold red]url crawl[/] workflow ([bold orange3]w[/])[/]
secator [orange3]s[/] [red]host[/] example.com                  [dim]# run a [bold red]host[/] scan ([bold orange3]s[/])[/]

[dim]# Show information on tasks, workflows or scans ...[/]
secator s host [blue]-dry[/]                         [dim]# show dry run (show exact commands that will be run)[/]
secator s host [blue]-tree[/]                        [dim]# show config tree (workflows and scans only)[/]
secator s host [blue]-yaml[/]                        [dim]# show config yaml (workflows and scans only)[/]

[dim]# Organize your results (workspace, database)[/]
secator s host [blue]-ws[/] [bright_magenta]prod[/] example.com         [dim]# save results to 'prod' workspace[/]
secator s host [blue]-driver[/] [bright_magenta]mongodb[/] example.com  [dim]# save results to mongodb database[/]

[dim]# Input types are flexible ...[/]
secator s host [cyan]example.com[/]                  [dim]# single input[/]
secator s host [cyan]host1,host2,host3[/]            [dim]# multiple inputs (comma-separated)[/]
secator s host [cyan]hosts.txt[/]                    [dim]# multiple inputs (txt file)[/]
[cyan]cat hosts.txt | [/]secator s host              [dim]# piped inputs[/]

[dim]# Options are mutualized ...[/]
secator s host [blue]-rl[/] [bright_magenta]10[/] [blue]-delay[/] [bright_magenta]1[/] [blue]-proxy[/] [bright_magenta]http://127.0.0.1:9090[/] example.com  [dim]# set rate limit, delay and proxy for all subtasks[/]
secator s host [blue]-pf[/] [bright_magenta]aggressive[/] example.com  [dim]# ... or use a profile to automatically set options[/]

[dim]:point_right: and [bold]YES[/], the above options and inputs work with any scan ([bold orange3]s[/]), workflow ([bold orange3]w[/]), and task ([bold orange3]x[/]), not just the host scan shown here![/]
""",  # noqa: E501
		title=f":shield: [{title_style}]Some basics[/]", **kwargs)

	panel2 = Panel(r"""
[dim bold]:left_arrow_curving_right: Secator aliases are useful to stop typing [bold cyan]secator <something>[/] and focus on what you want to run. Aliases are a must to increase your productivity.[/]

[bold]To enable aliases:[/]

secator alias enable       [dim]# enable aliases[/]
source ~/.secator/.aliases [dim]# load aliases in current shell[/]

[dim]# Now you can use aliases...[/]
a list                                                   [dim]# list all aliases[/]
httpx                                                    [dim]# aliased httpx ![/]
nmap -sV -p 443 --script vulners example.com             [dim]# aliased nmap ![/]
w subdomain_recon                                        [dim]# aliased subdomain_recon ![/]
s domain                                                 [dim]# aliased domain scan ![/]
cat hosts.txt | subfinder | naabu | httpx | w url_crawl  [dim]# pipes to chain tasks ![/]
""",  # noqa: E501
		title=f":shorts: [{title_style}]Aliases[/]", **kwargs)

	panel3 = Panel(r"""
[dim bold]:left_arrow_curving_right: Secator configuration is stored in a YAML file located at [bold cyan]~/.secator/config.yaml[/]. You can edit it manually or use the following commands to get/set values.[/]

c get         [dim]# get config value[/]
c get --user  [dim]# get user config value[/]
c edit        [dim]# edit user config in editor[/]
c set profiles.defaults aggressive                              [dim]# set 'aggressive' profile as default[/]
c set drivers.defaults mongodb                                  [dim]# set mongodb as default driver[/]
c set wordlists.defaults.http https://example.com/wordlist.txt  [dim]# set default wordlist for http fuzzing[/]
""",  # noqa: E501
		title=f":gear: [{title_style}]Configuration[/]", **kwargs)

	panel4 = Panel(r"""
[dim bold]:left_arrow_curving_right: By default, tasks are run sequentially. You can use a worker to run tasks in parallel and massively speed up your scans.[/]

wk                         [dim]# or [bold cyan]secator worker[/] if you don't use aliases ...[/]
httpx testphp.vulnweb.com  [dim]# <-- will run in worker and output results normally[/]

[dim]:question: Want to use a remote worker ?[/]
[dim]:point_right: Spawn a Celery worker on your remote server, a Redis instance and set the following config values to connect to it, both in the worker and locally:[/]
c set celery.result_backend redis://<remote_ip>:6379/0          [dim]# set redis backend[/]
c set celery.broker_url redis://<remote_ip>:6379/0              [dim]# set redis broker[/]
[dim]:point_right: Then, run your tasks, workflows or scans like you would locally ![/]
""",  # noqa: E501
		title=f":zap: [{title_style}]Too slow ? Use a worker[/]", **kwargs)

	panel5 = Panel(r"""
[dim bold]:left_arrow_curving_right: Reports are stored in the [bold cyan]~/.secator/reports[/] directory. You can list, show, filter and export reports using the following commands.[/]

[dim]# List and filter reports...[/]
r list                    [dim]# list all reports[/]
r list [blue]-ws[/] [bright_magenta]prod[/]           [dim]# list reports from the workspace 'prod'[/]
r list [blue]-d[/] [bright_magenta]1h[/]              [dim]# list reports from the last hour[/]

[dim]# Show and filter results...[/]
r show [blue]-q[/] [bright_magenta]"url.status_code not in ['401', '403']"[/] [blue]-o[/] [bright_magenta]txt[/]                                 [dim]# show urls with status 401 or 403, save to txt file[/]
r show tasks/10,tasks/11 [blue]-q[/] [bright_magenta]"tag.match and 'signup.php' in tag.match"[/] [blue]--unified[/] [blue]-o[/] [bright_magenta]json[/]  [dim]# show tags with targets matching 'signup.php' from tasks 10 and 11[/]
""",  # noqa: E501
		title=f":file_cabinet: [{title_style}]Digging into reports[/]", **kwargs)

	panel6 = Panel(r"""
[dim bold]:left_arrow_curving_right: Commands to manage secator installation.[/]

update [dim]# update secator to the latest version[/]

[dim]:point_right: Tools are automatically installed when first running a task, workflow or scan, but you can still install them manually.[/]
i tools httpx    [dim]# install tool 'httpx'[/]
i tools          [dim]# install all tools[/]

[dim]:point_right: Addons are optional dependencies required to enable certain features.[/]
i addon redis    [dim]# install addon 'redis'[/]
i addon gcs      [dim]# install addon 'gcs'[/]
i addon worker   [dim]# install addon 'worker'[/]
i addon gdrive   [dim]# install addon 'gdrive'[/]
i addon mongodb  [dim]# install addon 'mongodb'[/]
""",  # noqa: E501
		title=f":wrench: [{title_style}]Updates[/]", **kwargs)

	panel7 = Panel(r"""
[dim bold]:left_arrow_curving_right: Some useful scans and workflows we use day-to-day for recon.[/]

[orange3]:warning: Don't forget to add [bold blue]-dry[/] or [bold blue]-tree[/] before running your scans to see what will be done ![/]

[bold orange3]:trophy: Domain recon + Subdomain recon + Port scanning + URL crawl + URL vulns (XSS, SQLi, RCE, ...)[/]
s domain <DOMAIN>                [dim]# light[/]
s domain <DOMAIN> -pf all_ports  [dim]# light + full port scan[/]
s domain <DOMAIN> -pf full       [dim]# all features (full port scan, nuclei, pattern hunting, headless crawling, screenshots, etc.)[/]
s domain <DOMAIN> -pf passive    [dim]# passive (0 requests to targets)[/]

[bold orange3]:trophy: Subdomain recon[/]
w subdomain_recon <DOMAIN>                         [dim]# standard[/]
w subdomain_recon <DOMAIN> -brute-dns -brute-http  [dim]# bruteforce subdomains (DNS queries + HTTP Host header fuzzing)[/]
w subdomain_recon <DOMAIN> -pf passive             [dim]# passive (0 requests to targets)[/]

[bold orange3]:trophy: URL fuzzing[/]
w url_fuzz <URL>                                   [dim]# standard fuzzing (ffuf)[/]
w url_fuzz <URL> -hs                               [dim]# hunt secrets in HTTP responses (trufflehog)[/]
w url_fuzz <URL> -mc 200,301 -fs 204               [dim]# match 200, 301, and filter size equal to 204 bytes[/]
w url_fuzz -fuzzers ffuf,dirsearch <URL> -w <URL>  [dim]# choose fuzzers, use remote wordlist[/]

[bold orange3]:trophy: Vuln and secret scan:[/]
w code_scan <PATH>                                 [dim]# on a local path or git repo[/]
w code_scan https://github.com/freelabz/secator    [dim]# on a github repo[/]
w code_scan https://github.com/freelabz            [dim]# on a github org (all repos)[/]

[bold orange3]:trophy: Hunt user accounts[/]
w user_hunt elonmusk                               [dim]# by username[/]
w user_hunt elonmusk@tesla.com                     [dim]# by email[/]

[bold orange3]:trophy: Custom pipeline to find HTTP servers and fuzz alive ones[/]
subfinder vulnweb.com | naabu | httpx | ffuf -mc 200,301 -recursion
""",  # noqa: E501
		title=f":trophy: [{title_style}]Quick wins[/]", **kwargs)

	console.print(panel1)
	console.print(panel2)
	console.print(panel3)
	console.print(panel4)
	console.print(panel5)
	console.print(panel6)
	console.print(panel7)


#---------#
# INSTALL #
#---------#


def run_install(title=None, cmd=None, packages=None, next_steps=None):
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		sys.exit(1)
	# with console.status(f'[bold yellow] Installing {title}...'):
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


@cli.group(aliases=['i'])
def install():
	"""Install langs, tools and addons."""
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
			'Run [bold green4]secator config set addons.gcs.bucket_name <VALUE>[/].',
			'Run [bold green4]secator config set addons.gcs.credentials_path <VALUE>[/]. [dim](optional if using default credentials)[/]',  # noqa: E501
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


@addons.command('vulners')
def install_vulners():
	"Install Vulners addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[vulners]',
		title='Vulners addon',
		next_steps=[
			'Run [bold green4]secator config set addons.vulners.api_key <API_KEY>[/].',
			'Set [bold green4]secator config set providers.cve_default_provider vulners[/].',
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
@click.option('--cleanup', is_flag=True, default=False, help='Clean up tools after installation.')
@click.option('--fail-fast', is_flag=True, default=False, help='Fail fast if any tool fails to install.')
def install_tools(cmds, cleanup, fail_fast):
	"""Install supported tools."""
	if CONFIG.offline_mode:
		console.print(Error(message='Cannot run this command in offline mode.'))
		sys.exit(1)
	tools = []
	if cmds is not None:
		cmds = cmds.split(',')
		for cmd in cmds:
			if '==' in cmd:
				cmd, version = tuple(cmd.split('=='))
			else:
				cmd, version = cmd, None
			cls = next((cls for cls in discover_tasks() if cls.__name__ == cmd), None)
			if cls:
				if version:
					if cls.install_version and cls.install_version.startswith('v') and not version.startswith('v'):
						version = f'v{version}'
					cls.install_version = version
				tools.append(cls)
			else:
				console.print(Warning(message=f'Tool {cmd} is not supported or inexistent.'))
	else:
		tools = discover_tasks()
	tools.sort(key=lambda x: x.__name__)
	return_code = 0
	if not tools:
		console.print(Error(message='No tools found for installing.'))
		return
	for ix, cls in enumerate(tools):
		# with console.status(f'[bold yellow][{ix + 1}/{len(tools)}] Installing {cls.__name__} ...'):
		status = ToolInstaller.install(cls)
		if not status.is_ok():
			return_code = 1
			if fail_fast:
				sys.exit(return_code)
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
	"""Update to latest version."""
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
		for cls in discover_tasks():
			base_cmd = getattr(cls, 'cmd', None)
			if not base_cmd:
				continue
			cmd = base_cmd.split(' ')[0]
			version_flag = cls.get_version_flag()
			info = get_version_info(cmd, version_flag, cls.github_handle, cls.install_github_version_prefix)
			if not info['installed'] or info['outdated'] or not info['latest_version']:
				# with console.status(f'[bold yellow]Installing {cls.__name__} ...'):
				status = ToolInstaller.install(cls)
				if not status.is_ok():
					return_code = 1
		sys.exit(return_code)


#------#
# TEST #
#------#


@cli.group(cls=OrderedGroup)
def test():
	"""[dim]Run tests (dev build only)."""
	if not DEV_PACKAGE:
		console.print(Error(message='You MUST use a development version of secator to run tests.'))
		sys.exit(1)
	if not ADDONS_ENABLED['dev']:
		console.print(Error(message='Missing dev addon: please run "secator install addons dev"'))
		sys.exit(1)
	pass


def run_test(cmd, name=None, exit=True, verbose=False, use_os_system=False):
	"""Run a test and return the result.

	Args:
		cmd (str): Command to run.
		name (str, optional): Name of the test.
		exit (bool, optional): Exit after running the test with the return code.
		verbose (bool, optional): Print verbose output.
		use_os_system (bool, optional): Use os.system to run the command.

	Returns:
		Return code of the test.
	"""
	cmd_name = name + ' tests' if name else 'tests'
	if use_os_system:
		console.print(f'[bold red]{cmd}[/]')
		if not verbose:
			cmd += ' >/dev/null 2>&1'
		ret = os.system(cmd)
		if exit:
			sys.exit(os.waitstatus_to_exitcode(ret))
		return ret
	else:
		result = Command.execute(cmd, name=cmd_name, cwd=ROOT_FOLDER, quiet=not verbose)
		if name:
			if result.return_code == 0:
				console.print(f':tada: {name.capitalize()} tests passed !', style='bold green')
			else:
				console.print(f':x: {name.capitalize()} tests failed !', style='bold red')
		if exit:
			sys.exit(result.return_code)
		return result.return_code


@test.command()
@click.option('--linter', '-l', type=click.Choice(['flake8', 'ruff', 'isort', 'pylint']), default='flake8', help='Linter to use')  # noqa: E501
def lint(linter):
	"""Run lint tests."""
	opts = ''
	if linter == 'pylint':
		opts = '--indent-string "\t" --max-line-length 160 --disable=R,C,W'
	elif linter == 'ruff':
		opts = ' check'
	cmd = f'{sys.executable} -m {linter} {opts} secator/'
	run_test(cmd, 'lint', verbose=True, use_os_system=True)


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
@click.option('--no-coverage', is_flag=True, help='Disable coverage')
def unit(tasks, workflows, scans, test, no_coverage):
	"""Run unit tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_OFFLINE_MODE'] = "1"
	os.environ['SECATOR_HTTP_STORE_RESPONSES'] = '0'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	if not test:
		if tasks:
			test = 'test_tasks'
		elif workflows:
			test = 'test_workflows'
		elif scans:
			test = 'test_scans'

	import shutil
	shutil.rmtree('/tmp/.secator', ignore_errors=True)
	if not no_coverage:
		cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.unit -m pytest -s -vv tests/unit --durations=5'  # noqa: E501
	else:
		cmd = f'{sys.executable} -m pytest -s -vv tests/unit --durations=5'
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'unit', verbose=True, use_os_system=True)


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
@click.option('--no-cleanup', '-nc', is_flag=True, help='Do not perform cleanup (keep lab running, faster for relaunching tests)')  # noqa: E501
def integration(tasks, workflows, scans, test, no_cleanup):
	"""Run integration tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'
	os.environ['TEST_NO_CLEANUP'] = '1' if no_cleanup else '0'

	if not test:
		if tasks:
			test = 'test_tasks'
		elif workflows:
			test = 'test_workflows'
		elif scans:
			test = 'test_scans'

	import shutil
	shutil.rmtree('/tmp/.secator', ignore_errors=True)

	cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.integration -m pytest -s -vv tests/integration --durations=5'  # noqa: E501
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'integration', verbose=True, use_os_system=True)


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
def template(tasks, workflows, scans, test):
	"""Run integration tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/.secator'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	if not test:
		if tasks:
			test = 'test_tasks'
		elif workflows:
			test = 'test_workflows'
		elif scans:
			test = 'test_scans'

	import shutil
	shutil.rmtree('/tmp/.secator', ignore_errors=True)

	cmd = f'{sys.executable} -m coverage run --omit="*test*" --data-file=.coverage.templates -m pytest -s -vv tests/template --durations=5'  # noqa: E501
	if test:
		test_str = ' or '.join(test.split(','))
		cmd += f' -k "{test_str}"'
	run_test(cmd, 'template', verbose=True)


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
	run_test(cmd, 'performance', verbose=True, use_os_system=True)


@test.command()
@click.argument('name', type=str)
@click.option('--verbose', '-v', is_flag=True, default=False, help='Print verbose output')
@click.option('--check', '-c', is_flag=True, default=False, help='Check task semantics only (no unit + integration tests)')  # noqa: E501
@click.option('--system-exit', '-e', is_flag=True, default=True, help='Exit with system exit code')
def task(name, verbose, check, system_exit):
	"""Test a single task for semantics errors, and run unit + integration tests."""
	console.print(f'[bold gold3]:wrench: Testing task {name} ...[/]')
	task = [task for task in discover_tasks() if task.__name__ == name.strip()]
	warnings = []
	errors = []
	exit_code = 0

	# Check if task is correctly registered
	check_test(
		len(task) == 1,
		'Check task is registered',
		'Task is not registered. Please check your task name.',
		errors
	)
	if errors:
		if system_exit:
			sys.exit(1)
		else:
			return False

	task = task[0]
	task_name = task.__name__

	# Check task command is set
	cmd = getattr(task, 'cmd', None)
	if cmd:
		check_test(
			task.cmd,
			'Check task command is set (cls.cmd)',
			'Task has no cmd attribute.',
			errors
		)
	if errors:
		if system_exit:
			sys.exit(1)
		else:
			return False

	# Run install
	if hasattr(task, 'get_version_info'):
		cmd = f'secator install tools {task_name}'
		ret_code = Command.execute(cmd, name='install', quiet=not verbose, cwd=ROOT_FOLDER)
		version_info = task.get_version_info()
		if verbose:
			console.print(f'Version info:\n{version_info}')
		status = version_info['status']
		check_test(
			version_info['installed'],
			'Check task is installed',
			'Failed to install command. Fix your installation command.',
			errors
		)
		check_test(
			any(cmd for cmd in [task.install_pre, task.install_cmd, task.github_handle]),
			'Check task installation command is defined',
			'Task has no installation command. Please define one or more of the following class attributes: `install_pre`, `install_cmd`, `install_post`, `github_handle`.',  # noqa: E501
			errors
		)
		check_test(
			version_info['version'],
			'Check task version can be fetched',
			'Failed to detect current version. Consider updating your `version_flag` class attribute.',
			warnings,
			warn=True
		)
		check_test(
			status != 'latest unknown',
			'Check latest version',
			'Failed to detect latest version.',
			warnings,
			warn=True
		)
		check_test(
			not version_info['outdated'],
			'Check task version is up to date',
			f'Task is not up to date (current version: {version_info["version"]}, latest: {version_info["latest_version"]}). Consider updating your `install_version` class attribute.',  # noqa: E501
			warnings,
			warn=True
		)

	# Run task-specific tests
	check_test(
		task.__doc__,
		'Check task description is set (cls.__doc__)',
		'Task has no description (class docstring).',
		errors
	)
	check_test(
		task.input_types,
		'Check task input type is set (cls.input_type)',
		'Task has no input_type attribute.',
		warnings,
		warn=True
	)
	check_test(
		task.output_types,
		'Check task output types is set (cls.output_types)',
		'Task has no output_types attribute. Consider setting some so that secator can load your task outputs.',
		warnings,
		warn=True
	)
	if hasattr(task, 'install_version'):
		check_test(
			task.install_version,
			'Check task install_version is set (cls.install_version)',
			'Task has no install_version attribute. Consider setting it to pin the tool version and ensure it does not break in the future.',  # noqa: E501
			warnings,
			warn=True
		)

	if not check:

		# Run unit tests
		cmd = f'secator test unit --tasks {name}'
		ret_code = run_test(cmd, exit=False, verbose=verbose)
		check_test(
			ret_code == 0,
			'Check unit tests pass',
			'Unit tests failed.',
			errors
		)

		# Run integration tests
		cmd = f'secator test integration --tasks {name}'
		ret_code = run_test(cmd, exit=False, verbose=verbose)
		check_test(
			ret_code == 0,
			'Check integration tests pass',
			'Integration tests failed.',
			errors
		)

	# Exit with exit code
	exit_code = 1 if len(errors) > 0 else 0
	if exit_code == 0:
		console.print(f':tada: Task {name} tests passed !', style='bold green')
	else:
		console.print('\n[bold gold3]Errors:[/]')
		for error in errors:
			console.print(error)
		console.print(Error(message=f'Task {name} tests failed. Please fix the issues above.'))

	if warnings:
		console.print('\n[bold gold3]Warnings:[/]')
		for warning in warnings:
			console.print(warning)

	console.print("\n")
	if system_exit:
		sys.exit(exit_code)
	else:
		return True if exit_code == 0 else False


@test.command()
@click.pass_context
@click.option('--check', '-c', is_flag=True, default=False, help='Check task semantics only (no unit + integration tests)')  # noqa: E501
@click.option('--verbose', '-v', is_flag=True, default=False, help='Print verbose output')
def tasks(ctx, check, verbose):
	"""Test all tasks for semantics errors, and run unit + integration tests."""
	results = []
	for cls in discover_tasks():
		success = ctx.invoke(task, name=cls.__name__, verbose=verbose, check=check, system_exit=False)
		results.append(success)

	if any(not success for success in results):
		console.print(Error(message='Tasks checks failed. Please check the output for more details.'))
		sys.exit(1)
	console.print(Info(message='All tasks checks passed.'))
	sys.exit(0)


def check_test(condition, message, fail_message, results=[], warn=False):
	console.print(f'[bold magenta]:zap: {message} ...[/]', end='')
	if not condition:
		if not warn:
			error = Error(message=fail_message)
			console.print(' [bold red]FAILED[/]', style='dim')
			results.append(error)
		else:
			warning = Warning(message=fail_message)
			console.print(' [bold yellow]WARNING[/]', style='dim')
			results.append(warning)
	else:
		console.print(' [bold green]OK[/]', style='dim')
	return True


@test.command()
@click.option('--unit-only', '-u', is_flag=True, default=False, help='Only generate coverage for unit tests')
@click.option('--integration-only', '-i', is_flag=True, default=False, help='Only generate coverage for integration tests')  # noqa: E501
@click.option('--template-only', '-t', is_flag=True, default=False, help='Only generate coverage for template tests')  # noqa: E501
def coverage(unit_only, integration_only, template_only):
	"""Run coverage combine + coverage report."""
	cmd = f'{sys.executable} -m coverage report -m --omit=*/site-packages/*,*/tests/*,*/templates/*'
	if unit_only:
		cmd += ' --data-file=.coverage.unit'
	elif integration_only:
		cmd += ' --data-file=.coverage.integration'
	elif template_only:
		cmd += ' --data-file=.coverage.template'
	else:
		Command.execute(f'{sys.executable} -m coverage combine --keep', name='coverage combine', cwd=ROOT_FOLDER)
	run_test(cmd, 'coverage', use_os_system=True)

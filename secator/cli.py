import json
import os
import re
import shutil
import sys

from pathlib import Path

import rich_click as click
from dotmap import DotMap
from fp.fp import FreeProxy
from jinja2 import Template
from rich.live import Live
from rich.markdown import Markdown
from rich.rule import Rule

from secator.config import CONFIG, ROOT_FOLDER, Config, default_config, config_path
from secator.template import TemplateLoader
from secator.decorators import OrderedGroup, register_runner
from secator.definitions import ADDONS_ENABLED, ASCII, DEV_PACKAGE, OPT_NOT_SUPPORTED, VERSION
from secator.installer import ToolInstaller, fmt_health_table_row, get_health_table, get_version_info
from secator.rich import console
from secator.runners import Command, Runner
from secator.report import Report
from secator.serializers.dataclass import loads_dataclass
from secator.utils import debug, detect_host, discover_tasks, flatten, print_results_table, print_version

click.rich_click.USE_RICH_MARKUP = True

ALL_TASKS = discover_tasks()
ALL_CONFIGS = TemplateLoader.load_all()
ALL_WORKFLOWS = ALL_CONFIGS.workflow
ALL_SCANS = ALL_CONFIGS.scan


#-----#
# CLI #
#-----#

@click.group(cls=OrderedGroup, invoke_without_command=True)
@click.option('--version', '-version', is_flag=True, default=False)
@click.pass_context
def cli(ctx, version):
	"""Secator CLI."""
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
def task():
	"""Run a task."""
	pass


for cls in ALL_TASKS:
	config = DotMap({'name': cls.__name__, 'type': 'task'})
	register_runner(task, config)

#----------#
# WORKFLOW #
#----------#


@cli.group(cls=OrderedGroup, aliases=['w'])
def workflow():
	"""Run a workflow."""
	pass


for config in sorted(ALL_WORKFLOWS, key=lambda x: x['name']):
	register_runner(workflow, config)


#------#
# SCAN #
#------#

@cli.group(cls=OrderedGroup, aliases=['s'])
def scan():
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
	if not ADDONS_ENABLED['worker']:
		console.print('[bold red]Missing worker addon: please run [bold green4]secator install addons worker[/][/].')
		sys.exit(1)
	broker_protocol = CONFIG.celery.broker_url.split('://')[0]
	backend_protocol = CONFIG.celery.result_backend.split('://')[0]
	if CONFIG.celery.broker_url:
		if (broker_protocol == 'redis' or backend_protocol == 'redis') and not ADDONS_ENABLED['redis']:
			console.print('[bold red]Missing `redis` addon: please run [bold green4]secator install addons redis[/][/].')
			sys.exit(1)
	from secator.celery import app, is_celery_worker_alive
	debug('conf', obj=dict(app.conf), obj_breaklines=True, sub='celery.app.conf', level=4)
	debug('registered tasks', obj=list(app.tasks.keys()), obj_breaklines=True, sub='celery.tasks', level=4)
	if check:
		is_celery_worker_alive()
		return
	if not queue:
		queue = 'io,cpu,' + ','.join([r['queue'] for r in app.conf.task_routes.values()])
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
	if pool:
		cmd += f' -P {pool}'
	if concurrency:
		cmd += f' -c {concurrency}'
	if reload:
		patterns = "celery.py;tasks/*.py;runners/*.py;serializers/*.py;output_types/*.py;hooks/*.py;exporters/*.py"
		cmd = f'watchmedo auto-restart --directory=./ --patterns="{patterns}" --recursive -- {cmd}'
	Command.execute(cmd, name='secator worker')


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
		console.print('[bold red]Cannot run this command in offline mode.[/]')
		return
	proxy = FreeProxy(timeout=timeout, rand=True, anonym=True)
	for _ in range(number):
		url = proxy.get()
		print(url)


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
			console.print(
				f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of available interfaces.',
				style='bold red')
			return
		else:
			console.print(f'[bold green]Detected host IP: [bold orange1]{host}[/].[/]')

	# Download reverse shells JSON from repo
	revshells_json = f'{CONFIG.dirs.revshells}/revshells.json'
	if not os.path.exists(revshells_json) or force:
		if CONFIG.offline_mode:
			console.print('[bold red]Cannot run this command in offline mode.[/]')
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
		command = shell['command']
		alias = shell['alias']
		name = shell['name']
		command_str = Template(command).render(ip=host, port=port, shell='bash')
		console.print(Rule(f'[bold gold3]{alias}[/] - [bold red]{name} REMOTE SHELL', style='bold red', align='left'))
		lang = shell.get('lang') or 'sh'
		if len(command.splitlines()) == 1:
			console.print()
			print(f'\033[0;36m{command_str}')
		else:
			md = Markdown(f'```{lang}\n{command_str}\n```')
			console.print(md)
			console.print(f'Save this script as rev.{lang} and run it on your target', style='dim italic')
		console.print()
		console.print(Rule(style='bold red'))

	if listen:
		console.print(f'Starting netcat listener on port {port} ...', style='bold gold3')
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
				console.print(
					f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of interfaces.',
					style='bold red')
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
			console.print(f'Removed existing {output_cast_path}', style='bold green')

		with console.status('[bold gold3]Recording with asciinema ...[/]'):
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
		console.print(f'Generated {output_gif_path}', style='bold green')


@util.group('build')
def build():
	"""Build secator."""
	if not DEV_PACKAGE:
		console.print('[bold red]You MUST use a development version of secator to make builds.[/]')
		sys.exit(1)
	pass


@build.command('pypi')
def build_pypi():
	"""Build secator PyPI package."""
	if not ADDONS_ENABLED['build']:
		console.print('[bold red]Missing build addon: please run [bold green4]secator install addons build[/][/]')
		sys.exit(1)
	with console.status('[bold gold3]Building PyPI package...[/]'):
		ret = Command.execute(f'{sys.executable} -m hatch build', name='hatch build', cwd=ROOT_FOLDER)
		sys.exit(ret.return_code)


@build.command('docker')
@click.option('--tag', '-t', type=str, default=None, help='Specific tag')
@click.option('--latest', '-l', is_flag=True, default=False, help='Latest tag')
def build_docker(tag, latest):
	"""Build secator Docker image."""
	if not tag:
		tag = VERSION if latest else 'dev'
	cmd = f'docker build -t freelabz/secator:{tag}'
	if latest:
		cmd += ' -t freelabz/secator:latest'
	cmd += ' .'
	with console.status('[bold gold3]Building Docker image...[/]'):
		ret = Command.execute(cmd, name='docker build', cwd=ROOT_FOLDER)
		sys.exit(ret.return_code)


@util.group('publish')
def publish():
	"""Publish secator."""
	if not DEV_PACKAGE:
		console.print('[bold red]You MUST use a development version of secator to publish builds.[/]')
		sys.exit(1)
	pass


@publish.command('pypi')
def publish_pypi():
	"""Publish secator PyPI package."""
	if not ADDONS_ENABLED['build']:
		console.print('[bold red]Missing build addon: please run [bold green4]secator install addons build[/][/]')
		sys.exit(1)
	os.environ['HATCH_INDEX_USER'] = '__token__'
	hatch_token = os.environ.get('HATCH_INDEX_AUTH')
	if not hatch_token:
		console.print('[bold red]Missing PyPI auth token (HATCH_INDEX_AUTH env variable).')
		sys.exit(1)
	with console.status('[bold gold3]Publishing PyPI package...[/]'):
		ret = Command.execute(f'{sys.executable} -m hatch publish', name='hatch publish', cwd=ROOT_FOLDER)
		sys.exit(ret.return_code)


@publish.command('docker')
@click.option('--tag', '-t', default=None, help='Specific tag')
@click.option('--latest', '-l', is_flag=True, default=False, help='Latest tag')
def publish_docker(tag, latest):
	"""Publish secator Docker image."""
	if not tag:
		tag = VERSION if latest else 'dev'
	cmd = f'docker push freelabz/secator:{tag}'
	cmd2 = 'docker push freelabz/secator:latest'
	with console.status(f'[bold gold3]Publishing Docker image {tag}...[/]'):
		ret = Command.execute(cmd, name=f'docker push ({tag})', cwd=ROOT_FOLDER)
		if latest:
			ret2 = Command.execute(cmd2, name='docker push (latest)')
			sys.exit(max(ret.return_code, ret2.return_code))
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
		console.print('[bold red]:x: Invalid config, not saving it.')


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


#--------#
# REPORT #
#--------#


@cli.group(aliases=['r'])
def report():
	"""View previous reports."""
	pass


@report.command('show')
@click.argument('json_path')
@click.option('-o', '--output', type=str, default='console', help='Format')
@click.option('-e', '--exclude-fields', type=str, default='', help='List of fields to exclude (comma-separated)')
def report_show(json_path, output, exclude_fields):
	"""Show a JSON report."""
	with open(json_path, 'r') as f:
		report = loads_dataclass(f.read())
		results = flatten(list(report['results'].values()))
	if output == 'console':
		for result in results:
			console.print(result)
	elif output == 'table':
		exclude_fields = exclude_fields.split(',')
		print_results_table(
			results,
			title=report['info']['title'],
			exclude_fields=exclude_fields)


@report.command('list')
@click.option('-ws', '--workspace', type=str)
def report_list(workspace):
	reports_dir = CONFIG.dirs.reports
	json_reports = reports_dir.glob("**/**/report.json")
	ws_reports = {}
	for path in json_reports:
		ws, runner, number = str(path).split('/')[-4:-1]
		if ws not in ws_reports:
			ws_reports[ws] = []
		with open(path, 'r') as f:
			try:
				content = json.loads(f.read())
				data = {'path': path, 'name': content['info']['name'], 'runner': runner}
				ws_reports[ws].append(data)
			except json.JSONDecodeError as e:
				console.print(f'[bold red]Could not load {path}: {str(e)}')

	for ws in ws_reports:
		if workspace and not ws == workspace:
			continue
		console.print(f'[bold gold3]{ws}:')
		for data in sorted(ws_reports[ws], key=lambda x: x['path']):
			console.print(f'   • {data["path"]} ([bold blue]{data["name"]}[/] [dim]{data["runner"][:-1]}[/])')


@report.command('export')
@click.argument('json_path', type=str)
@click.option('--output-folder', '-of', type=str)
@click.option('-output', '-o', type=str)
def report_export(json_path, output_folder, output):
	with open(json_path, 'r') as f:
		data = loads_dataclass(f.read())
		flatten(list(data['results'].values()))

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
def health(json, debug):
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
		for addon in ['worker', 'google', 'mongodb', 'redis', 'dev', 'trace', 'build']:
			addon_var = ADDONS_ENABLED[addon]
			info = {
				'name': addon,
				'version': None,
				'status': 'ok' if addon_var else 'missing',
				'latest_version': None,
				'installed': addon_var,
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
			cmd = tool.cmd.split(' ')[0]
			version_flag = tool.version_flag or f'{tool.opt_prefix}version'
			version_flag = None if tool.version_flag == OPT_NOT_SUPPORTED else version_flag
			info = get_version_info(cmd, version_flag, tool.install_github_handle)
			row = fmt_health_table_row(info, 'tools')
			table.add_row(*row)
			status['tools'][tool.__name__] = info

	# Print JSON health
	if json:
		import json as _json
		print(_json.dumps(status))

#---------#
# INSTALL #
#---------#


def run_install(cmd, title, next_steps=None):
	if CONFIG.offline_mode:
		console.print('[bold red]Cannot run this command in offline mode.[/]')
		return
	with console.status(f'[bold yellow] Installing {title}...'):
		ret = Command.execute(cmd, cls_attributes={'shell': True}, print_cmd=True, print_line=True)
		if ret.return_code != 0:
			console.print(f':exclamation_mark: Failed to install {title}.', style='bold red')
		else:
			console.print(f':tada: {title.capitalize()} installed successfully !', style='bold green')
			if next_steps:
				console.print('[bold gold3]:wrench: Next steps:[/]')
				for ix, step in enumerate(next_steps):
					console.print(f'   :keycap_{ix}: {step}')
		sys.exit(ret.return_code)


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
	"Install worker addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[worker]',
		title='worker addon',
		next_steps=[
			'Run [bold green4]secator worker[/] to run a Celery worker using the file system as a backend and broker.',
			'Run [bold green4]secator x httpx testphp.vulnweb.com[/] to admire your task running in a worker.',
			'[dim]\[optional][/dim] Run [bold green4]secator install addons redis[/] to setup Redis backend / broker.'
		]
	)


@addons.command('google')
def install_google():
	"Install google addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[google]',
		title='google addon',
		next_steps=[
			'Run [bold green4]secator config set addons.google.credentials_path <VALUE>[/].',
			'Run [bold green4]secator config set addons.google.drive_parent_folder_id <VALUE>[/].',
			'Run [bold green4]secator x httpx testphp.vulnweb.com -o gdrive[/] to send reports to Google Drive.'
		]
	)


@addons.command('mongodb')
def install_mongodb():
	"Install mongodb addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[mongodb]',
		title='mongodb addon',
		next_steps=[
			'[dim]\[optional][/] Run [bold green4]docker run --name mongo -p 27017:27017 -d mongo:latest[/] to run a local MongoDB instance.',  # noqa: E501
			'Run [bold green4]secator config set addons.mongodb.url mongodb://<URL>[/].',
			'Run [bold green4]secator x httpx testphp.vulnweb.com -driver mongodb[/] to save results to MongoDB.'
		]
	)


@addons.command('redis')
def install_redis():
	"Install redis addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[redis]',
		title='redis addon',
		next_steps=[
			'[dim]\[optional][/] Run [bold green4]docker run --name redis -p 6379:6379 -d redis[/] to run a local Redis instance.',  # noqa: E501
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
		title='dev addon',
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
		cmd='wget -O - https://raw.githubusercontent.com/freelabz/secator/main/scripts/install_ruby.sh | sudo sh',
		title='Ruby'
	)


@install.command('tools')
@click.argument('cmds', required=False)
def install_tools(cmds):
	"""Install supported tools."""
	if CONFIG.offline_mode:
		console.print('[bold red]Cannot run this command in offline mode.[/]')
		return
	if cmds is not None:
		cmds = cmds.split(',')
		tools = [cls for cls in ALL_TASKS if cls.__name__ in cmds]
	else:
		tools = ALL_TASKS

	for ix, cls in enumerate(tools):
		with console.status(f'[bold yellow][{ix}/{len(tools)}] Installing {cls.__name__} ...'):
			ToolInstaller.install(cls)
		console.print()


@install.command('cves')
@click.option('--force', is_flag=True)
def install_cves(force):
	"""Install CVEs (enables passive vulnerability search)."""
	if CONFIG.offline_mode:
		console.print('[bold red]Cannot run this command in offline mode.[/]')
		return
	cve_json_path = f'{CONFIG.dirs.cves}/circl-cve-search-expanded.json'
	if not os.path.exists(cve_json_path) or force:
		with console.status('[bold yellow]Downloading zipped CVEs from cve.circl.lu ...[/]'):
			Command.execute('wget https://cve.circl.lu/static/circl-cve-search-expanded.json.gz', cwd=CONFIG.dirs.cves)
		with console.status('[bold yellow]Unzipping CVEs ...[/]'):
			Command.execute(f'gunzip {CONFIG.dirs.cves}/circl-cve-search-expanded.json.gz', cwd=CONFIG.dirs.cves)
	with console.status(f'[bold yellow]Installing CVEs to {CONFIG.dirs.cves} ...[/]'):
		with open(cve_json_path, 'r') as f:
			for line in f:
				data = json.loads(line)
				cve_id = data['id']
				cve_path = f'{CONFIG.dirs.cves}/{cve_id}.json'
				with open(cve_path, 'w') as f:
					f.write(line)
				console.print(f'CVE saved to {cve_path}')
	console.print(':tada: CVEs installed successfully !', style='bold green')


#--------#
# UPDATE #
#--------#

@cli.command('update')
def update():
	"""[dim]Update to latest version.[/]"""
	if CONFIG.offline_mode:
		console.print('[bold red]Cannot run this command in offline mode.[/]')
		return
	info = get_version_info('secator', github_handle='freelabz/secator', version=VERSION)
	latest_version = info['latest_version']
	if info['status'] == 'latest':
		console.print(f'[bold green]secator is already at the newest version {latest_version}[/] !')
		sys.exit(0)
	console.print(f'[bold gold3]:wrench: Updating secator from {VERSION} to {latest_version} ...[/]')
	if 'pipx' in sys.executable:
		Command.execute(f'pipx install secator=={latest_version} --force')
	else:
		Command.execute(f'pip install secator=={latest_version}')


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
		console.print('[bold red]You MUST use a development version of secator to run tests.[/]')
		sys.exit(1)
	if not ADDONS_ENABLED['dev']:
		console.print('[bold red]Missing dev addon: please run [bold green4]secator install addons dev[/][/]')
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
@click.option('--debug', '-d', type=int, default=0, help='Add debug information')
def unit(tasks, workflows, scans, test, debug=False):
	"""Run unit tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DEBUG_LEVEL'] = str(debug)
	os.environ['SECATOR_HTTP_STORE_RESPONSES'] = '0'
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'

	cmd = f'{sys.executable} -m coverage run --omit="*test*" -m unittest'
	if test:
		if not test.startswith('tests.unit'):
			test = f'tests.unit.{test}'
		cmd += f' {test}'
	else:
		cmd += ' discover -v tests.unit'
	run_test(cmd, 'unit')


@test.command()
@click.option('--tasks', type=str, default='', help='Secator tasks to test (comma-separated)')
@click.option('--workflows', type=str, default='', help='Secator workflows to test (comma-separated)')
@click.option('--scans', type=str, default='', help='Secator scans to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secator test to run')
@click.option('--debug', '-d', type=int, default=0, help='Add debug information')
def integration(tasks, workflows, scans, test, debug):
	"""Run integration tests."""
	os.environ['TEST_TASKS'] = tasks or ''
	os.environ['TEST_WORKFLOWS'] = workflows or ''
	os.environ['TEST_SCANS'] = scans or ''
	os.environ['SECATOR_DEBUG_LEVEL'] = str(debug)
	os.environ['SECATOR_RUNNERS_SKIP_CVE_SEARCH'] = '1'
	os.environ['SECATOR_DIRS_DATA'] = '/tmp/data'
	os.environ['SECATOR_DIRS_REPORTS'] = '/tmp/data/reports'
	os.environ['SECATOR_DIRS_CELERY'] = '/tmp/celery'
	os.environ['SECATOR_DIRS_CELERY_DATA'] = '/tmp/celery/data'
	os.environ['SECATOR_DIRS_CELERY_RESULTS'] = '/tmp/celery/results'
	import shutil
	for path in ['/tmp/data', '/tmp/celery', '/tmp/celery/data', '/tmp/celery/results']:
		shutil.rmtree(path, ignore_errors=True)

	cmd = f'{sys.executable} -m unittest'
	if test:
		if not test.startswith('tests.integration'):
			test = f'tests.integration.{test}'
		cmd += f' {test}'
	else:
		cmd += ' discover -v tests.integration'
	run_test(cmd, 'integration')


@test.command()
def coverage():
	"""Run coverage report."""
	cmd = f'{sys.executable} -m coverage report -m --omit=*/site-packages/*,*/tests/*,*/templates/*'
	run_test(cmd, 'coverage')

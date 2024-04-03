import json
import os
import re
import sys

import rich_click as click
from dotmap import DotMap
from fp.fp import FreeProxy
from jinja2 import Template
from rich.markdown import Markdown
from rich.rule import Rule

from secator.config import ConfigLoader
from secator.decorators import OrderedGroup, register_runner
from secator.definitions import (ASCII, CVES_FOLDER, DATA_FOLDER,
								 OPT_NOT_SUPPORTED, PAYLOADS_FOLDER,
								 ROOT_FOLDER, SCRIPTS_FOLDER, VERSION,
								 WORKER_ADDON_ENABLED, DEV_ADDON_ENABLED, DEV_PACKAGE)
from secator.rich import console
from secator.runners import Command
from secator.serializers.dataclass import loads_dataclass
from secator.utils import (debug, detect_host, discover_tasks, find_list_item,
						   flatten, print_results_table)

click.rich_click.USE_RICH_MARKUP = True

ALL_TASKS = discover_tasks()
ALL_CONFIGS = ConfigLoader.load_all()
ALL_WORKFLOWS = ALL_CONFIGS.workflow
ALL_SCANS = ALL_CONFIGS.scan
DEFAULT_CMD_OPTS = {
	'no_capture': True,
	'print_cmd': True,
}


#-----#
# CLI #
#-----#

@click.group(cls=OrderedGroup, invoke_without_command=True)
@click.option('--no-banner', '-nb', is_flag=True, default=False)
@click.option('--version', '-version', is_flag=True, default=False)
@click.pass_context
def cli(ctx, no_banner, version):
	"""Secator CLI."""
	if not no_banner:
		print(ASCII, file=sys.stderr)
	if ctx.invoked_subcommand is None:
		if version:
			print(f'Current Version: v{VERSION}')
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
	if not WORKER_ADDON_ENABLED:
		console.print('[bold red]Missing worker addon: please run `secator install addons worker`[/].')
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
	Command.run_command(
		cmd,
		name='secator worker',
		**DEFAULT_CMD_OPTS
	)


#--------#
# REPORT #
#--------#


@cli.group(aliases=['r'])
def report():
	"""Reports."""
	pass


@report.command('show')
@click.argument('json_path')
@click.option('-e', '--exclude-fields', type=str, default='', help='List of fields to exclude (comma-separated)')
def report_show(json_path, exclude_fields):
	"""Show a JSON report as a nicely-formatted table."""
	with open(json_path, 'r') as f:
		report = loads_dataclass(f.read())
		results = flatten(list(report['results'].values()))
	exclude_fields = exclude_fields.split(',')
	print_results_table(
		results,
		title=report['info']['title'],
		exclude_fields=exclude_fields)


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


def which(command):
	"""Run which on a command.

	Args:
		command (str): Command to check.

	Returns:
		secator.Command: Command instance.
	"""
	return Command.run_command(
		f'which {command}',
		quiet=True,
		print_errors=False
	)


def version(cls):
	"""Get version for a Command.

	Args:
		cls: Command class.

	Returns:
		string: Version string or 'n/a' if not found.
	"""
	base_cmd = cls.cmd.split(' ')[0]
	if cls.version_flag == OPT_NOT_SUPPORTED:
		return 'N/A'
	version_flag = cls.version_flag or f'{cls.opt_prefix}version'
	version_cmd = f'{base_cmd} {version_flag}'
	return get_version(version_cmd)


def get_version(version_cmd):
	"""Run version command and match first version number found.

	Args:
		version_cmd (str): Command to get the version.

	Returns:
		str: Version string.
	"""
	regex = r'[0-9]+\.[0-9]+\.?[0-9]*\.?[a-zA-Z]*'
	ret = Command.run_command(
		version_cmd,
		quiet=True,
		print_errors=False
	)
	match = re.findall(regex, ret.output)
	if not match:
		return 'n/a'
	return match[0]


@cli.command(name='health', aliases=['h'])
@click.option('--json', '-json', is_flag=True, default=False, help='JSON lines output')
@click.option('--debug', '-debug', is_flag=True, default=False, help='Debug health output')
def health(json, debug):
	"""Health."""
	tools = [cls for cls in ALL_TASKS]
	status = {'tools': {}, 'languages': {}, 'secator': {}}

	def print_status(cmd, return_code, version=None, bin=None, category=None):
		s = '[bold green]ok     [/]' if return_code == 0 else '[bold red]failed [/]'
		s = f'[bold magenta]{cmd:<15}[/] {s} '
		if return_code == 0 and version:
			if version == 'N/A':
				s += f'[dim blue]{version:<12}[/]'
			else:
				s += f'[bold blue]{version:<12}[/]'
		elif category:
			s += ' '*12 + f'[dim]# secator install {category} {cmd}'
		if bin:
			s += f'[dim gold3]{bin}[/]'
		console.print(s, highlight=False)

	# Check secator
	console.print(':wrench: [bold gold3]Checking secator ...[/]')
	ret = which('secator')
	if not json:
		print_status('secator', ret.return_code, VERSION, ret.output, None)
	status['secator'] = {'installed': ret.return_code == 0}

	# Check languages
	console.print('\n:wrench: [bold gold3]Checking installed languages ...[/]')
	version_cmds = {'go': 'version', 'python3': '--version', 'ruby': '--version', 'rustc': '--version'}
	for lang, version_flag in version_cmds.items():
		ret = which(lang)
		ret2 = get_version(f'{lang} {version_flag}')
		if not json:
			print_status(lang, ret.return_code, ret2, ret.output, 'lang')
		status['languages'][lang] = {'installed': ret.return_code == 0}

	# Check tools
	console.print('\n:wrench: [bold gold3]Checking installed tools ...[/]')
	for tool in tools:
		cmd = tool.cmd.split(' ')[0]
		ret = which(cmd)
		ret2 = version(tool)
		if not json:
			print_status(tool.__name__, ret.return_code, ret2, ret.output, 'tools')
		status['tools'][tool.__name__] = {'installed': ret.return_code == 0}

	# Print JSON health
	if json:
		console.print(status)

#---------#
# INSTALL #
#---------#


def run_install(cmd, title, next_steps=None):
	with console.status(f'[bold yellow] Installing {title}...'):
		ret = Command.run_command(
			cmd,
			cls_attributes={'shell': True},
			print_cmd=True,
			print_line=True
		)
		if ret.return_code != 0:
			console.print(f':exclamation_mark: Failed to install {title}.', style='bold red')
		else:
			console.print(f':tada: {title.capitalize()} installed successfully !', style='bold green')
			if next_steps:
				console.print('[bold gold3]:wrench: Next steps:[/]')
				for ix, step in enumerate(next_steps):
					console.print(f'   :keycap_{ix}: {step}')
		sys.exit(ret.return_code)


@cli.group(aliases=['i'])
def install():
	"Installations."
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
			'Run "secator worker" to run a Celery worker using the file system as a backend and broker.',
			'Run "secator x httpx testphp.vulnweb.com" to admire your task running in a worker.',
			'[dim]\[optional][/dim] Run "secator install addons redis" to install the Redis addon.'
		]
	)


@addons.command('google')
def install_google():
	"Install google addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[google]',
		title='google addon',
		next_steps=[
			'Set the "GOOGLE_CREDENTIALS_PATH" and "GOOGLE_DRIVE_PARENT_FOLDER_ID" environment variables.',
			'Run "secator x httpx testphp.vulnweb.com -o gdrive" to admire your results flowing to Google Drive.'
		]
	)


@addons.command('mongodb')
def install_mongodb():
	"Install mongodb addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[mongodb]',
		title='mongodb addon',
		next_steps=[
			'[dim]\[optional][/] Run "docker run --name mongo -p 27017:27017 -d mongo:latest" to run a local MongoDB instance.',
			'Set the "MONGODB_URL=mongodb://<url>" environment variable pointing to your MongoDB instance.',
			'Run "secator x httpx testphp.vulnweb.com -driver mongodb" to save results to MongoDB.'
		]
	)


@addons.command('redis')
def install_redis():
	"Install redis addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[redis]',
		title='redis addon',
		next_steps=[
			'[dim]\[optional][/] Run "docker run --name redis -p 5432:5432 -d redis" to run a local Redis instance.',
			'Set the "CELERY_BROKER_URL=redis://<url>" environment variable pointing to your Redis instance.',
			'Run "secator worker" to run a worker.',
			'Run "secator x httpx testphp.vulnweb.com" to run a test task.'
		]
	)


@addons.command('dev')
def install_dev():
	"Install dev addon."
	run_install(
		cmd=f'{sys.executable} -m pip install secator[dev]',
		title='dev addon',
		next_steps=[
			'Run "secator test lint" to run lint tests.',
			'Run "secator test unit" to run unit tests.',
			'Run "secator test integration" to run integration tests.',
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
		title='Go'
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
	if cmds is not None:
		cmds = cmds.split(',')
		tools = [cls for cls in ALL_TASKS if cls.__name__ in cmds]
	else:
		tools = ALL_TASKS

	for ix, cls in enumerate(tools):
		with console.status(f'[bold yellow][{ix}/{len(tools)}] Installing {cls.__name__} ...'):
			cls.install()
		console.print()


@install.command('cves')
@click.option('--force', is_flag=True)
def install_cves(force):
	"""Install CVEs to file system for passive vulnerability search."""
	cve_json_path = f'{CVES_FOLDER}/circl-cve-search-expanded.json'
	if not os.path.exists(cve_json_path) or force:
		with console.status('[bold yellow]Downloading zipped CVEs from cve.circl.lu ...[/]'):
			Command.run_command(
				'wget https://cve.circl.lu/static/circl-cve-search-expanded.json.gz',
				cwd=CVES_FOLDER,
				**DEFAULT_CMD_OPTS
			)
		with console.status('[bold yellow]Unzipping CVEs ...[/]'):
			Command.run_command(
				f'gunzip {CVES_FOLDER}/circl-cve-search-expanded.json.gz',
				cwd=CVES_FOLDER,
				**DEFAULT_CMD_OPTS
			)
	with console.status(f'[bold yellow]Installing CVEs to {CVES_FOLDER} ...[/]'):
		with open(cve_json_path, 'r') as f:
			for line in f:
				data = json.loads(line)
				cve_id = data['id']
				cve_path = f'{CVES_FOLDER}/{cve_id}.json'
				with open(cve_path, 'w') as f:
					f.write(line)
				console.print(f'CVE saved to {cve_path}')
	console.print(':tada: CVEs installed successfully !', style='bold green')


#-------#
# ALIAS #
#-------#


@cli.group(aliases=['a'])
def alias():
	"""Aliases."""
	pass


@alias.command('enable')
@click.pass_context
def enable_aliases(ctx):
	"""Enable aliases."""
	fpath = f'{DATA_FOLDER}/.aliases'
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
	fpath = f'{DATA_FOLDER}/.unalias'
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


#-------#
# UTILS #
#-------#


@cli.group(aliases=['u'])
def utils():
	"""Utilities."""
	pass


@utils.command()
@click.option('--timeout', type=float, default=0.2, help='Proxy timeout (in seconds)')
@click.option('--number', '-n', type=int, default=1, help='Number of proxies')
def get_proxy(timeout, number):
	"""Get a random proxy."""
	proxy = FreeProxy(timeout=timeout, rand=True, anonym=True)
	for _ in range(number):
		url = proxy.get()
		print(url)


@utils.command()
@click.argument('name', type=str, default=None, required=False)
@click.option('--host', '-h', type=str, default=None, help='Specify LHOST for revshell, otherwise autodetected.')
@click.option('--port', '-p', type=int, default=9001, show_default=True, help='Specify PORT for revshell')
@click.option('--interface', '-i', type=str, help='Interface to use to detect IP')
@click.option('--listen', '-l', is_flag=True, default=False, help='Spawn netcat listener on specified port')
def revshells(name, host, port, interface, listen):
	"""Show reverse shell source codes and run netcat listener."""
	if host is None:  # detect host automatically
		host = detect_host(interface)
		if not host:
			console.print(
				f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of available interfaces.',
				style='bold red')
			return

	with open(f'{SCRIPTS_FOLDER}/revshells.json') as f:
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
		Command.run_command(
			cmd,
			**DEFAULT_CMD_OPTS
		)


@utils.command()
@click.option('--directory', '-d', type=str, default=PAYLOADS_FOLDER, show_default=True, help='HTTP server directory')
@click.option('--host', '-h', type=str, default=None, help='HTTP host')
@click.option('--port', '-p', type=int, default=9001, help='HTTP server port')
@click.option('--interface', '-i', type=str, default=None, help='Interface to use to auto-detect host IP')
def serve(directory, host, port, interface):
	"""Serve payloads in HTTP server."""
	LSE_URL = 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh'
	LINPEAS_URL = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh'
	SUDOKILLER_URL = 'https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/SUDO_KILLERv2.4.2.sh'
	PAYLOADS = [
		{
			'fname': 'lse.sh',
			'description': 'Linux Smart Enumeration',
			'command': f'wget {LSE_URL} -O lse.sh && chmod 700 lse.sh'
		},
		{
			'fname': 'linpeas.sh',
			'description': 'Linux Privilege Escalation Awesome Script',
			'command': f'wget {LINPEAS_URL} -O linpeas.sh && chmod 700 linpeas.sh'
		},
		{
			'fname': 'sudo_killer.sh',
			'description': 'SUDO_KILLER',
			'command': f'wget {SUDOKILLER_URL} -O sudo_killer.sh && chmod 700 sudo_killer.sh'
		}
	]
	for ix, payload in enumerate(PAYLOADS):
		descr = payload.get('description', '')
		fname = payload['fname']
		if not os.path.exists(f'{directory}/{fname}'):
			with console.status(f'[bold yellow][{ix}/{len(PAYLOADS)}] Downloading {fname} [dim]({descr})[/] ...[/]'):
				cmd = payload['command']
				console.print(f'[bold magenta]{fname} [dim]({descr})[/] ...[/]', )
				opts = DEFAULT_CMD_OPTS.copy()
				opts['no_capture'] = False
				Command.run_command(
					cmd,
					cls_attributes={'shell': True},
					cwd=directory,
					**opts
				)
		console.print()

	console.print(Rule())
	console.print(f'Available payloads in {directory}: ', style='bold yellow')
	opts = DEFAULT_CMD_OPTS.copy()
	opts['print_cmd'] = False
	for fname in os.listdir(directory):
		if not host:
			host = detect_host(interface)
			if not host:
				console.print(
					f'Interface "{interface}" could not be found. Run "ifconfig" to see the list of interfaces.',
					style='bold red')
				return
		payload = find_list_item(PAYLOADS, fname, key='fname', default={})
		fdescr = payload.get('description', 'No description')
		console.print(f'{fname} [dim]({fdescr})[/]', style='bold magenta')
		console.print(f'wget http://{host}:{port}/{fname}', style='dim italic')
		console.print('')
	console.print(Rule())
	console.print('Starting HTTP server ...', style='bold yellow')
	Command.run_command(
		f'python -m http.server {port}',
		cwd=directory,
		**DEFAULT_CMD_OPTS
	)


@utils.command()
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
			Command.run_command(
				f'asciinema-automation -aa "-c /bin/sh" {script} {output_cast_path} --timeout 200',
				cls_attributes=attrs,
				raw=True,
				**DEFAULT_CMD_OPTS,
			)
			console.print(f'Generated {output_cast_path}', style='bold green')
	elif interactive:
		os.environ.update(attrs['env'])
		Command.run_command(
			f'asciinema rec -c /bin/bash --stdin --overwrite {output_cast_path}',
		)

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
			Command.run_command(
				f'asciinema-edit quantize --range 1 {output_cast_path} --out {output_cast_path}.tmp',
				cls_attributes=attrs,
				raw=True,
				**DEFAULT_CMD_OPTS,
			)
			if os.path.exists(f'{output_cast_path}.tmp'):
				os.replace(f'{output_cast_path}.tmp', output_cast_path)
			console.print(f'Edited {output_cast_path}', style='bold green')

	# Convert to GIF
	with console.status(f'[bold gold3]Converting to {output_gif_path} ...[/]'):
		Command.run_command(
			f'agg {output_cast_path} {output_gif_path}',
			cls_attributes=attrs,
			**DEFAULT_CMD_OPTS,
		)
		console.print(f'Generated {output_gif_path}', style='bold green')


#------#
# TEST #
#------#


@cli.group(cls=OrderedGroup)
def test():
	"""Tests."""
	if not DEV_PACKAGE:
		console.print('[bold red]You MUST use a development version of secator to run tests.[/]')
		sys.exit(1)
	if not DEV_ADDON_ENABLED:
		console.print('[bold red]Missing dev addon: please run `secator install addons dev`')
		sys.exit(1)
	pass


def run_test(cmd, name):
	"""Run a test and return the result.

	Args:
		cmd: Command to run.
		name: Name of the test.
	"""
	result = Command.run_command(
		cmd,
		name=name + ' tests',
		cwd=ROOT_FOLDER,
		**DEFAULT_CMD_OPTS
	)
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
	os.environ['DEBUG'] = str(debug)
	os.environ['DEFAULT_STORE_HTTP_RESPONSES'] = '0'
	os.environ['DEFAULT_SKIP_CVE_SEARCH'] = '1'

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
	os.environ['DEBUG'] = str(debug)
	os.environ['DEFAULT_SKIP_CVE_SEARCH'] = '1'
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
	cmd = f'{sys.executable} -m coverage report -m'
	run_test(cmd, 'coverage')

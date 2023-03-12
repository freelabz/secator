import json
import os
import sys

import rich_click as click
from dotmap import DotMap
from fp.fp import FreeProxy

from secsy.celery import *
from secsy.config import ConfigLoader
from secsy.decorators import OrderedGroup, register_runner
from secsy.definitions import ASCII, TEMP_FOLDER, CVES_FOLDER, ROOT_FOLDER, DEBUG
from secsy.rich import console
from secsy.runners import Command
from secsy.runners._base import Runner
from secsy.utils import discover_tasks, flatten

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
@click.option('--no-banner', is_flag=True, default=False)
def cli(no_banner):
	"""Secsy CLI."""
	if not no_banner:
		print(ASCII, file=sys.stderr)
	pass


@cli.group(aliases=['t', 'tk', 'cmd', 'command'])
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


@cli.group(cls=OrderedGroup, aliases=['s', 'sc'])
def scan():
	"""Run a scan."""
	pass

for config in sorted(ALL_SCANS, key=lambda x: x['name']):
	register_runner(scan, config)


@cli.group(aliases=['u', 'ut'])
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
	for cls in cmds:
		with console.status(f'Installing {cls.__name__} ...'):
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
	from secsy.rich import console
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
	path = ROOT_FOLDER + '/scripts/install.sh'
	with open(path, 'w') as f:
		f.write('#!/bin/bash\n\n')
		for task in ALL_TASKS:
			if task.install_cmd:
				f.write(f'# {task.__name__}\n')
				f.write(task.install_cmd + '\n\n')
	Command.run_command(
		f'chmod +x {path}',
		**DEFAULT_CMD_OPTS
	)
	console.print(f':file_cabinet: [bold green]Saved install script to {path}[/]')


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
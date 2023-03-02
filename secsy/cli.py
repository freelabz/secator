import logging
import os
import sys

import rich_click as click

from secsy.runners import Command
from secsy.decorators import (OrderedGroup, register_tasks, register_scans,
                              register_workflows)
from secsy.utils import (discover_external_tasks, discover_internal_tasks,
                         setup_logging)
from secsy.definitions import ASCII

DEBUG = bool(int(os.environ.get('DEBUG', '0')))
YAML_MODE = bool(int(os.environ.get('YAML_MODE', '0')))
ALL_CMDS = discover_internal_tasks() + discover_external_tasks()

level = logging.DEBUG if DEBUG else logging.INFO
setup_logging(level)

DEFAULT_CMD_OPTS = {
	'no_capture': True,
	'print_cmd': True,
	'print_timestamp': True
}


#--------#
# GROUPS #
#--------#

@click.group(cls=OrderedGroup)
def cli():
	"""Secsy CLI."""
	print(ASCII, file=sys.stderr)
	pass


@cli.group(aliases=['t', 'tk', 'cmd', 'command'])
def task():
	"""Run a task."""
	pass


@cli.group(aliases=['w', 'wf', 'flow'])
def workflow():
	"""Run a workflow."""
	pass


@cli.group(aliases=['sc'])
def scan():
	"""Run a scan."""
	pass


@cli.group(aliases=['ut'])
def utils():
	"""Run a utility."""
	pass


@cli.command()
@click.option('-c', '--concurrency', type=int, help='Number of child processes processing the queue.')
def worker(concurrency):
	"""Run a Celery worker."""
	cmd = 'celery -A secsy.celery.app worker -n runner'
	if concurrency:
		cmd += f' -c {concurrency}'
	Command.run_command(
		cmd,
		**DEFAULT_CMD_OPTS
	)

register_tasks(task)
register_workflows(workflow)
register_scans(scan)


#-------#
# UTILS #
#-------#

@utils.command()
@click.argument('cmds', required=False)
def install(cmds):
	"""Install commands."""
	if cmds is not None:
		cmds = cmds.split(',')
		cmds = [cls for cls in ALL_CMDS if cls.__name__ in cmds]
	else:
		cmds = ALL_CMDS
	for cls in cmds:
		cls.install()

@utils.command()
@click.option('--timeout', type=float, default=0.2, help='Proxy timeout (in seconds)')
def get_proxy(timeout):
	from fp.fp import FreeProxy
	url = FreeProxy(timeout=timeout, anonym=True).get()
	print(url)


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
@click.option('--test', '-t', type=str, default='tests.unit', help='Secsy test to run')
@click.option('--coverage', '-x', is_flag=True, help='Run coverage on results')
@click.option('--debug', '-d', is_flag=True, help='Add debug information')
def unit(commands, test, coverage=False, debug=False):
	os.environ['TEST_COMMANDS'] = commands or ''
	os.environ['DEBUG'] = str(int(debug))

	cmd = 'coverage run --omit="*test*" -m unittest'
	if test:
		cmd += f' {test}'
	else:
		cmd += ' -v tests.unit'

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
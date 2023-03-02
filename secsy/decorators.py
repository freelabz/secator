import sys
from collections import OrderedDict

import rich_click as click
from dotmap import DotMap
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup

from secsy.config import ConfigLoader
from secsy.definitions import *
from secsy.runners import Scan, Task, Workflow
from secsy.utils import (discover_tasks, expand_input, get_command_category,
                         get_command_cls, get_task_name_padding)

DEFAULT_CLI_OPTIONS = {
	'json': {'is_flag': True, 'default': False, 'help': 'Enable JSON mode'},
	'orig': {'is_flag': True, 'default': False, 'help': 'Enable original output (no schema conversion)'},
	'raw': {'is_flag': True, 'default': False, 'help': 'Enable text output for piping to other tools'},
	'color': {'is_flag': True, 'default': False, 'help': 'Enable output coloring'},
	'table': {'is_flag': True, 'default': False, 'help': 'Enable Table mode'},
	'quiet': {'is_flag': True, 'default': False, 'help': 'Enable quiet mode'},
}

click.rich_click.USE_RICH_MARKUP = True
ALL_CONFIGS = ConfigLoader.load_all()


class OrderedGroup(RichGroup):
	def __init__(self, name=None, commands=None, **attrs):
		super(OrderedGroup, self).__init__(name, commands, **attrs)
		self.commands = commands or OrderedDict()

	def group(self, *args, **kwargs):
		"""Behaves the same as `click.Group.group()` except if passed
		a list of names, all after the first will be aliases for the first.
		"""
		def decorator(f):
			aliased_group = []
			aliases = kwargs.pop('aliases', [])
			if aliases:
				max_width = _get_rich_console().width
				# we have a list so create group aliases
				aliases_str = ', '.join(f'[bold cyan]{alias}[/]' for alias in aliases)
				padding = max_width // 4
				f.__doc__ = f'{f.__doc__:<{padding}}[dim](aliases)[/] {aliases_str}'
				for alias in aliases:
					grp = super(OrderedGroup, self).group(
						alias, *args, hidden=True, **kwargs)(f)
					aliased_group.append(grp)

			# create the main group
			grp = super(OrderedGroup, self).group(*args, **kwargs)(f)

			# for all of the aliased groups, share the main group commands
			for aliased in aliased_group:
				aliased.commands = grp.commands

			return grp
		return decorator

	def list_commands(self, ctx):
		return self.commands


def get_command_options(*tasks):
	"""Get unified list of command options from a list of secsy tasks classes.

	Args:
		tasks (list): List of secsy command classes.

	Returns:
		list: List of deduplicated options.
	"""
	opt_cache = []
	all_opts = OrderedDict({})
	help_padding = get_task_name_padding()
	for cls in tasks:
		opts = OrderedDict(DEFAULT_CLI_OPTIONS, **cls.meta_opts, **cls.opts)
		for opt, opt_conf in opts.items():
			if opt not in cls.opt_key_map and opt not in cls.opts and opt not in DEFAULT_CLI_OPTIONS:
				continue
			if cls.opt_key_map.get(opt) == OPT_NOT_SUPPORTED:
				continue
			prefix = None
			if opt in cls.opts:
				prefix = cls.__name__
			elif opt in cls.meta_opts:
				prefix = 'meta'
			elif opt in DEFAULT_CLI_OPTIONS:
				prefix = 'global'
			opt = opt.replace('_', '-')
			if opt in opt_cache:
				continue
			opt_conf['show_default'] = True
			help = opt_conf.get('help', '')
			if help and prefix and prefix not in help:
				opt_conf['help'] = f'[italic]{prefix:<{help_padding}}[/]{help}'
			all_opts[opt] = opt_conf
			opt_cache.append(opt)
	return all_opts


def decorate_command_options(opts):
	"""Add click.option decorator to decorate click command.

	Args:
		opts (dict): Dict of command options.

	Returns:
		function: Decorator.
	"""
	def decorator(f):
		reversed_opts = OrderedDict(list(opts.items())[::-1])
		for opt_name, opt_conf in reversed_opts.items():
			f = click.option(f'--{opt_name}', **opt_conf)(f)
		return f
	return decorator


# def register_task(cls, cli_endpoint):
# 	"""Register a secsy task with the CLI, from a Command object.

# 	The resulting command has all the meta options + options of the 
# 	Command object, plus some common format parameters that can be passed 
# 	such as -json, -orig, -raw, -color, -table, -quiet.

# 	Args:
# 		secsy.runners.Command: Command runner class.

# 	Returns:
# 		click.BaseCommand: Click command.
# 	"""
# 	input_type = cls.input_type or 'input'
# 	options = get_command_options(cls)
# 	help_padding = ' ' * (get_task_name_padding() - 6)

# 	@click.argument(input_type, required=False)
# 	@click.option('--worker', is_flag=True, help=f'[italic]global[/]{help_padding}Run tasks in a distributed way inside worker (FASTER).')
# 	@click.option('--verbose', is_flag=True, help=f'[italic]global[/]{help_padding}Verbose mode, show full command output.')
# 	@click.option('--debug', is_flag=True, help=f'[italic]global[/]{help_padding}Debug mode, show debug logs.')
# 	@decorate_command_options(options)
# 	@click.pass_context
# 	def func(ctx, worker, verbose, debug, **opts):
# 		default_opts = {
# 			'print_cmd': True,
# 			'print_timestamp': True,
# 			'print_item_count': True,
# 			'print_item': True,
# 			'print_line': True,
# 		}
# 		opts.update(default_opts)
# 		input = opts.pop(input_type)
# 		input = expand_input(input)
# 		if input is None:
# 			click.echo(ctx.get_help())
# 			sys.exit(0)
# 		config = DotMap({'name': cls.__name__, 'options': opts})
# 		task = Task(config, input, debug=debug, **opts)
# 		task.run(sync=not worker)

# 	cls_category = get_command_category(cls)
# 	settings = {'ignore_unknown_options': True}
# 	cli_endpoint.command(
# 		name=cls.__name__,
# 		context_settings=settings,
# 		# no_args_is_help=True, # TODO: incompatible with stdin output
# 		short_help=f'{cls_category:<10}{cls.__doc__}')(func)


def register_tasks(cli_endpoint):
	"""Register secsy commands as Click commands with their options translated 
	to Click format.

	Args:
		cmds (list): List of Command objects to register.
		cli_endpoint (click.Group): Click group to register commands with.
	"""
	cmds = discover_tasks()
	for cls in cmds:
		config = DotMap({'name': cls.__name__})
		register_runner(cli_endpoint, config)

def register_workflows(cli_endpoint, *dirs):
	"""Register Click workflow commands dynamically.

	Args:
		cli_endpoint (click.Group): Click group to register commands with.
		dirs (list): List of dirs to load workflows from.
	"""
	for workflow in ALL_CONFIGS.workflows:
		register_runner(cli_endpoint, workflow)

def register_scans(cli_endpoint, *dirs):
	"""Register Click scan commands dynamically.
	
	Args:
		cli_endpoint (click.Group): Click group to register commands with.
		dirs (list): List of dirs to load scans from.
	"""
	for scan in ALL_CONFIGS.scans:
		register_runner(cli_endpoint, scan)

# def register_workflow(cli_endpoint, config):
# 	workflow_name = config.name
# 	workflow_description = config.get('description', '')
# 	tasks = [get_command_cls(task) for task in Task.get_tasks_from_conf(config.tasks)]
# 	options = get_command_options(*tasks)
# 	help_padding = ' ' * (get_task_name_padding() - 6)

# 	@click.argument('target')
# 	@click.option('--worker', is_flag=True, help=f'[italic]global[/]{help_padding}Run tasks in a distributed way inside worker (FASTER).')
# 	@click.option('--verbose', is_flag=True, help=f'[italic]global[/]{help_padding}Verbose mode, show full command output.')
# 	@click.option('--debug', is_flag=True, help=f'[italic]global[/]{help_padding}Debug mode, show debug logs.')
# 	@decorate_command_options(options)
# 	@click.pass_context
# 	def func(ctx, worker, verbose, debug, **opts):
# 		default_opts = {
# 			'print_cmd': True,
# 			'print_timestamp': True,
# 			'print_item_count': True,
# 			'print_item': verbose,
# 			'print_line': verbose,
# 			'json': True
# 		}
# 		opts.update(default_opts)
# 		input = opts.pop('target')
# 		input = expand_input(input)
# 		if input is None:
# 			click.echo(ctx.get_help())
# 			sys.exit(0)
# 		config = ConfigLoader(name=f'workflows/{workflow_name}')
# 		workflow = Workflow(config, input, debug=debug, **opts)
# 		results = workflow.run(sync=not worker, results=results, print_results=True)
# 		return results

# 	settings = {'ignore_unknown_options': True}
# 	cli_endpoint.command(
# 		name=workflow_name,
# 		context_settings=settings,
# 		no_args_is_help=True,
# 		short_help=workflow_description)(func)


# def register_scan(cli_endpoint, scan):
# 	workflow_names = list(scan.workflows.keys())
# 	workflows = [w for w in ALL_CONFIGS.workflows if w.name in workflow_names]
# 	tasks = [get_command_cls(task) for workflow in workflows for task in Task.get_tasks_from_conf(workflow.tasks)]
# 	options = get_command_options(*tasks)
# 	help_padding = ' ' * (get_task_name_padding() - 6)

# 	@click.argument('target')
# 	@click.option('--worker', is_flag=True, help=f'[italic]global[/]{help_padding}Run tasks in a distributed way inside worker (FASTER).')
# 	@click.option('--verbose', is_flag=True, help=f'[italic]global[/]{help_padding}Verbose mode, show full command output.')
# 	@click.option('--debug', is_flag=True, help=f'[italic]global[/]{help_padding}Debug mode, show debug logs.')
# 	@decorate_command_options(options)
# 	@click.pass_context
# 	def func(ctx, worker, verbose, debug, **opts):
# 		default_opts = {
# 			'print_cmd': True,
# 			'print_timestamp': True,
# 			'print_item_count': True,
# 			'print_item': verbose,
# 			'print_line': verbose,
# 			'json': True
# 		}
# 		opts.update(default_opts)
# 		input = opts.pop('target')
# 		input = expand_input(input)
# 		if input is None:
# 			click.echo(ctx.get_help())
# 			sys.exit(0)
# 		scan = Scan(scan, input, debug=debug, **opts)
# 		scan.run(sync=not worker)

# 	settings = {'ignore_unknown_options': True}
# 	cli_endpoint.command(
# 		name=scan.name,
# 		context_settings=settings,
# 		no_args_is_help=True,
# 		short_help=scan.get('description', ''))(func)



def register_runner(cli_endpoint, config):
	fmt_opts = {
		'print_cmd': True,
		'print_timestamp': True,
		'print_item_count': True,
	}
	short_help = ''
	input_type = 'targets'
	runner_cls = None
	tasks = []

	if cli_endpoint.name == 'scan':
		tasks = [
			get_command_cls(task)
			for workflow in ALL_CONFIGS.workflows
			for task in Task.get_tasks_from_conf(workflow.tasks)
			if workflow.name in list(config.workflows.keys())
		]
		input_type = 'targets'
		short_help = config.description or ''
		fmt_opts['json'] = True
		runner_cls = Scan

	elif cli_endpoint.name == 'workflow':
		tasks = [
			get_command_cls(task) for task in Task.get_tasks_from_conf(config.tasks)
		]
		input_type = 'targets'
		short_help = config.description or ''
		fmt_opts['json'] = True
		runner_cls = Workflow

	elif cli_endpoint.name == 'task':
		tasks = [
			get_command_cls(config.name)
		]
		task_cls = Task.get_task_class(config.name)
		task_category = get_command_category(task_cls)
		input_type = task_cls.input_type or 'targets'
		short_help = f'{task_category:<10}{task_cls.__doc__}'
		fmt_opts['print_item'] = True
		fmt_opts['print_line'] = True
		runner_cls = Task

	options = get_command_options(*tasks)
	help_padding = ' ' * (get_task_name_padding() - 6)


	@click.argument(input_type)
	@click.option('--worker', is_flag=True, help=f'[italic]global[/]{help_padding}Run tasks in a distributed way inside worker (FASTER).')
	@click.option('--verbose', is_flag=True, help=f'[italic]global[/]{help_padding}Verbose mode, show full command output.')
	@click.option('--debug', is_flag=True, help=f'[italic]global[/]{help_padding}Debug mode, show debug logs.')
	@decorate_command_options(options)
	@click.pass_context
	def func(ctx, worker, verbose, debug, **opts):
		opts.update(fmt_opts)
		if cli_endpoint.name in ['scans', 'workflows']:
			opts['print_item'] = verbose
			opts['print_line'] = verbose
		targets = opts.pop(input_type)
		targets = expand_input(targets)
		if input is None:
			click.echo(ctx.get_help())
			sys.exit(0)
		runner = runner_cls(config, targets, debug=debug, **opts)
		runner.run(sync=not worker)

	settings = {'ignore_unknown_options': True}
	cli_endpoint.command(
		name=config.name,
		context_settings=settings,
		no_args_is_help=True,
		short_help=short_help)(func)
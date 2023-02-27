from collections import OrderedDict

import rich_click as click
from rich_click.rich_group import RichGroup

from secsy.config import ConfigLoader
from secsy.definitions import *
from secsy.runner import run_scan, run_workflow
from secsy.utils import (find_external_commands, find_internal_commands,
                         get_command_category, get_command_cls,
                         expand_input)

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
        #: the registered subcommands by their exported names.
        self.commands = commands or OrderedDict()

    def list_commands(self, ctx):
        return self.commands


def get_command_options(*tools):
	"""Get unified list of command options from a list of secsy commands
	classes.

	Args:
		commands (list): List of secsy command classes.

	Returns:
		list: List of deduplicated options.
	"""
	opt_cache = []
	all_opts = OrderedDict({})
	for cls in tools:
		opts = OrderedDict(DEFAULT_CLI_OPTIONS, **cls.meta_opts, **cls.opts)
		for opt, opt_conf in opts.items():
			if (opt not in cls.opt_key_map and opt not in cls.opts and opt not in DEFAULT_CLI_OPTIONS) or (cls.opt_key_map.get(opt) == OPT_NOT_SUPPORTED):
				continue
			prefix = None
			if (opt in cls.opts):
				prefix = cls.__name__
			elif (opt in cls.meta_opts):
				prefix = 'meta'
			elif (opt in DEFAULT_CLI_OPTIONS):
				prefix = 'global'
			opt = opt.replace('_', '-')
			if opt in opt_cache:
				continue
			opt_conf['show_default'] = True
			help = opt_conf.get('help', '')
			if help and prefix and prefix not in help:
				opt_conf['help'] = f'[italic]{prefix:<10}[/] {help}'
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


def register_command(cls, cli_endpoint):
	"""Register a secsy command with the CLI, from a CommandRunner object.

	The resulting command has all the meta options + options of the 
	CommandRunner object, plus some common format parameters that can be passed 
	such as -json, -orig, -raw, -color, -table, -quiet.

	Args:
		secsy.cmd.CommandRunner: Derived class of CommandRunner representing a 
			command.

	Returns:
		click.BaseCommand: Click command.
	"""
	input_type = cls.input_type or 'input'
	options = get_command_options(cls)
	default_opts = {
		'print_cmd': True,
		'print_item': True,
		'print_item_count': True,
		'print_line': True,
		'print_timestamp': True,
	}
	@click.argument(input_type)
	@decorate_command_options(options)
	def func(**opts):
		opts.update(default_opts)
		input = opts.pop(input_type)
		input = expand_input(input)
		cls(input, **opts).run()

	cls_category = get_command_category(cls)
	settings = {'ignore_unknown_options': True}
	cli_endpoint.command(
		name=cls.__name__,
		context_settings=settings,
		no_args_is_help=True,
		short_help=f'{cls_category:<10}{cls.__doc__}')(func)


def register_commands(cli_endpoint):
	"""Register secsy commands as Click commands with their options translated 
	to Click format.

	Args:
		cmds (list): List of CommandRunner objects to register.
		cli_endpoint (click.Group): Click group to register commands with.
	"""
	cmds = find_internal_commands() + find_external_commands()
	for cls in cmds:
		register_command(cls, cli_endpoint)


def register_workflows(cli_endpoint, *dirs):
	"""Register Click workflow commands dynamically.

	Args:
		cli_endpoint (click.Group): Click group to register commands with.
		dirs (list): List of dirs to load workflows from.
	"""
	for workflow in ALL_CONFIGS.workflows:
		register_workflow(cli_endpoint, workflow)


def get_tasks_from_conf(config):
	tasks = []
	for name, opts in config.items():
		if name == '_group':
			tasks.extend(get_tasks_from_conf(opts))
		elif name == '_chain':
			tasks.extend(get_tasks_from_conf(opts))
		else:
			tasks.append(name)
	return tasks			

def register_workflow(cli_endpoint, config):
	workflow_name = config.name
	workflow_description = config.get('description', '')
	tasks = [get_command_cls(task) for task in get_tasks_from_conf(config.tasks)]
	options = get_command_options(*tasks)

	@click.argument('target')
	@click.option('--worker', is_flag=True, help='[italic]global     [/]Run tasks in a distributed way inside worker (FASTER).')
	@click.option('--verbose', is_flag=True, help='[italic]global     [/]Verbose mode, show full command output.')
	@decorate_command_options(options)
	def func(worker, verbose, **opts):
		default_opts = {
			'print_cmd': True,
			'print_timestamp': True,
			'print_item_count': True,
			'print_item': verbose,
			'print_line': verbose,
			'json': True
		}
		opts.update(default_opts)
		input = opts.pop('target')
		input = expand_input(input)
		run_workflow(workflow_name, input, sync=not worker, **opts)

	settings = {'ignore_unknown_options': True}
	cli_endpoint.command(
		name=workflow_name,
		context_settings=settings,
		no_args_is_help=True,
		short_help=workflow_description)(func)


def register_scans(cli_endpoint, *dirs):
	"""Register Click scan commands dynamically.
	
	Args:
		cli_endpoint (click.Group): Click group to register commands with.
		dirs (list): List of dirs to load scans from.
	"""
	for scan in ALL_CONFIGS.scans:
		register_scan(cli_endpoint, scan)


def register_scan(cli_endpoint, scan):
	scan_workflows = list(scan.workflows.keys())
	workflows = [w for w in ALL_CONFIGS.workflows if w.name in scan_workflows]
	tasks = [get_command_cls(task) for workflow in workflows for task in get_tasks_from_conf(workflow.tasks)]
	options = get_command_options(*tasks)

	@click.argument('target')
	@click.option('--worker', is_flag=True, help='[italic]global     [/]Run tasks in a distributed way inside worker (FASTER).')
	@click.option('--verbose', is_flag=True, help='[italic]global     [/]Verbose mode, show full command output.')
	@decorate_command_options(options)
	def func(worker, verbose, **opts):
		default_opts = {
			'print_cmd': True,
			'print_timestamp': True,
			'print_item_count': True,
			'print_item': verbose,
			'print_line': verbose,
			'json': True
		}
		opts.update(default_opts)
		input = opts.pop('target')
		input = expand_input(input)
		run_scan(scan.name, input, sync=not worker, **opts)

	settings = {'ignore_unknown_options': True}
	cli_endpoint.command(
		name=scan.name,
		context_settings=settings,
		no_args_is_help=True,
		short_help=scan.get('description', ''))(func)
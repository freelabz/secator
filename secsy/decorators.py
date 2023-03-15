import sys
from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup

from secsy.celery import is_celery_worker_alive
from secsy.definitions import *
from secsy.runners import Scan, Task, Workflow
from secsy.utils import (deduplicate, expand_input, get_command_category,
                         get_command_cls, get_task_name_padding)

DEFAULT_OUTPUT_OPTIONS = {
	'json': {'is_flag': True, 'default': False, 'help': 'Enable JSON mode'},
	'orig': {'is_flag': True, 'default': False, 'help': 'Enable original output (no schema conversion)'},
	'raw': {'is_flag': True, 'default': False, 'help': 'Enable text output for piping to other tools'},
	'format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	# 'filter': {'default': '', 'short': 'f', 'help': 'Results filter'}, # TODO add this
	'color': {'is_flag': True, 'default': False, 'help': 'Enable output coloring'},
	'table': {'is_flag': True, 'default': False, 'help': 'Enable Table mode'},
	'quiet': {'is_flag': True, 'default': False, 'help': 'Enable quiet mode'},
}

DEFAULT_EXECUTION_OPTIONS = {
	'sync': {'is_flag': True, 'help': f'Run tasks synchronously (automatic if no worker is alive)'},
	'worker': {'is_flag': True, 'help': f'Run tasks in worker (automatic if worker is alive)'},
	'debug': {'is_flag': True, 'help': f'Debug mode'},
	'proxy': {'type': str, 'help': f'HTTP proxy'},
}

DEFAULT_CLI_OPTIONS = list(DEFAULT_OUTPUT_OPTIONS.keys()) + list(DEFAULT_EXECUTION_OPTIONS.keys())


class OrderedGroup(RichGroup):
	def __init__(self, name=None, commands=None, **attrs):
		super(OrderedGroup, self).__init__(name, commands, **attrs)
		self.commands = commands or OrderedDict()

	def group(self, *args, **kwargs):
		"""Behaves the same as `click.Group.group()` except if passed
		a list of names, all after the first will be aliases for the first.
		"""
		def decorator(f):
			aliases = kwargs.pop('aliases', [])
			aliased_group = []
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
			grp.aliases = aliases

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

	for cls in tasks:
		opts = OrderedDict(DEFAULT_EXECUTION_OPTIONS, **DEFAULT_OUTPUT_OPTIONS, **cls.meta_opts, **cls.opts)
		for opt, opt_conf in opts.items():

			# Opt is not supported by this task
			if opt not in cls.opt_key_map and opt not in cls.opts and opt not in DEFAULT_OUTPUT_OPTIONS and opt not in DEFAULT_EXECUTION_OPTIONS:
				continue

			if cls.opt_key_map.get(opt) == OPT_NOT_SUPPORTED:
				continue

			# Get opt prefix
			prefix = None
			if opt in cls.opts:
				prefix = cls.__name__
			elif opt in cls.meta_opts:
				prefix = 'Meta'
			elif opt in DEFAULT_OUTPUT_OPTIONS:
				prefix = 'Output'
			elif opt in DEFAULT_EXECUTION_OPTIONS:
				prefix = 'Execution'

			# Check if opt already processed before
			opt = opt.replace('_', '-')
			if opt in opt_cache:
				continue

			# Build help
			conf = opt_conf.copy()
			conf['show_default'] = True
			conf['prefix'] = prefix
			all_opts[opt] = conf
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
			conf = opt_conf.copy()
			short = conf.pop('short', None)
			conf.pop('prefix', None)
			long = f'--{opt_name}'
			short = f'-{short}' if short else f'-{opt_name}'
			f = click.option(long, short, **conf)(f)
		return f
	return decorator


def register_runner(cli_endpoint, config):
	fmt_opts = {
		'print_cmd': True,
		'print_timestamp': True,
		'print_item_count': True,
	}
	short_help = ''
	input_type = 'targets'
	input_required = True
	runner_cls = None
	tasks = []
	no_args_is_help = True

	if cli_endpoint.name == 'scan':
		# TODO: this should be refactored to scan.get_tasks_from_conf() or scan.tasks
		from secsy.cli import ALL_CONFIGS
		tasks = [
			get_command_cls(task)
			for workflow in ALL_CONFIGS.workflows
			for task in Task.get_tasks_from_conf(workflow.tasks)
			if workflow.name in list(config.workflows.keys())
		]
		input_type = 'targets'
		name = config.name
		short_help = config.description or ''
		fmt_opts['json'] = True
		runner_cls = Scan

	elif cli_endpoint.name == 'workflow':
		# TODO: this should be refactored to workflow.get_tasks_from_conf() or workflow.tasks
		tasks = [
			get_command_cls(task) for task in Task.get_tasks_from_conf(config.tasks)
		]
		input_type = 'targets'
		name = config.name
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
		name = config.name
		short_help = f'[dim italic magenta]{task_category:<10}[/]{task_cls.__doc__}'
		fmt_opts['print_item'] = True
		fmt_opts['print_line'] = True
		runner_cls = Task
		no_args_is_help = False
		input_required = False

	options = get_command_options(*tasks)

	# TODO: maybe allow this in the future
	# def get_unknown_opts(ctx):
	# 	return {
	# 		(ctx.args[i][2:]
    # 		if str(ctx.args[i]).startswith("--") \
	# 		else ctx.args[i][1:]): ctx.args[i+1]
	# 		for i in range(0, len(ctx.args), 2)
	# 	}

	@click.argument(input_type, required=input_required)
	@decorate_command_options(options)
	@click.pass_context
	def func(ctx, **opts):
		opts.update(fmt_opts)
		sync = opts['sync']
		worker = opts['worker']
		debug = opts['debug']
		# TODO: maybe allow this in the future
		# unknown_opts = get_unknown_opts(ctx)
		# opts.update(unknown_opts)
		if cli_endpoint.name in ['scan', 'workflow']:
			opts['print_item'] = debug
			opts['print_line'] = debug
		targets = opts.pop(input_type)
		targets = expand_input(targets)
		if input is None:
			click.echo(ctx.get_help())
			sys.exit(0)
		if sync:
			sync = True
		elif worker:
			sync = False
		elif cli_endpoint.name in ['scan', 'workflow']: # automatically run in worker if it's alive
			sync = not is_celery_worker_alive()
		else:
			sync = True
		runner = runner_cls(config, targets, **opts)
		runner.run(sync=sync)

	settings = {'ignore_unknown_options': True, 'allow_extra_args': True}
	cli_endpoint.command(
		name=config.name,
		context_settings=settings,
		no_args_is_help=no_args_is_help,
		short_help=short_help)(func)

	generate_rich_click_opt_groups(cli_endpoint, name, input_type, options)


def generate_rich_click_opt_groups(cli_endpoint, name, input_type, options):
	from secsy.utils import deduplicate
	sortorder = {
		'Execution': 0,
		'Output': 1,
		'Meta': 2,
	}
	prefixes = deduplicate([opt['prefix'] for opt in options.values()])
	prefixes = sorted(prefixes, key=lambda x: sortorder.get(x, 3))
	opt_group = [
		{
			'name': 'Targets',
			'options': [input_type],
		},
	]
	for prefix in prefixes:
		prefix_opts = [
			opt for opt, conf in options.items()
			if conf['prefix'] == prefix
		]
		opt_names = [f'--{opt_name}' for opt_name in prefix_opts]
		if prefix == 'Execution':
			opt_names.append('--help')
		opt_group.append({
			'name': prefix + ' options',
			'options': opt_names
		})
	aliases = [cli_endpoint.name, *cli_endpoint.aliases]
	for alias in aliases:
		endpoint_name = f'secsy {alias} {name}'
		click.rich_click.OPTION_GROUPS[endpoint_name] = opt_group
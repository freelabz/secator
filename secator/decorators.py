import sys
from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup

from secator.definitions import ADDONS_ENABLED, OPT_NOT_SUPPORTED
from secator.config import CONFIG
from secator.runners import Scan, Task, Workflow
from secator.utils import (deduplicate, expand_input, get_command_category,
						   get_command_cls)

RUNNER_OPTS = {
	'output': {'type': str, 'default': None, 'help': 'Output options (-o table,json,csv,gdrive)', 'short': 'o'},
	'workspace': {'type': str, 'default': 'default', 'help': 'Workspace', 'short': 'ws'},
	'json': {'is_flag': True, 'default': False, 'help': 'Enable JSON mode'},
	'orig': {'is_flag': True, 'default': False, 'help': 'Enable original output (no schema conversion)'},
	'raw': {'is_flag': True, 'default': False, 'help': 'Enable text output for piping to other tools'},
	'show': {'is_flag': True, 'default': False, 'help': 'Show command that will be run (tasks only)'},
	'format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	# 'filter': {'default': '', 'short': 'f', 'help': 'Results filter', 'short': 'of'}, # TODO add this
	'quiet': {'is_flag': True, 'default': False, 'help': 'Enable quiet mode'},
}

RUNNER_GLOBAL_OPTS = {
	'sync': {'is_flag': True, 'help': 'Run tasks synchronously (automatic if no worker is alive)'},
	'proxy': {'type': str, 'help': 'HTTP proxy'},
	'driver': {'type': str, 'help': 'Export real-time results. E.g: "mongodb"'}
	# 'debug': {'type': int, 'default': 0, 'help': 'Debug mode'},
}

DEFAULT_CLI_OPTIONS = list(RUNNER_OPTS.keys()) + list(RUNNER_GLOBAL_OPTS.keys())


class OrderedGroup(RichGroup):
	def __init__(self, name=None, commands=None, **attrs):
		super(OrderedGroup, self).__init__(name, commands, **attrs)
		self.commands = commands or OrderedDict()

	def command(self, *args, **kwargs):
		"""Behaves the same as `click.Group.command()` but supports aliases.
		"""
		def decorator(f):
			aliases = kwargs.pop("aliases", None)
			if aliases:
				max_width = _get_rich_console().width
				aliases_str = ', '.join(f'[bold cyan]{alias}[/]' for alias in aliases)
				padding = max_width // 4

				name = kwargs.pop("name", None)
				if not name:
					raise click.UsageError("`name` command argument is required when using aliases.")

				f.__doc__ = f.__doc__ or '\0'.ljust(padding+1)
				f.__doc__ = f'{f.__doc__:<{padding}}[dim](aliases)[/] {aliases_str}'
				base_command = super(OrderedGroup, self).command(
					name, *args, **kwargs
				)(f)
				for alias in aliases:
					cmd = super(OrderedGroup, self).command(alias, *args, hidden=True, **kwargs)(f)
					cmd.help = f"Alias for '{name}'.\n\n{cmd.help}"
					cmd.params = base_command.params

			else:
				cmd = super(OrderedGroup, self).command(*args, **kwargs)(f)

			return cmd
		return decorator

	def group(self, *args, **kwargs):
		"""Behaves the same as `click.Group.group()` but supports aliases.
		"""
		def decorator(f):
			aliases = kwargs.pop('aliases', [])
			aliased_group = []
			if aliases:
				max_width = _get_rich_console().width
				aliases_str = ', '.join(f'[bold cyan]{alias}[/]' for alias in aliases)
				padding = max_width // 4
				f.__doc__ = f.__doc__ or '\0'.ljust(padding+1)
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
	"""Get unified list of command options from a list of secator tasks classes.

	Args:
		tasks (list): List of secator command classes.

	Returns:
		list: List of deduplicated options.
	"""
	opt_cache = []
	all_opts = OrderedDict({})

	for cls in tasks:
		opts = OrderedDict(RUNNER_GLOBAL_OPTS, **RUNNER_OPTS, **cls.meta_opts, **cls.opts)
		for opt, opt_conf in opts.items():

			# Get opt key map if any
			opt_key_map = getattr(cls, 'opt_key_map', {})

			# Opt is not supported by this task
			if opt not in opt_key_map\
				and opt not in cls.opts\
				and opt not in RUNNER_OPTS\
				and opt not in RUNNER_GLOBAL_OPTS:
				continue

			if opt_key_map.get(opt) == OPT_NOT_SUPPORTED:
				continue

			# Get opt prefix
			prefix = None
			if opt in cls.opts:
				prefix = cls.__name__
			elif opt in cls.meta_opts:
				# TODO: Add options categories
				# category = get_command_category(cls)
				# prefix = category
				prefix = 'Meta'
			elif opt in RUNNER_OPTS:
				prefix = 'Output'
			elif opt in RUNNER_GLOBAL_OPTS:
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
			conf.pop('internal', False)
			conf.pop('prefix', None)
			long = f'--{opt_name}'
			short = f'-{short}' if short else f'-{opt_name}'
			f = click.option(long, short, **conf)(f)
		return f
	return decorator


def task():
	def decorator(cls):
		cls.__task__ = True
		return cls
	return decorator


def register_runner(cli_endpoint, config):
	fmt_opts = {
		'print_cmd': True,
	}
	short_help = ''
	input_type = 'targets'
	input_required = True
	runner_cls = None
	tasks = []
	no_args_is_help = True

	if cli_endpoint.name == 'scan':
		# TODO: this should be refactored to scan.get_tasks_from_conf() or scan.tasks
		from secator.cli import ALL_CONFIGS
		tasks = [
			get_command_cls(task)
			for workflow in ALL_CONFIGS.workflow
			for task in Task.get_tasks_from_conf(workflow.tasks)
			if workflow.name in list(config.workflows.keys())
		]
		input_type = 'targets'
		name = config.name
		short_help = config.description or ''
		if config.alias:
			short_help += f' [dim]alias: {config.alias}'
		fmt_opts['print_start'] = True
		fmt_opts['print_run_summary'] = True
		fmt_opts['print_progress'] = False
		runner_cls = Scan

	elif cli_endpoint.name == 'workflow':
		# TODO: this should be refactored to workflow.get_tasks_from_conf() or workflow.tasks
		tasks = [
			get_command_cls(task) for task in Task.get_tasks_from_conf(config.tasks)
		]
		input_type = 'targets'
		name = config.name
		short_help = config.description or ''
		if config.alias:
			short_help = f'{short_help:<55} [dim](alias)[/][bold cyan] {config.alias}'
		fmt_opts['print_start'] = True
		fmt_opts['print_run_summary'] = True
		fmt_opts['print_progress'] = False
		runner_cls = Workflow

	elif cli_endpoint.name == 'task':
		tasks = [
			get_command_cls(config.name)
		]
		task_cls = Task.get_task_class(config.name)
		task_category = get_command_category(task_cls)
		input_type = task_cls.input_type or 'targets'
		name = config.name
		short_help = f'[magenta]{task_category:<15}[/]{task_cls.__doc__}'
		fmt_opts['print_item_count'] = True
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
		# debug = opts['debug']
		ws = opts.pop('workspace')
		driver = opts.pop('driver', '')
		show = opts['show']
		context = {'workspace_name': ws}
		# TODO: maybe allow this in the future
		# unknown_opts = get_unknown_opts(ctx)
		# opts.update(unknown_opts)
		targets = opts.pop(input_type)
		targets = expand_input(targets)
		if sync or show:
			sync = True
		else:
			from secator.celery import is_celery_worker_alive
			worker_alive = is_celery_worker_alive()
			if not worker_alive:
				sync = True
			else:
				sync = False
				broker_protocol = CONFIG.celery.broker_url.split('://')[0]
				backend_protocol = CONFIG.celery.result_backend.split('://')[0]
				if CONFIG.celery.broker_url:
					if (broker_protocol == 'redis' or backend_protocol == 'redis') and not ADDONS_ENABLED['redis']:
						_get_rich_console().print('[bold red]Missing `redis` addon: please run `secator install addons redis`[/].')
						sys.exit(1)
		opts['sync'] = sync
		opts.update({
			'print_item': not sync,
			'print_line': sync,
			'print_remote_status': not sync,
			'print_start': not sync
		})

		# Build hooks from driver name
		hooks = {}
		if driver == 'mongodb':
			if not ADDONS_ENABLED['mongodb']:
				_get_rich_console().print('[bold red]Missing `mongodb` addon: please run `secator install addons mongodb`[/].')
				sys.exit(1)
			from secator.hooks.mongodb import MONGODB_HOOKS
			hooks = MONGODB_HOOKS

		# Build exporters
		runner = runner_cls(config, targets, run_opts=opts, hooks=hooks, context=context)
		runner.run()

	settings = {'ignore_unknown_options': False, 'allow_extra_args': False}
	cli_endpoint.command(
		name=config.name,
		context_settings=settings,
		no_args_is_help=no_args_is_help,
		short_help=short_help)(func)

	generate_rich_click_opt_groups(cli_endpoint, name, input_type, options)


def generate_rich_click_opt_groups(cli_endpoint, name, input_type, options):
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
		endpoint_name = f'secator {alias} {name}'
		click.rich_click.OPTION_GROUPS[endpoint_name] = opt_group

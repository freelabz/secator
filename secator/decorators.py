import sys

from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup

from secator.config import CONFIG
from secator.definitions import ADDONS_ENABLED, OPT_NOT_SUPPORTED
from secator.runners import Scan, Task, Workflow
from secator.utils import (deduplicate, expand_input, get_command_category,
						   get_command_cls)

RUNNER_OPTS = {
	'output': {'type': str, 'default': None, 'help': 'Output options (-o table,json,csv,gdrive)', 'short': 'o'},
	'workspace': {'type': str, 'default': 'default', 'help': 'Workspace', 'short': 'ws'},
	'print_json': {'is_flag': True, 'short': 'json', 'default': False, 'help': 'Print items as JSON lines'},
	'print_raw': {'is_flag': True, 'short': 'raw', 'default': False, 'help': 'Print items in raw format'},
	'print_stat': {'is_flag': True, 'short': 'stat', 'default': False, 'help': 'Print runtime statistics'},
	'print_format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	'show': {'is_flag': True, 'default': False, 'help': 'Show command that will be run (tasks only)'},
	'no_process': {'is_flag': True, 'default': False, 'help': 'Disable secator processing'},
	'enable_profiling': {'is_flag': True, 'default': False, 'help': 'Run Python profiling'},
	# 'filter': {'default': '', 'short': 'f', 'help': 'Results filter', 'short': 'of'}, # TODO add this
	'quiet': {'is_flag': True, 'default': False, 'help': 'Enable quiet mode'},
}

RUNNER_GLOBAL_OPTS = {
	'sync': {'is_flag': True, 'help': 'Run tasks synchronously (automatic if no worker is alive)'},
	'worker': {'is_flag': True, 'default': False, 'help': 'Run tasks in worker'},
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
			conf.pop('shlex', True)
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


def generate_cli_subcommand(cli_endpoint, func, **opts):
	return cli_endpoint.command(**opts)(func)


def register_runner(cli_endpoint, config):
	name = config.name
	input_required = True
	input_type = 'targets'
	command_opts = {
		'no_args_is_help': True,
		'context_settings': {
			'ignore_unknown_options': False,
			'allow_extra_args': False
		}
	}

	if cli_endpoint.name == 'scan':
		# TODO: this should be refactored to scan.get_tasks_from_conf() or scan.tasks
		from secator.cli import ALL_CONFIGS
		runner_cls = Scan
		tasks = [
			get_command_cls(task)
			for workflow in ALL_CONFIGS.workflow
			for task in Task.get_tasks_from_conf(workflow.tasks)
			if workflow.name in list(config.workflows.keys())
		]
		short_help = config.description or ''
		short_help += f' [dim]alias: {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help
		})

	elif cli_endpoint.name == 'workflow':
		# TODO: this should be refactored to workflow.get_tasks_from_conf() or workflow.tasks
		runner_cls = Workflow
		tasks = [
			get_command_cls(task) for task in Task.get_tasks_from_conf(config.tasks)
		]
		short_help = config.description or ''
		short_help = f'{short_help:<55} [dim](alias)[/][bold cyan] {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help
		})

	elif cli_endpoint.name == 'task':
		runner_cls = Task
		input_required = False  # allow targets from stdin
		tasks = [
			get_command_cls(config.name)
		]
		task_cls = Task.get_task_class(config.name)
		task_category = get_command_category(task_cls)
		input_type = task_cls.input_type or 'targets'
		short_help = f'[magenta]{task_category:<15}[/]{task_cls.__doc__}'
		command_opts.update({
			'name': name,
			'short_help': short_help,
			'no_args_is_help': False
		})

	else:
		raise ValueError(f"Unrecognized runner endpoint name {cli_endpoint.name}")

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
		sync = opts['sync']
		worker = opts.pop('worker')
		ws = opts.pop('workspace')
		driver = opts.pop('driver', '')
		show = opts['show']
		context = {'workspace_name': ws}

		# Remove options whose values are default values
		for k, v in options.items():
			opt_name = k.replace('-', '_')
			if opt_name in opts and opts[opt_name] == v.get('default', None):
				del opts[opt_name]

		# TODO: maybe allow this in the future
		# unknown_opts = get_unknown_opts(ctx)
		# opts.update(unknown_opts)

		inputs = opts.pop(input_type)
		inputs = expand_input(inputs, ctx)
		if sync or show:
			sync = True
		else:
			from secator.celery import is_celery_worker_alive
			worker_alive = is_celery_worker_alive()
			if not worker_alive and not worker:
				sync = True
			else:
				sync = False
				broker_protocol = CONFIG.celery.broker_url.split('://')[0]
				backend_protocol = CONFIG.celery.result_backend.split('://')[0]
				if CONFIG.celery.broker_url:
					if (broker_protocol == 'redis' or backend_protocol == 'redis') and not ADDONS_ENABLED['redis']:
						_get_rich_console().print('[bold red]Missing `redis` addon: please run `secator install addons redis`[/].')
						sys.exit(1)

		# Build hooks from driver name
		hooks = {}
		if driver == 'mongodb':
			if not ADDONS_ENABLED['mongodb']:
				_get_rich_console().print('[bold red]Missing `mongodb` addon: please run `secator install addons mongodb`[/].')
				sys.exit(1)
			from secator.hooks.mongodb import MONGODB_HOOKS
			hooks = MONGODB_HOOKS

		# Set run options
		opts.update({
			'print_cmd': True,
			'print_item': True,
			'print_line': True,
			'print_progress': True,
			'print_remote_info': not sync,
			'piped_input': ctx.obj['piped_input'],
			'piped_output': ctx.obj['piped_output'],
			'caller': 'cli',
			'sync': sync,
		})

		# Start runner
		runner = runner_cls(config, inputs, run_opts=opts, hooks=hooks, context=context)
		runner.run()

	generate_cli_subcommand(cli_endpoint, func, **command_opts)
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

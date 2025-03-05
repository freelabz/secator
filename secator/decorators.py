import sys

from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup

from secator.config import CONFIG
from secator.definitions import ADDONS_ENABLED, OPT_NOT_SUPPORTED
from secator.runners import Scan, Task, Workflow
from secator.utils import (deduplicate, expand_input, get_command_category)

RUNNER_OPTS = {
	'output': {'type': str, 'default': None, 'help': 'Output options (-o table,json,csv,gdrive)', 'short': 'o'},
	'workspace': {'type': str, 'default': 'default', 'help': 'Workspace', 'short': 'ws'},
	'print_json': {'is_flag': True, 'short': 'json', 'default': False, 'help': 'Print items as JSON lines'},
	'print_raw': {'is_flag': True, 'short': 'raw', 'default': False, 'help': 'Print items in raw format'},
	'print_stat': {'is_flag': True, 'short': 'stat', 'default': False, 'help': 'Print runtime statistics'},
	'print_format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	'enable_profiler': {'is_flag': True, 'short': 'prof', 'default': False, 'help': 'Enable runner profiling'},
	'show': {'is_flag': True, 'default': False, 'help': 'Show command that will be run (tasks only)'},
	'no_process': {'is_flag': True, 'default': False, 'help': 'Disable secator processing'},
	# 'filter': {'default': '', 'short': 'f', 'help': 'Results filter', 'short': 'of'}, # TODO add this
	'quiet': {'is_flag': True, 'default': False, 'help': 'Enable quiet mode'},
}

RUNNER_GLOBAL_OPTS = {
	'sync': {'is_flag': True, 'help': 'Run tasks synchronously (automatic if no worker is alive)'},
	'worker': {'is_flag': True, 'default': False, 'help': 'Run tasks in worker'},
	'no_poll': {'is_flag': True, 'default': False, 'help': 'Do not live poll for tasks results when running in worker'},
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


def get_command_options(config):
	"""Get unified list of command options from a list of secator tasks classes and optionally a Runner config.

	Args:
		config (TemplateLoader): Current runner config.

	Returns:
		list: List of deduplicated options.
	"""
	from secator.utils import debug
	opt_cache = []
	all_opts = OrderedDict({})
	tasks = config.flat_tasks
	tasks_cls = set([c['class'] for c in tasks.values()])

	# Loop through tasks and set options
	for cls in tasks_cls:
		opts = OrderedDict(RUNNER_GLOBAL_OPTS, **RUNNER_OPTS, **cls.meta_opts, **cls.opts)

		# Find opts defined in config corresponding to this task class
		# TODO: rework this as this ignores subsequent tasks of the same task class
		task_config_opts = {}
		if config.type != 'task':
			for k, v in tasks.items():
				if v['class'] == cls:
					task_config_opts = v['opts']

		# Loop through options
		for opt, opt_conf in opts.items():

			# Get opt key map if any
			opt_key_map = getattr(cls, 'opt_key_map', {})

			# Opt is not supported by this task
			if opt not in opt_key_map\
				and opt not in cls.opts\
				and opt not in RUNNER_OPTS\
				and opt not in RUNNER_GLOBAL_OPTS:
				continue

			# Opt is defined as unsupported
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

			# Get opt conf
			conf = opt_conf.copy()
			conf['show_default'] = True
			conf['prefix'] = prefix
			opt_default = conf.get('default', None)
			opt_is_flag = conf.get('is_flag', False)
			opt_value_in_config = task_config_opts.get(opt)

			# Check if opt already defined in config
			if opt_value_in_config:
				if conf.get('required', False):
					debug('OPT (skipped: opt is required and defined in config)', obj={'opt': opt}, sub=f'cli.{config.name}', verbose=True)  # noqa: E501
					continue
				mapped_value = cls.opt_value_map.get(opt)
				if callable(mapped_value):
					opt_value_in_config = mapped_value(opt_value_in_config)
				elif mapped_value:
					opt_value_in_config = mapped_value
				if opt_value_in_config != opt_default:
					if opt in opt_cache:
						continue
					if opt_is_flag:
						conf['reverse'] = True
						conf['default'] = not conf['default']
					# print(f'{opt}: change default to {opt_value_in_config}')
					conf['default'] = opt_value_in_config

			# If opt is a flag but the default is True, add opposite flag
			if opt_is_flag and opt_default is True:
				conf['reverse'] = True

			# Check if opt already processed before
			if opt in opt_cache:
				# debug('OPT (skipped: opt is already in opt cache)', obj={'opt': opt}, sub=f'cli.{config.name}', verbose=True)
				continue

			# Build help
			opt_cache.append(opt)
			opt = opt.replace('_', '-')
			all_opts[opt] = conf

			# Debug
			debug_conf = OrderedDict({'opt': opt, 'config_val': opt_value_in_config or 'N/A', **conf.copy()})
			debug('OPT', obj=debug_conf, sub=f'cli.{config.name}', verbose=True)

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
			short_opt = conf.pop('short', None)
			conf.pop('internal', None)
			conf.pop('prefix', None)
			conf.pop('shlex', None)
			conf.pop('meta', None)
			conf.pop('supported', None)
			conf.pop('process', None)
			reverse = conf.pop('reverse', False)
			long = f'--{opt_name}'
			short = f'-{short_opt}' if short_opt else f'-{opt_name}'
			if reverse:
				long += f'/--no-{opt_name}'
				short += f'/-n{short_opt}' if short else f'/-n{opt_name}'
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
		runner_cls = Scan
		short_help = config.description or ''
		short_help += f' [dim]alias: {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help
		})

	elif cli_endpoint.name == 'workflow':
		runner_cls = Workflow
		short_help = config.description or ''
		short_help = f'{short_help:<55} [dim](alias)[/][bold cyan] {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help
		})

	elif cli_endpoint.name == 'task':
		runner_cls = Task
		input_required = False  # allow targets from stdin
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
	options = get_command_options(config)

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

		# Expand input
		inputs = opts.pop(input_type)
		inputs = expand_input(inputs, ctx)

		# Build hooks from driver name
		hooks = []
		drivers = driver.split(',') if driver else []
		console = _get_rich_console()
		supported_drivers = ['mongodb', 'gcs']
		for driver in drivers:
			if driver in supported_drivers:
				if not ADDONS_ENABLED[driver]:
					console.print(f'[bold red]Missing "{driver}" addon: please run `secator install addons {driver}`[/].')
					sys.exit(1)
				from secator.utils import import_dynamic
				driver_hooks = import_dynamic(f'secator.hooks.{driver}', 'HOOKS')
				if driver_hooks is None:
					console.print(f'[bold red]Missing "secator.hooks.{driver}.HOOKS".[/]')
					sys.exit(1)
				hooks.append(driver_hooks)
			else:
				supported_drivers_str = ', '.join([f'[bold green]{_}[/]' for _ in supported_drivers])
				console.print(f'[bold red]Driver "{driver}" is not supported.[/]')
				console.print(f'Supported drivers: {supported_drivers_str}')
				sys.exit(1)

		from secator.utils import deep_merge_dicts
		hooks = deep_merge_dicts(*hooks)

		# Enable sync or not
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

		from secator.utils import debug
		debug('Run options', obj=opts, sub='cli')

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

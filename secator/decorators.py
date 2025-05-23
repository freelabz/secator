import sys

from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console

from secator.config import CONFIG
from secator.click import CLICK_LIST
from secator.definitions import ADDONS_ENABLED, OPT_NOT_SUPPORTED
from secator.runners import Scan, Task, Workflow
from secator.tree import build_runner_tree
from secator.utils import (deduplicate, expand_input, get_command_category)


CLI_OPTS = {
	'output': {'type': str, 'default': None, 'help': 'Output options (-o table,json,csv,gdrive)', 'short': 'o'},
	'profiles': {'type': str, 'default': 'default', 'help': 'Profiles', 'short': 'pf'},
	'workspace': {'type': str, 'default': 'default', 'help': 'Workspace', 'short': 'ws'},
	'print_json': {'is_flag': True, 'short': 'json', 'default': False, 'help': 'Print items as JSON lines'},
	'print_raw': {'is_flag': True, 'short': 'raw', 'default': False, 'help': 'Print items in raw format'},
	'print_stat': {'is_flag': True, 'short': 'stat', 'default': False, 'help': 'Print runtime statistics'},
	'print_format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	'enable_profiler': {'is_flag': True, 'short': 'prof', 'default': False, 'help': 'Enable runner profiling'},
	'process': {'is_flag': True, 'short': 'nps', 'default': True, 'help': 'Enable secator processing', 'reverse': True},
	'quiet': {'is_flag': True, 'short': 'q', 'default': not CONFIG.cli.show_command_output, 'opposite': 'verbose', 'help': 'Enable quiet mode'},  # noqa: E501
	'dry_run': {'is_flag': True, 'short': 'dr', 'default': False, 'help': 'Enable dry run'},
	'show': {'is_flag': True, 'short': 'yml', 'default': False, 'help': 'Show runner yaml'},
	'tree': {'is_flag': True, 'short': 'tree', 'default': False, 'help': 'Show runner tree'},
	'version': {'is_flag': True, 'help': 'Show version'},
}

CLI_GLOBAL_OPTS = {
	'sync': {'is_flag': True, 'help': 'Run tasks locally or in worker', 'opposite': 'worker'},
	'no_poll': {'is_flag': True, 'short': 'np', 'default': False, 'help': 'Do not live poll for tasks results when running in worker'},  # noqa: E501
	'driver': {'type': str, 'help': 'Export real-time results. E.g: "mongodb"'},
}

DEFAULT_CLI_OPTIONS = list(CLI_OPTS.keys()) + list(CLI_GLOBAL_OPTS.keys())


def task():
	def decorator(cls):
		cls.__task__ = True
		return cls
	return decorator


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
			internal = conf.pop('internal', False)
			display = conf.pop('display', True)
			if internal and not display:
				continue
			conf.pop('prefix', None)
			conf.pop('shlex', None)
			conf.pop('meta', None)
			conf.pop('supported', None)
			conf.pop('process', None)
			conf.pop('pre_process', None)
			conf.pop('requires_sudo', None)
			reverse = conf.pop('reverse', False)
			opposite = conf.pop('opposite', None)
			long = f'--{opt_name}'
			short = f'-{short_opt}' if short_opt else f'-{opt_name}'
			if reverse:
				if opposite:
					long += f'/--{opposite}'
					short += f'/-{opposite}'
					conf['help'] = conf['help'].replace(opt_name, f'{opt_name} / {opposite}')
				else:
					long += f'/--no-{opt_name}'
					short += f'/-n{short_opt}' if short_opt else f'/-n{opt_name}'
			f = click.option(long, short, **conf)(f)
		return f
	return decorator


def get_command_options(config):
	"""Get unified list of command options.

	Args:
		config (TemplateLoader): Current runner config.

	Returns:
		list: List of deduplicated options.
	"""
	# TODO: refactor this function to use runner.supported_opts instead.
	from secator.utils import debug
	opt_cache = []
	all_opts = OrderedDict({})
	runner_opts = config.options.toDict()
	runner_default_opts = config.default_options.toDict()
	tasks = config.flat_tasks
	tasks_cls = set([c['class'] for c in tasks.values()])

	# Get runner children options (for scans)
	children = config._extract_workflows()
	for child in children.values():
		if not child:
			continue
		for k, v in child.options.toDict().items():
			if k not in runner_opts:
				runner_opts[k] = v
				runner_opts[k]['meta'] = child.name
			if k not in runner_default_opts:
				runner_default_opts[k] = v['default']

	# Convert YAML options to CLI options
	for k, v in runner_opts.items():
		if 'type' in v:
			type_mapping = {'str': str, 'list': CLICK_LIST, 'int': int, 'float': float}
			type_str = v['type']
			runner_opts[k]['type'] = type_mapping.get(type_str, str)

	# Loop through tasks and set options
	for cls in tasks_cls:
		opts = OrderedDict(CLI_GLOBAL_OPTS, **CLI_OPTS, **cls.meta_opts, **cls.opts, **runner_opts)

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

			# Opt is not supported by this runner
			if opt not in opt_key_map\
				and opt not in cls.opts\
				and opt not in CLI_OPTS\
				and opt not in CLI_GLOBAL_OPTS\
				and opt not in runner_opts:
				continue

			# Opt is defined as unsupported
			if opt_key_map.get(opt) == OPT_NOT_SUPPORTED:
				continue

			# Get opt prefix
			prefix = None
			if opt in cls.opts:
				prefix = cls.__name__
			elif opt in cls.meta_opts:
				prefix = 'Meta'
			elif opt in runner_opts:
				prefix = opt_conf.get('meta', config.type)
			elif opt in CLI_OPTS:
				prefix = 'Output'
			elif opt in CLI_GLOBAL_OPTS:
				prefix = 'Execution'

			# Get opt value from YAML config
			opt_conf_value = task_config_opts.get(opt) or runner_default_opts.get(opt)

			# Get opt conf
			conf = opt_conf.copy()
			opt_is_flag = conf.get('is_flag', False)
			opt_default = conf.get('default', False if opt_is_flag else None)
			opt_is_required = conf.get('required', False)
			conf['show_default'] = True
			conf['prefix'] = prefix
			conf['default'] = opt_default
			conf['reverse'] = False

			# Change CLI opt defaults if opt was overriden in YAML config
			if opt_conf_value:
				if opt_is_required:  # required, but defined in config
					conf['required'] = False
				mapped_value = cls.opt_value_map.get(opt)
				if callable(mapped_value):
					opt_conf_value = mapped_value(opt_conf_value)
				elif mapped_value:
					opt_conf_value = mapped_value

				# Handle option defaults
				if opt_conf_value != opt_default:
					if opt in opt_cache:
						continue
					if opt_is_flag:
						conf['default'] = opt_default = opt_conf_value

			# Add reverse flag
			if isinstance(opt_default, bool):
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
			debug_conf = OrderedDict({'opt': opt, 'config_val': opt_conf_value or 'N/A', **conf.copy()})
			debug('OPT', obj=debug_conf, sub=f'cli.{config.name}', verbose=True)

	return all_opts


def generate_cli_subcommand(cli_endpoint, func, **opts):
	return cli_endpoint.command(**opts)(func)


def register_runner(cli_endpoint, config):
	name = config.name
	input_required = True
	command_opts = {
		'no_args_is_help': True,
		'context_settings': {
			'ignore_unknown_options': False,
			'allow_extra_args': False
		}
	}

	if cli_endpoint.name == 'scan':
		runner_cls = Scan
		input_required = False  # allow targets from stdin
		short_help = config.description or ''
		short_help += f' [dim]alias: {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help,
			'no_args_is_help': False
		})
		input_types = config.input_types

	elif cli_endpoint.name == 'workflow':
		runner_cls = Workflow
		input_required = False  # allow targets from stdin
		short_help = config.description or ''
		short_help = f'{short_help:<55} [dim](alias)[/][bold cyan] {config.alias}' if config.alias else ''
		command_opts.update({
			'name': name,
			'short_help': short_help,
			'no_args_is_help': False
		})
		input_types = config.input_types

	elif cli_endpoint.name == 'task':
		runner_cls = Task
		input_required = False  # allow targets from stdin
		task_cls = Task.get_task_class(config.name)
		task_category = get_command_category(task_cls)
		short_help = f'[magenta]{task_category:<25}[/] {task_cls.__doc__}'
		command_opts.update({
			'name': name,
			'short_help': short_help,
			'no_args_is_help': False
		})
		input_types = task_cls.input_types

	else:
		raise ValueError(f"Unrecognized runner endpoint name {cli_endpoint.name}")
	input_types_str = '|'.join(input_types) if input_types else 'targets'
	options = get_command_options(config)

	# TODO: maybe allow this in the future
	# def get_unknown_opts(ctx):
	# 	return {
	# 		(ctx.args[i][2:]
	# 		if str(ctx.args[i]).startswith("--") \
	# 		else ctx.args[i][1:]): ctx.args[i+1]
	# 		for i in range(0, len(ctx.args), 2)
	# 	}

	@click.argument(input_types_str, required=input_required)
	@decorate_command_options(options)
	@click.pass_context
	def func(ctx, **opts):
		console = _get_rich_console()
		version = opts['version']
		sync = opts['sync']
		ws = opts.pop('workspace')
		driver = opts.pop('driver', '')
		quiet = opts['quiet']
		dry_run = opts['dry_run']
		show = opts['show']
		tree = opts['tree']
		context = {'workspace_name': ws}
		ctx.obj['dry_run'] = dry_run

		# Show version
		if version:
			data = task_cls.get_version_info()
			current = data['version']
			latest = data['latest_version']
			installed = data['installed']
			if not installed:
				console.print(f'[bold red]{task_cls.__name__} is not installed.[/]')
			else:
				console.print(f'{task_cls.__name__} version: [bold green]{current}[/] (recommended: [bold green]{latest}[/])')
			sys.exit(0)

		# Show runner yaml
		if show:
			config.print()
			sys.exit(0)

		# Show runner tree
		if tree:
			tree = build_runner_tree(config)
			console.print(tree.render_tree())
			sys.exit(0)

		# TODO: maybe allow this in the future
		# unknown_opts = get_unknown_opts(ctx)
		# opts.update(unknown_opts)

		# Expand input
		inputs = opts.pop(input_types_str)
		inputs = expand_input(inputs, ctx)

		# Build hooks from driver name
		hooks = []
		drivers = driver.split(',') if driver else []
		supported_drivers = ['mongodb', 'gcs']
		actual_drivers = []
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
				actual_drivers.append(driver)
			else:
				supported_drivers_str = ', '.join([f'[bold green]{_}[/]' for _ in supported_drivers])
				console.print(f'[bold red]Driver "{driver}" is not supported.[/]')
				console.print(f'Supported drivers: {supported_drivers_str}')
				sys.exit(1)

		from secator.utils import deep_merge_dicts
		hooks = deep_merge_dicts(*hooks)

		# Enable sync or not
		if sync or dry_run:
			sync = True
		else:
			from secator.celery import is_celery_worker_alive
			worker_alive = is_celery_worker_alive()
			if not worker_alive and not sync:
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
			'print_profiles': True,
			'print_start': True,
			'print_end': True,
			'print_remote_info': not sync,
			'piped_input': ctx.obj['piped_input'],
			'piped_output': ctx.obj['piped_output'],
			'caller': 'cli',
			'sync': sync,
			'quiet': quiet
		})

		# Start runner
		runner = runner_cls(config, inputs, run_opts=opts, hooks=hooks, context=context)
		runner.run()

	generate_cli_subcommand(cli_endpoint, func, **command_opts)
	generate_rich_click_opt_groups(cli_endpoint, name, input_types, options)


def generate_rich_click_opt_groups(cli_endpoint, name, input_types, options):
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
			'options': input_types,
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

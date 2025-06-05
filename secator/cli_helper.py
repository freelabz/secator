import datetime
import os
import re
import sys

from collections import OrderedDict
from contextlib import nullcontext

import psutil
import rich_click as click
from rich_click.rich_click import _get_rich_console

from secator.config import CONFIG
from secator.click import CLICK_LIST
from secator.definitions import ADDONS_ENABLED
from secator.runners import Scan, Task, Workflow
from secator.template import get_config_options
from secator.tree import build_runner_tree
from secator.utils import (deduplicate, expand_input, get_command_category)
from secator.loader import get_configs_by_type


WORKSPACES = next(os.walk(CONFIG.dirs.reports))[1]
WORKSPACES_STR = '|'.join([f'[dim yellow3]{_}[/]' for _ in WORKSPACES])
PROFILES_STR = ','.join([f'[dim yellow3]{_.name}[/]' for _ in get_configs_by_type('profile')])
DRIVERS_STR = ','.join([f'[dim yellow3]{_}[/]' for _ in ['mongodb', 'gcs']])
DRIVER_DEFAULTS_STR = ','.join(CONFIG.drivers.defaults) if CONFIG.drivers.defaults else None
PROFILE_DEFAULTS_STR = ','.join(CONFIG.profiles.defaults) if CONFIG.profiles.defaults else None
EXPORTERS_STR = ','.join([f'[dim yellow3]{_}[/]' for _ in ['csv', 'gdrive', 'json', 'table', 'txt']])

CLI_OUTPUT_OPTS = {
	'output': {'type': str, 'default': None, 'help': f'Output options [{EXPORTERS_STR}] [dim orange4](comma-separated)[/]', 'short': 'o'},  # noqa: E501
	'fmt': {'default': '', 'short': 'fmt', 'internal_name': 'print_format', 'help': 'Output formatting string'},
	'json': {'is_flag': True, 'short': 'json', 'internal_name': 'print_json', 'default': False, 'help': 'Print items as JSON lines'},  # noqa: E501
	'raw': {'is_flag': True, 'short': 'raw', 'internal_name': 'print_raw', 'default': False, 'help': 'Print items in raw format'},  # noqa: E501
	'stat': {'is_flag': True, 'short': 'stat', 'internal_name': 'print_stat', 'default': False, 'help': 'Print runtime statistics'},  # noqa: E501
	'quiet': {'is_flag': True, 'short': 'q', 'default': not CONFIG.cli.show_command_output, 'opposite': 'verbose', 'help': 'Hide or show original command output'},  # noqa: E501
	'yaml': {'is_flag': True, 'short': 'yaml', 'default': False, 'help': 'Show runner yaml'},
	'tree': {'is_flag': True, 'short': 'tree', 'default': False, 'help': 'Show runner tree'},
	'dry_run': {'is_flag': True, 'short': 'dry', 'default': False, 'help': 'Show dry run'},
	'process': {'is_flag': True, 'short': 'ps', 'default': True, 'help': 'Enable / disable secator processing', 'reverse': True},  # noqa: E501
	'version': {'is_flag': True, 'help': 'Show runner version'},
}

CLI_EXEC_OPTS = {
	'workspace': {'type': str, 'default': 'default', 'help': f'Workspace [{WORKSPACES_STR}|[dim orange4]<new>[/]]', 'short': 'ws'},  # noqa: E501
	'profiles': {'type': str, 'help': f'Profiles [{PROFILES_STR}] [dim orange4](comma-separated)[/]', 'default': PROFILE_DEFAULTS_STR, 'short': 'pf'},  # noqa: E501
	'driver': {'type': str, 'help': f'Drivers [{DRIVERS_STR}] [dim orange4](comma-separated)[/]', 'default': DRIVER_DEFAULTS_STR},  # noqa: E501
	'sync': {'is_flag': True, 'help': 'Run tasks locally or in worker', 'opposite': 'worker'},
	'no_poll': {'is_flag': True, 'short': 'np', 'default': False, 'help': 'Do not live poll for tasks results when running in worker'},  # noqa: E501
	'enable_pyinstrument': {'is_flag': True, 'short': 'pyinstrument', 'default': False, 'help': 'Enable pyinstrument profiling'},  # noqa: E501
	'enable_memray': {'is_flag': True, 'short': 'memray', 'default': False, 'help': 'Enable memray profiling'},
}

CLI_TYPE_MAPPING = {
	'str': str,
	'list': CLICK_LIST,
	'int': int,
	'float': float,
	# 'choice': click.Choice,
	# 'file': click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
	# 'dir': click.Path(exists=True, file_okay=False, dir_okay=True, readable=True),
	# 'path': click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
	# 'url': click.URL,
}

DEFAULT_CLI_OPTIONS = list(CLI_OUTPUT_OPTS.keys()) + list(CLI_EXEC_OPTS.keys())


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
			internal_name = conf.pop('internal_name', None)
			if internal and not display:
				continue
			conf.pop('shlex', None)
			conf.pop('meta', None)
			conf.pop('supported', None)
			conf.pop('process', None)
			conf.pop('pre_process', None)
			conf.pop('requires_sudo', None)
			conf.pop('prefix', None)
			applies_to = conf.pop('applies_to', None)
			default_from = conf.pop('default_from', None)
			reverse = conf.pop('reverse', False)
			opposite = conf.pop('opposite', None)
			long = f'--{opt_name}'
			short = f'-{short_opt}' if short_opt else f'-{opt_name}'
			if reverse:
				if opposite:
					long += f'/--{opposite}'
					short += f'/-{opposite}' if len(short) > 2 else f'/-{opposite[0]}'
					conf['help'] = conf['help'].replace(opt_name, f'{opt_name} / {opposite}')
				else:
					long += f'/--no-{opt_name}'
					short += f'/-n{short_opt}' if short_opt else f'/-n{opt_name}'
			if applies_to:
				applies_to_str = ", ".join(f'[bold yellow3]{_}[/]' for _ in applies_to)
				conf['help'] += rf' \[[dim]{applies_to_str}[/]]'
			if default_from:
				conf['help'] += rf' \[[dim]default from: [dim yellow3]{default_from}[/][/]]'
			args = [long, short]
			if internal_name:
				args.append(internal_name)
			f = click.option(*args, **conf)(f)
		return f
	return decorator


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
	options = get_config_options(
		config,
		exec_opts=CLI_EXEC_OPTS,
		output_opts=CLI_OUTPUT_OPTS,
		type_mapping=CLI_TYPE_MAPPING
	)

	# TODO: maybe allow this in the future
	# def get_unknown_opts(ctx):
	# 	return {
	# 		(ctx.args[i][2:]
	# 		if str(ctx.args[i]).startswith("--") \
	# 		else ctx.args[i][1:]): ctx.args[i+1]
	# 		for i in range(0, len(ctx.args), 2)
	# 	}

	@click.argument('inputs', metavar=input_types_str, required=input_required)
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
		yaml = opts['yaml']
		tree = opts['tree']
		context = {'workspace_name': ws}
		enable_pyinstrument = opts['enable_pyinstrument']
		enable_memray = opts['enable_memray']
		contextmanager = nullcontext()
		process = None

		# Set dry run
		ctx.obj['dry_run'] = dry_run

		# Show version
		if version:
			if not cli_endpoint.name == 'task':
				console.print(f'[bold red]Version information is not available for {cli_endpoint.name}.[/]')
				sys.exit(1)
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
		if yaml:
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
		inputs = opts.pop('inputs')
		inputs = expand_input(inputs, ctx)

		# Build hooks from driver name
		hooks = []
		drivers = driver.split(',') if driver else []
		drivers = list(set(CONFIG.drivers.defaults + drivers))
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

		if enable_pyinstrument or enable_memray:
			if not ADDONS_ENABLED["trace"]:
				console.print(
					'[bold red]Missing "trace" addon: please run `secator install addons trace`[/].'
				)
				sys.exit(1)
			import memray
			output_file = f'trace_memray_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.bin'
			contextmanager = memray.Tracker(output_file)

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
				if CONFIG.celery.broker_url and \
				   (broker_protocol == 'redis' or backend_protocol == 'redis') \
				   and not ADDONS_ENABLED['redis']:
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
			'print_target': True,
			'print_end': True,
			'print_remote_info': not sync,
			'piped_input': ctx.obj['piped_input'],
			'piped_output': ctx.obj['piped_output'],
			'caller': 'cli',
			'sync': sync,
			'quiet': quiet
		})

		# Start runner
		with contextmanager:
			if enable_memray:
				process = psutil.Process()
				console.print(
					f"[bold yellow3]Initial RAM Usage: {process.memory_info().rss / 1024 ** 2} MB[/]"
				)
			item_count = 0
			runner = runner_cls(
				config, inputs, run_opts=opts, hooks=hooks, context=context
			)
			for item in runner:
				del item
				item_count += 1
				if process and item_count % 100 == 0:
					console.print(
						f"[bold yellow3]RAM Usage: {process.memory_info().rss / 1024 ** 2} MB[/]"
					)

		if enable_memray:
			console.print(f"[bold green]Memray output file: {output_file}[/]")
			os.system(f"memray flamegraph {output_file}")

	generate_cli_subcommand(cli_endpoint, func, **command_opts)
	generate_rich_click_opt_groups(cli_endpoint, name, input_types, options)


def generate_rich_click_opt_groups(cli_endpoint, name, input_types, options):
	sortorder = {
		'Execution': 0,
		'Output': 1,
		'Meta': 2,
		'Config.*': 3,
		'Shared task': 4,
		'Task.*': 5,
		'Workflow.*': 6,
		'Scan.*': 7,
	}

	def match_sort_order(prefix):
		for k, v in sortorder.items():
			if re.match(k, prefix):
				return v
		return 8

	prefixes = deduplicate([opt['prefix'] for opt in options.values()])
	prefixes = sorted(prefixes, key=match_sort_order)
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
		if prefix not in ['Execution', 'Output']:
			prefix_opts = sorted(prefix_opts)
		opt_names = [f'--{opt_name}' for opt_name in prefix_opts]
		if prefix == 'Output':
			opt_names.append('--help')
		opt_group.append({
			'name': prefix + ' options',
			'options': opt_names
		})
	aliases = [cli_endpoint.name, *cli_endpoint.aliases]
	for alias in aliases:
		endpoint_name = f'secator {alias} {name}'
		click.rich_click.OPTION_GROUPS[endpoint_name] = opt_group

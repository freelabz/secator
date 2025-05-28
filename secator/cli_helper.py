import os
import sys
from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console

from secator.config import CONFIG
from secator.click import CLICK_LIST
from secator.definitions import ADDONS_ENABLED
from secator.runners import Scan, Task, Workflow
from secator.template import TemplateLoader
from secator.tree import build_runner_tree
from secator.utils import (deduplicate, expand_input, get_command_category)
from secator.loader import get_configs_by_type


WORKSPACES = next(os.walk(CONFIG.dirs.reports))[1]

WORKSPACES_STR = '|'.join([f'[dim yellow3]{_}[/]' for _ in WORKSPACES])

CLI_OUTPUT_OPTS = {
	'output': {'type': str, 'default': None, 'help': 'Output options (-o table,json,csv,gdrive)', 'short': 'o'},
	'print_json': {'is_flag': True, 'short': 'json', 'default': False, 'help': 'Print items as JSON lines'},
	'print_raw': {'is_flag': True, 'short': 'raw', 'default': False, 'help': 'Print items in raw format'},
	'print_stat': {'is_flag': True, 'short': 'stat', 'default': False, 'help': 'Print runtime statistics'},
	'print_format': {'default': '', 'short': 'fmt', 'help': 'Output formatting string'},
	'enable_profiler': {'is_flag': True, 'short': 'prof', 'default': False, 'help': 'Enable runner profiling'},
	'quiet': {'is_flag': True, 'short': 'q', 'default': not CONFIG.cli.show_command_output, 'opposite': 'verbose', 'help': 'Enable quiet mode'},  # noqa: E501
	'show': {'is_flag': True, 'short': 'yml', 'default': False, 'help': 'Show runner yaml'},
	'tree': {'is_flag': True, 'short': 'tree', 'default': False, 'help': 'Show runner tree'},
	'version': {'is_flag': True, 'help': 'Show version'},
}

CLI_EXEC_OPTS = {
	'driver': {'type': click.Choice(['mongodb', 'gcs']), 'help': 'Drivers'},
	'profiles': {'type': click.Choice([p.name for p in get_configs_by_type('profile')]), 'default': 'default', 'help': 'Profiles', 'short': 'pf'},  # noqa: E501
	'workspace': {'type': str, 'default': 'default', 'help': f'Workspace ({WORKSPACES_STR}|[dim yellow3]<new>[/])', 'short': 'ws'},  # noqa: E501
	'dry_run': {'is_flag': True, 'short': 'dr', 'default': False, 'help': 'Enable dry run'},
	'sync': {'is_flag': True, 'help': 'Run tasks locally or in worker', 'opposite': 'worker'},
	'no_poll': {'is_flag': True, 'short': 'np', 'default': False, 'help': 'Do not live poll for tasks results when running in worker'},  # noqa: E501
	'process': {'is_flag': True, 'short': 'nps', 'default': True, 'help': 'Enable secator processing', 'reverse': True},
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
			if internal and not display:
				continue
			conf.pop('shlex', None)
			conf.pop('meta', None)
			conf.pop('supported', None)
			conf.pop('process', None)
			conf.pop('pre_process', None)
			conf.pop('requires_sudo', None)
			conf.pop('prefix', None)
			extra = conf.pop('extra', None)
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
			if extra:
				conf['help'] += f' [dim yellow3]\[{extra}][/]'
			f = click.option(long, short, **conf)(f)
		return f
	return decorator


def get_command_options(config):
	from secator.tree import build_runner_tree, walk_runner_tree, get_flat_node_list
	from secator.utils import debug
	if config.type == 'task':
		fake_config = TemplateLoader({
			'name': config.name,
			'type': 'workflow',
			'tasks': {config.name: {}}
		})
		config = fake_config
	tree = build_runner_tree(config)
	nodes = get_flat_node_list(tree)
	all_opts = OrderedDict({})
	default_opts = config.default_options.toDict()

	# Gather all task options
	all_task_opts = {}
	for node in nodes:
		if node.type != 'task':
			continue
		task = Task.get_task_class(node.name)
		all_task_opts[node.id] = list(task.opts.keys())
		all_task_opts[node.id].extend(list(task.meta_opts.keys()))
	# debug(f'all_task_opts: {all_task_opts}', sub=f'cli.{config.name}')

	# Gather global runner options
	debug(f'[magenta]{config.name}[/]', sub=f'cli.{config.name}')
	debug(f'{tree.render_tree()}', sub=f'cli.{config.name}')

	# Add global options
	for opt in CLI_EXEC_OPTS:
		opt_conf = CLI_EXEC_OPTS[opt].copy()
		opt_conf['prefix'] = 'Execution'
		all_opts[opt] = opt_conf

	for opt in CLI_OUTPUT_OPTS:
		opt_conf = CLI_OUTPUT_OPTS[opt].copy()
		opt_conf['prefix'] = 'Output'
		all_opts[opt] = opt_conf

	def find_same_opts(node, nodes, opt_name, check_class_opts=False):
		"""Find options with the same name that are defined in other nodes of the same type."""
		same_opts = []
		task_cls = None
		opts_to_check = node.opts.keys()
		if check_class_opts:
			task_cls = Task.get_task_class(node.name)
			opts_to_check = task_cls.opts.keys()
		for k in opts_to_check:
			for _ in nodes:
				if _.id == node.id or _.type != node.type:
					continue
				if k != opt_name:
					continue
				node_task = None
				if task_cls:
					node_task = Task.get_task_class(_.name)
					if k not in node_task.opts.keys():
						continue
					opts_value = node_task.opts[k]
				else:
					if k not in _.opts.keys():
						continue
					opts_value = _.opts[k]
				name_str = 'nodes' if not check_class_opts else 'tasks'
				debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{opt_name}[/] found in other {name_str} [bold blue]{_.id}[/]', sub=f'cli.{config.name}.same', verbose=True)  # noqa: E501
				same_opts.append({
					'id': _.id,
					'task_name': node_task.__name__ if check_class_opts else None,
					'name': _.name,
					'value': opts_value,
				})
		if same_opts:
			other_tasks = ", ".join([f'[bold yellow]{_["id"]}[/]' for _ in same_opts])
			debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{opt_name}[/] found in {len(same_opts)} other {name_str}: {other_tasks}', sub=f'cli.{config.name}.same', verbose=True)  # noqa: E501
		return same_opts

	def process_node(node):
		debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] ({node.type})', sub=f'cli.{config.name}')

		if node.type not in ['task', 'workflow']:
			return

		# Process workflow options
		if node.type == 'workflow':
			node_id_str = node.id.replace('.', '_').replace('/', '_')
			for k, v in node.opts.items():
				same_opts = find_same_opts(node, nodes, k)
				conf = v.copy()
				opt_name = k
				short = conf.get('short')
				conf['prefix'] = f'{node.type} {node.name}'
				if 'type' in v:
					type_mapping = {'str': str, 'list': CLICK_LIST, 'int': int, 'float': float}
					type_str = v['type']
					conf['type'] = type_mapping.get(type_str, str)
				if len(same_opts) > 0:  # change opt name to avoid conflict
					conf['prefix'] = f'{node.type} {node.name}'
					new_name = f'{node.name.replace("/", "_")}'
					conf['short'] = f'{new_name}_{short}' if short else short
					opt_name = f'{new_name}_{k}'
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] renamed to [bold green]{opt_name}[/] [dim red](duplicated)[/]', sub=f'cli.{config.name}')  # noqa: E501
				all_opts[opt_name] = conf
			return

		# Process task options
		cls = Task.get_task_class(node.name)
		task_opts = cls.opts.copy()
		task_meta_opts = cls.meta_opts.copy()
		task_opts_all = {**task_opts, **task_meta_opts}
		node_opts = node.opts or {}
		node_id_str = node.id.replace('.', '_').replace('/', '_')
		same_task_name = any(_.name == node.name and _.id != node.id for _ in nodes)
		for k, v in task_opts_all.items():
			conf = v.copy()
			conf['prefix'] = cls.__name__
			config_default = node_opts.get(k) or default_opts.get(k)
			opt_name = k
			short = conf.get('short')
			same_opts = find_same_opts(node, nodes, k)
			if config_default:
				conf['required'] = False
				conf['default'] = config_default
				if node_opts.get(k):
					conf['extra'] = f'default from: {node.id}'
				elif default_opts.get(k):
					conf['extra'] = f'default from: {config.type}{config.name}'
				mapped_value = cls.opt_value_map.get(opt_name)
				if mapped_value:
					if callable(mapped_value):
						config_default = mapped_value(config_default)
					else:
						config_default = mapped_value
				conf['default'] = config_default
				if len(same_opts) > 0:  # change opt name to avoid conflict
					new_name = f'{node_id_str}' if same_task_name else f'{node.name.replace("/", "_")}'
					conf['short'] = f'{new_name}_{short}' if short else short
					opt_name = f'{new_name}_{k}'
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] renamed to [bold green]{opt_name}[/] [dim red](default set in config)[/]', sub=f'cli.{config.name}')  # noqa: E501
			elif k in task_meta_opts:
				debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] changed prefix to [bold cyan]Meta[/]', sub=f'cli.{config.name}')  # noqa: E501
				conf['prefix'] = 'Meta'
			elif k in task_opts:
				conf['prefix'] = cls.__name__
				same_opts = find_same_opts(node, nodes, k, check_class_opts=True)
				if len(same_opts) > 0:
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] changed prefix to [bold cyan]Common[/] [dim red](duplicated {len(same_opts)} times)[/]', sub=f'cli.{config.name}')  # noqa: E501
					conf['prefix'] = 'Shared task'
					applies_to = set([_['name'] for _ in same_opts] + [node.name])
					applies_to_str = ", ".join(applies_to)
					conf['extra'] = f'applies to: {applies_to_str}'
			else:
				raise ValueError(f'Unknown option {k} for task {node.id}')
			opt_name = opt_name.replace('_', '-')
			if short:
				conf['short'] = conf['short'].replace('_', '-')
			all_opts[opt_name] = conf

	walk_runner_tree(tree, process_node)

	# Process root runner options
	runner_opts = config.options.toDict()
	for k, v in runner_opts.items():
		all_opts[k] = v
		all_opts[k]['prefix'] = f'{config.type}'
		if 'type' in v:
			type_mapping = {'str': str, 'list': CLICK_LIST, 'int': int, 'float': float}
			type_str = v['type']
			all_opts[k]['type'] = type_mapping.get(type_str, str)

	# Normalize all options
	debug('[bold yellow3]All opts processed. Showing defaults:[/]', sub=f'cli.{config.name}')
	normalized_opts = OrderedDict({})
	for k, v in all_opts.items():
		v['reverse'] = False
		v['show_default'] = True
		default = v.get('default', False)
		if isinstance(default, bool) and default is True:
			v['reverse'] = True
		k = k.replace('_', '-')
		debug(f'\t[bold]{k}[/] -> [bold green]{v.get("default", "N/A")}[/]', sub=f'cli.{config.name}')
		normalized_opts[k] = v
	return normalized_opts

# def get_command_options(config):
# 	"""Get unified list of command options.

# 	Args:
# 		config (TemplateLoader): Current runner config.

# 	Returns:
# 		list: List of deduplicated options.
# 	"""
# 	# TODO: refactor this function to use runner.supported_opts instead.
# 	from secator.utils import debug
# 	opt_cache = []
# 	all_opts = OrderedDict({})
# 	runner_opts = config.options.toDict()
# 	runner_default_opts = config.default_options.toDict()
# 	tasks = config.flat_tasks
# 	for name, task in tasks.items():
# 		task['class'] = Task.get_task_class(task['name'])

# 	# Get runner children options (for scans)
# 	children = config._extract_workflows()
# 	for child in children.values():
# 		if not child:
# 			continue
# 		for k, v in child.options.toDict().items():
# 			if k not in runner_opts:
# 				runner_opts[k] = v
# 				runner_opts[k]['meta'] = child.name
# 			if k not in runner_default_opts:
# 				runner_default_opts[k] = v['default']

# 	# Convert YAML options to Click options
# 	for k, v in runner_opts.items():
# 		if 'type' in v:
# 			type_mapping = {'str': str, 'list': CLICK_LIST, 'int': int, 'float': float}
# 			type_str = v['type']
# 			runner_opts[k]['type'] = type_mapping.get(type_str, str)

# 	# Loop through flat tasks and set options
# 	for id, task in tasks.items():
# 		name = task['name']
# 		cls = task['class']
# 		opts = OrderedDict(CLI_EXEC_OPTS, **CLI_OUTPUT_OPTS, **cls.meta_opts, **cls.opts, **runner_opts)

# 		# Find opts defined in config corresponding to this task class
# 		task_config_opts = {}
# 		if config.type != 'task':
# 			for _, v in tasks.items():
# 				if v['class'] == cls:
# 					task_config_opts = v['opts']

# 		# Loop through options
# 		for opt, opt_conf in opts.items():
# 			conf = opt_conf.copy()

# 			# Get opt key map if any
# 			opt_key_map = getattr(cls, 'opt_key_map', {})

# 			# Opt is not supported by this runner
# 			if opt not in opt_key_map\
# 				and opt not in cls.opts\
# 				and opt not in CLI_OUTPUT_OPTS\
# 				and opt not in CLI_EXEC_OPTS\
# 				and opt not in runner_opts:
# 				continue

# 			# Opt is defined as unsupported
# 			if opt_key_map.get(opt) == OPT_NOT_SUPPORTED:
# 				continue

# 			# Get opt prefix
# 			prefix = None
# 			if opt in cls.opts:
# 				prefix = name
# 			elif opt in cls.meta_opts:
# 				prefix = 'Meta'
# 			elif opt in runner_opts:
# 				prefix = opt_conf.get('meta', config.type)
# 			elif opt in CLI_OUTPUT_OPTS:
# 				prefix = 'Output'
# 			elif opt in CLI_EXEC_OPTS:
# 				prefix = 'Execution'

# 			# Get opt value from YAML config
# 			opt_conf_value = task_config_opts.get(opt) or runner_default_opts.get(opt)

# 			# Get opt conf
# 			opt_is_flag = conf.get('is_flag', False)
# 			opt_default = conf.get('default', False if opt_is_flag else None)
# 			opt_is_required = conf.get('required', False)
# 			conf['show_default'] = True
# 			conf['prefix'] = prefix
# 			conf['default'] = opt_default
# 			conf['reverse'] = False
# 			conf['extra'] = None

# 			# Change CLI opt defaults if opt was overriden in YAML config
# 			if opt_conf_value:
# 				conf['prefix'] = id
# 				print(f'setting prefix to {id}')
# 				conf['extra'] = f'config default: {opt_conf_value}'  # noqa: E501
# 				if opt_is_required:  # required, but defined in config
# 					conf['required'] = False
# 				mapped_value = cls.opt_value_map.get(opt)
# 				if callable(mapped_value):
# 					opt_conf_value = mapped_value(opt_conf_value)
# 				elif mapped_value:
# 					opt_conf_value = mapped_value

# 				# Handle option defaults
# 				if opt_conf_value != opt_default:
# 					if opt in opt_cache:
# 						continue
# 					if opt_is_flag:
# 						conf['default'] = opt_default = opt_conf_value

# 			# Add reverse flag
# 			if isinstance(opt_default, bool) and opt_default is True:
# 				conf['reverse'] = True

# 			# Check if opt already processed before
# 			# if opt in opt_cache:
# 			# 	conf['prefix'] = cls.__name__
# 			# 	# debug('OPT (skipped: opt is already in opt cache)', obj={'opt': opt}, sub=f'cli.{config.name}', verbose=True)
# 			# 	continue

# 			# Build help
# 			opt_cache.append(opt)
# 			opt = opt.replace('_', '-')
# 			all_opts[opt] = conf

# 			# Debug
# 			debug_conf = OrderedDict({'opt': opt, 'config_val': opt_conf_value or 'N/A', **conf.copy()})
# 			debug('OPT', obj=debug_conf, sub=f'cli.{config.name}', verbose=True)

# 	debug('\n', obj=all_opts, sub=f'cli.{config.name}.all', obj_breaklines=True, verbose=True)
# 	return all_opts


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
		show = opts['show']
		tree = opts['tree']
		context = {'workspace_name': ws}
		ctx.obj['dry_run'] = dry_run

		# Show version
		if version and cli_endpoint.name == 'task':
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
		inputs = opts.pop('inputs')
		inputs = expand_input(inputs, ctx)

		# Build hooks from driver name
		hooks = []
		drivers = driver.split(',') if driver else []
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

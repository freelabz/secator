import yaml

from collections import OrderedDict
from dotmap import DotMap
from pathlib import Path

from secator.output_types import Error
from secator.rich import console


class TemplateLoader(DotMap):

	def __init__(self, input={}, name=None, **kwargs):
		if name:
			split = name.split('/')
			if len(split) != 2:
				console.print(Error(message=f'Cannot load {name}: you should specify a type for the template when loading by name (e.g. workflow/<workflow_name>)'))  # noqa: E501
				return
			_type, _name = tuple(split)
			if _type.endswith('s'):
				_type = _type[:-1]
			from secator.loader import find_templates
			config = next((p for p in find_templates() if p['type'] == _type and p['name'] == _name), None)
			if not config:
				console.print(Error(message=f'Template {_type}/{_name} not found in loaded templates'))
				config = {}
		elif isinstance(input, dict):
			config = input
		elif isinstance(input, Path) or Path(input).exists():
			config = self._load_from_path(input)
			config['_path'] = str(input)
		elif isinstance(input, str):
			config = self._load(input)
		super().__init__(config, **kwargs)

	def _load_from_path(self, path):
		if not path.exists():
			console.print(Error(message=f'Config path {path} does not exists'))
			return
		with path.open('r') as f:
			return self._load(f.read())

	def _load(self, input):
		return yaml.load(input, Loader=yaml.Loader)

	def print(self):
		"""Print config as highlighted yaml."""
		config = self.toDict()
		_path = config.pop('_path', None)
		if _path:
			console.print(f'[italic green]{_path}[/]\n')
		yaml_str = yaml.dump(config, indent=4, sort_keys=False)
		from rich.syntax import Syntax
		yaml_highlight = Syntax(yaml_str, 'yaml', line_numbers=True)
		console.print(yaml_highlight)


def get_short_id(id_str, config_name):
	"""Remove config name prefix from ID string if present.

	Args:
		id_str: The ID string to process
		config_name: The config name prefix to remove

	Returns:
		str: ID string with prefix removed, or original string if no prefix found
	"""
	if id_str.startswith(config_name):
		return id_str.replace(config_name + '.', '')
	return id_str


def get_config_options(config, exec_opts=None, output_opts=None, type_mapping=None):
	"""Extract and normalize command-line options from configuration.

	Args:
		config: Configuration object (task, workflow, or scan)
		exec_opts: Execution options dictionary (optional)
		output_opts: Output options dictionary (optional)
		type_mapping: Type mapping for option types (optional)

	Returns:
		OrderedDict: Normalized options with metadata
	"""
	from secator.tree import build_runner_tree, walk_runner_tree, get_flat_node_list
	from secator.utils import debug
	from secator.runners.task import Task

	# Task config created on-the-fly
	if config.type == 'task':
		config = TemplateLoader({
			'name': config.name,
			'type': 'workflow',
			'tasks': {config.name: {}}
		})

	# Get main info
	tree = build_runner_tree(config)
	nodes = get_flat_node_list(tree)
	exec_opts = exec_opts or {}
	output_opts = output_opts or {}
	type_mapping = type_mapping or {}
	all_opts = OrderedDict({})

	# Log current config and tree
	debug(f'[magenta]{config.name}[/]', sub=f'cli.{config.name}')
	debug(f'{tree.render_tree()}', sub=f'cli.{config.name}')

	# Process global execution options
	for opt in exec_opts:
		opt_conf = exec_opts[opt].copy()
		opt_conf['prefix'] = 'Execution'
		all_opts[opt] = opt_conf

	# Process global output options
	for opt in output_opts:
		opt_conf = output_opts[opt].copy()
		opt_conf['prefix'] = 'Output'
		all_opts[opt] = opt_conf

	# Process config options
	# a.k.a:
	# - default YAML config options, defined in default_options: key in the runner YAML config
	# - new options defined in options: key in the runner YAML config
	config_opts_defaults = config.default_options.toDict()
	config_opts = config.options.toDict()
	for k, v in config_opts.items():
		all_opts[k] = v
		all_opts[k]['prefix'] = f'{config.type}'

	def find_same_opts(node, nodes, opt_name, check_class_opts=False):
		"""Find options with the same name that are defined in other nodes of the same type."""
		same_opts = []
		for _ in nodes:
			if _.id == node.id or _.type != node.type:
				continue
			node_task = None
			if check_class_opts:
				node_task = Task.get_task_class(_.name)
				if opt_name not in node_task.opts:
					continue
				opts_value = node_task.opts[opt_name]
			else:
				if opt_name not in _.opts:
					continue
				opts_value = _.opts[opt_name]
			name_str = 'nodes' if not check_class_opts else 'tasks'
			debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{opt_name}[/] found in other {name_str} [bold blue]{_.id}[/]', sub=f'cli.{config.name}.same', verbose=True)  # noqa: E501
			same_opts.append({
				'id': _.id,
				'task_name': node_task.__name__ if node_task else None,
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
		# a.k.a the new options defined in options: key in the workflow YAML config;
		if node.type == 'workflow':
			for k, v in node.opts.items():
				same_opts = find_same_opts(node, nodes, k)
				conf = v.copy()
				opt_name = k
				conf['prefix'] = f'{node.type.capitalize()} {node.name}'
				if len(same_opts) > 0:  # opt name conflict, change opt name
					opt_name = f'{node.name}.{k}'
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] renamed to [bold green]{opt_name}[/] [dim red](duplicated)[/]', sub=f'cli.{config.name}')  # noqa: E501
				all_opts[opt_name] = conf
			return

		# Process task options
		# a.k.a task options defined in their respective task classes
		cls = Task.get_task_class(node.name)
		task_opts = cls.opts.copy()
		task_opts_meta = cls.meta_opts.copy()
		task_opts_all = {**task_opts, **task_opts_meta}
		node_opts = node.opts or {}
		ancestor_opts_defaults = node.ancestor.default_opts or {}
		node_id_str = get_short_id(node.id, config.name)

		for k, v in task_opts_all.items():
			conf = v.copy()
			conf['prefix'] = f'Task {node.name}'
			default_from_config = node_opts.get(k) or ancestor_opts_defaults.get(k) or config_opts_defaults.get(k)
			opt_name = k
			same_opts = find_same_opts(node, nodes, k)

			# Found a default in YAML config, either in task options, or workflow options, or config options
			if default_from_config:
				conf['required'] = False
				conf['default'] = default_from_config
				conf['default_from'] = node_id_str
				if node_opts.get(k):
					conf['default_from'] = node_id_str
					conf['prefix'] = 'Config'
				elif ancestor_opts_defaults.get(k):
					conf['default_from'] = get_short_id(node.ancestor.id, config.name)
					conf['prefix'] = f'{node.ancestor.type.capitalize()} {node.ancestor.name}'
				elif config_opts_defaults.get(k):
					conf['default_from'] = config.name
					conf['prefix'] = 'Config'
				mapped_value = cls.opt_value_map.get(opt_name)
				if mapped_value:
					if callable(mapped_value):
						default_from_config = mapped_value(default_from_config)
					else:
						default_from_config = mapped_value
				conf['default'] = default_from_config
				if len(same_opts) > 0:  # change opt name to avoid conflict
					conf['prefix'] = 'Config'
					opt_name = f'{conf["default_from"]}.{k}'
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] renamed to [bold green]{opt_name}[/] [dim red](default set in config)[/]', sub=f'cli.{config.name}')  # noqa: E501

			# Standard meta options like rate_limit, delay, proxy, etc...
			elif k in task_opts_meta:
				conf['prefix'] = 'Meta'
				debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] changed prefix to [bold cyan]Meta[/]', sub=f'cli.{config.name}')  # noqa: E501

			# Task-specific options
			elif k in task_opts:
				same_opts = find_same_opts(node, nodes, k, check_class_opts=True)
				if len(same_opts) > 0:
					applies_to = set([node.name] + [_['name'] for _ in same_opts])
					conf['applies_to'] = applies_to
					conf['prefix'] = 'Shared task'
					debug(f'[bold]{config.name}[/] -> [bold blue]{node.id}[/] -> [bold green]{k}[/] changed prefix to [bold cyan]Common[/] [dim red](duplicated {len(same_opts)} times)[/]', sub=f'cli.{config.name}')  # noqa: E501
			else:
				raise ValueError(f'Unknown option {k} for task {node.id}')
			all_opts[opt_name] = conf

	walk_runner_tree(tree, process_node)

	# Normalize all options
	debug('[bold yellow3]All opts processed. Showing defaults:[/]', sub=f'cli.{config.name}')
	normalized_opts = OrderedDict({})
	for k, v in all_opts.items():
		v['reverse'] = False
		v['show_default'] = True
		default_from = v.get('default_from')
		default = v.get('default', False)
		if isinstance(default, bool) and default is True:
			v['reverse'] = True
		if type_mapping and 'type' in v:
			v['type'] = type_mapping.get(v['type'], str)
		short = v.get('short')
		k = k.replace('.', '-').replace('_', '-').replace('/', '-')
		from_str = default_from.replace('.', '-').replace('_', '-').replace('/', '-') if default_from else None
		if not default_from or from_str not in k:
			v['short'] = short if short else None
		else:
			v['short'] = f'{from_str}-{short}' if short else None
		debug(f'\t[bold]{k}[/] -> [bold green]{v.get("default", "N/A")}[/] [dim red](default from {v.get("default_from", "N/A")})[/]', sub=f'cli.{config.name}')  # noqa: E501
		normalized_opts[k] = v
	return normalized_opts

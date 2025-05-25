import yaml

from collections import OrderedDict
from dotmap import DotMap
from pathlib import Path

from secator.output_types import Error
from secator.rich import console
from secator.utils import convert_functions_to_strings


class TemplateLoader(DotMap):

	def __init__(self, input={}, name=None, **kwargs):
		if name:
			if '/' not in name:
				console.print(Error(message=f'Cannot load {name}: you should specify a type for the template when loading by name (e.g. workflow/<workflow_name>)'))  # noqa: E501
				return
			_type, name = name.split('/')
			from secator.loader import find_templates
			config = next((p for p in find_templates() if p['type'] == _type and p['name'] == name in str(p)), None)
			if not config:
				console.print(Error(message=f'Template {name} not found in loaded templates'))
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

	# TODO: deprecate
	@property
	def supported_opts(self):
		"""Property to access supported options easily."""
		return self._collect_supported_opts()

	# TODO: deprecate
	@property
	def flat_tasks(self):
		"""Property to access tasks easily."""
		return self._extract_tasks()

	# TODO: deprecate
	def _collect_supported_opts(self):
		"""Collect supported options from the tasks and workflows extracted from the config."""
		tasks = self._extract_tasks()
		workflows = self._extract_workflows()
		opts = self.options.toDict()
		for wf_name, workflow in workflows.items():
			for k, v in workflow.options.toDict().items():
				if k not in opts or not opts[k].get('supported', False):
					opts[k] = convert_functions_to_strings(v)
					opts[k]['meta'] = wf_name
		for _, task_info in tasks.items():
			task_class = task_info['class']
			if task_class:
				task_opts = task_class.get_supported_opts()
				for name, conf in task_opts.items():
					if name not in opts or not opts[name].get('supported', False):
						opts[name] = convert_functions_to_strings(conf)
		return opts

	# TODO: deprecate
	def _extract_tasks(self):
		"""Extract tasks from any workflow or scan config.

		Returns:
			dict: A dict of task full name to task configuration containing the keyts keys ['name', 'class', 'opts']).
		"""
		from secator.runners import Task
		tasks = OrderedDict()

		def parse_config(config, prefix=''):
			for key, value in config.items():
				if key.startswith('_group'):
					parse_config(value, prefix)
				else:
					value = value or TemplateLoader()
					task_name = f'{prefix}/{key}' if prefix else key
					name = key.split('/')[0]
					if task_name not in tasks:
						tasks[task_name] = {'name': name, 'class': Task.get_task_class(name), 'opts': {}}
					tasks[task_name]['opts'] = value.toDict()

		if not self.type:
			return tasks

		elif self.type == 'task':
			tasks[self.name] = {'name': self.name, 'class': Task.get_task_class(self.name)}

		elif self.type == 'scan':
			workflows = self._extract_workflows()
			for wf_name, config in workflows.items():
				wf_tasks = config.flat_tasks
				for task_key, task_val in wf_tasks.items():
					unique_task_key = f"{wf_name}/{task_key}"  # prefix task with workflow name
					tasks[unique_task_key] = task_val

		elif self.type == 'workflow':
			parse_config(self.tasks)

		return dict(tasks)

	# TODO: deprecate
	def _extract_workflows(self):
		"""Extract workflows from the config."""
		workflows = OrderedDict()
		for wf_name, _ in self.workflows.items():
			name = wf_name.split('/')[0]
			config = TemplateLoader(name=f'workflow/{name}')
			workflows[wf_name] = config
		return workflows

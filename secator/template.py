import glob

from collections import OrderedDict
from pathlib import Path

import yaml
from dotmap import DotMap

from secator.config import CONFIG, CONFIGS_FOLDER
from secator.rich import console
from secator.utils import convert_functions_to_strings, debug
from secator.output_types import Error

TEMPLATES = []


class TemplateLoader(DotMap):

	def __init__(self, input={}, name=None, **kwargs):
		if name:
			if '/' not in name:
				console.print(Error(message=f'Cannot load {name}: you should specify a type for the template when loading by name (e.g. workflow/<workflow_name>)'))  # noqa: E501
				return
			_type, name = name.split('/')
			config = next((p for p in TEMPLATES if p['type'] == _type and p['name'] == name in str(p)), None)
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

	def add_to_templates(self):
		TEMPLATES.append(self)

	def _load_from_path(self, path):
		if not path.exists():
			console.print(Error(message=f'Config path {path} does not exists'))
			return
		with path.open('r') as f:
			return self._load(f.read())

	def _load(self, input):
		return yaml.load(input, Loader=yaml.Loader)

	@property
	def supported_opts(self):
		"""Property to access supported options easily."""
		return self._collect_supported_opts()

	@property
	def flat_tasks(self):
		"""Property to access tasks easily."""
		return self._extract_tasks()

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

	def _collect_supported_opts(self):
		"""Collect supported options from the tasks extracted from the config."""
		tasks = self._extract_tasks()
		opts = {}
		for _, task_info in tasks.items():
			task_class = task_info['class']
			if task_class:
				task_opts = task_class.get_supported_opts()
				for name, conf in task_opts.items():
					if name not in opts or not opts[name].get('supported', False):
						opts[name] = convert_functions_to_strings(conf)
		return opts

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
				elif value:
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
			# For each workflow in the scan, load it and incorporate it with a unique prefix
			for wf_name, _ in self.workflows.items():
				name = wf_name.split('/')[0]
				config = TemplateLoader(name=f'workflow/{name}')
				wf_tasks = config.flat_tasks
				# Prefix tasks from this workflow with its name to prevent collision
				for task_key, task_val in wf_tasks.items():
					unique_task_key = f"{wf_name}/{task_key}"  # Append workflow name to task key
					tasks[unique_task_key] = task_val

		elif self.type == 'workflow':
			# Normal parsing of a workflow
			parse_config(self.tasks)

		return dict(tasks)


def find_templates():
	results = []
	dirs = [CONFIGS_FOLDER]
	if CONFIG.dirs.templates:
		dirs.append(CONFIG.dirs.templates)
	paths = []
	for dir in dirs:
		config_paths = [
			Path(path)
			for path in glob.glob(str(dir).rstrip('/') + '/**/*.y*ml', recursive=True)
		]
		debug(f'Found {len(config_paths)} templates in {dir}', sub='template')
		paths.extend(config_paths)
	for path in paths:
		config = TemplateLoader(input=path)
		debug(f'Loaded template from {path}', sub='template')
		results.append(config)
	return results


TEMPLATES = find_templates()

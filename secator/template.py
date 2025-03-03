import glob

from collections import OrderedDict
from pathlib import Path

import yaml
from dotmap import DotMap

from secator.config import CONFIG, CONFIGS_FOLDER
from secator.rich import console
from secator.utils import convert_functions_to_strings


TEMPLATES_DIR_KEYS = ['workflow', 'scan', 'profile']


def load_template(name):
	"""Load a config by name.

	Args:
		name: Name of the config, for instances profiles/aggressive or workflows/domain_scan.

	Returns:
		dict: Loaded config.
	"""
	path = CONFIGS_FOLDER / f'{name}.yaml'
	if not path.exists():
		console.log(f'Config "{name}" could not be loaded.')
		return
	with path.open('r') as f:
		return yaml.load(f.read(), Loader=yaml.Loader)


def find_templates():
	results = {'scan': [], 'workflow': [], 'profile': []}
	dirs_type = [CONFIGS_FOLDER]
	if CONFIG.dirs.templates:
		dirs_type.append(CONFIG.dirs.templates)
	paths = []
	for dir in dirs_type:
		dir_paths = [
			Path(path)
			for path in glob.glob(str(dir).rstrip('/') + '/**/*.y*ml', recursive=True)
		]
		paths.extend(dir_paths)
	for path in paths:
		with path.open('r') as f:
			try:
				config = yaml.load(f.read(), yaml.Loader)
				type = config.get('type')
				if type:
					results[type].append(path)
			except yaml.YAMLError as exc:
				console.log(f'Unable to load config at {path}')
				console.log(str(exc))
	return results


class TemplateLoader(DotMap):

	def __init__(self, input={}, name=None, **kwargs):
		if name:
			name = name.replace('-', '_')  # so that workflows have a nice '-' in CLI
			config = self._load_from_name(name)
		elif isinstance(input, str) or isinstance(input, Path):
			config = self._load_from_file(input)
		else:
			config = input
		super().__init__(config)

	def _load_from_file(self, path):
		if isinstance(path, str):
			path = Path(path)
		if not path.exists():
			console.log(f'Config path {path} does not exists', style='bold red')
			return
		with path.open('r') as f:
			return yaml.load(f.read(), Loader=yaml.Loader)

	def _load_from_name(self, name):
		return load_template(name)

	@classmethod
	def load_all(cls):
		configs = find_templates()
		return TemplateLoader({
			key: [TemplateLoader(path) for path in configs[key]]
			for key in TEMPLATES_DIR_KEYS
		})

	@property
	def supported_opts(self):
		"""Property to access supported options easily."""
		return self._collect_supported_opts()

	@property
	def flat_tasks(self):
		"""Property to access tasks easily."""
		return self._extract_tasks()

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
				config = TemplateLoader(name=f'workflows/{name}')
				wf_tasks = config.flat_tasks
				# Prefix tasks from this workflow with its name to prevent collision
				for task_key, task_val in wf_tasks.items():
					unique_task_key = f"{wf_name}/{task_key}"  # Append workflow name to task key
					tasks[unique_task_key] = task_val

		elif self.type == 'workflow':
			# Normal parsing of a workflow
			parse_config(self.tasks)

		return dict(tasks)

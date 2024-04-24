import glob
from pathlib import Path

import yaml
from dotmap import DotMap

from secator.rich import console
from secator.config import CONFIG, CONFIGS_FOLDER

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

	def get_tasks_class(self):
		from secator.runners import Task
		tasks = []
		for name, conf in self.tasks.items():
			if name == '_group':
				group_conf = TemplateLoader(input={'tasks': conf})
				tasks.extend(group_conf.get_tasks_class())
			else:
				tasks.append(Task.get_task_class(name))
		return tasks

	def get_workflows(self):
		return [TemplateLoader(name=f'workflows/{name}') for name, _ in self.workflows.items()]

	def get_workflow_supported_opts(self):
		opts = {}
		tasks = self.get_tasks_class()
		for task_cls in tasks:
			task_opts = task_cls.get_supported_opts()
			for name, conf in task_opts.items():
				supported = opts.get(name, {}).get('supported', False)
				opts[name] = conf
				opts[name]['supported'] = conf['supported'] or supported
		return opts

	def get_scan_supported_opts(self):
		opts = {}
		workflows = self.get_workflows()
		for workflow in workflows:
			workflow_opts = workflow.get_workflow_supported_opts()
			for name, conf in workflow_opts.items():
				supported = opts.get(name, {}).get('supported', False)
				opts[name] = conf
				opts[name]['supported'] = conf['supported'] or supported
		return opts

	@property
	def supported_opts(self):
		return self.get_supported_opts()

	def get_supported_opts(self):
		opts = {}
		if self.type == 'workflow':
			opts = self.get_workflow_supported_opts()
		elif self.type == 'scan':
			opts = self.get_scan_supported_opts()
		elif self.type == 'task':
			tasks = self.get_tasks_class()
			if tasks:
				opts = tasks[0].get_supported_opts()
		return dict(sorted(opts.items()))

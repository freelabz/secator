from functools import cache
from pkgutil import iter_modules
from secator.rich import console
from secator.config import CONFIG, CONFIGS_FOLDER
from secator.template import TemplateLoader
from secator.utils import debug
from pathlib import Path
import glob
import importlib
import inspect
import sys


@cache
def find_templates():
	discover_tasks()  # always load tasks first
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


@cache
def get_configs_by_type(type):
	if type == 'task':
		tasks = discover_tasks()
		task_config = [TemplateLoader({
			'name': cls.__name__,
			'type': 'task',
			'description': cls.__doc__,
			'input_types': cls.input_types,
			'output_types': [t.get_name() for t in cls.output_types],
			'proxychains': getattr(cls, 'proxychains', True),
			'proxy_socks5': getattr(cls, 'proxy_socks5', True),
			'proxy_http': getattr(cls, 'proxy_http', True),
			'default_cmd': cls.cmd,
			'install_cmd': cls.install_cmd,
		}) for cls in tasks]  # noqa: E501
		return sorted(task_config, key=lambda x: x['name'])
	return sorted([t for t in find_templates() if t.type == type], key=lambda x: x.name)


@cache
def discover_tasks():
	"""Find all secator tasks (internal + external)."""
	return discover_internal_tasks() + discover_external_tasks()


@cache
def discover_internal_tasks():
	"""Find internal secator tasks."""
	from secator.runners import Runner
	package_dir = Path(__file__).resolve().parent / 'tasks'
	task_classes = []
	for (_, module_name, _) in iter_modules([str(package_dir)]):
		if module_name.startswith('_'):
			continue
		try:
			module = importlib.import_module(f'secator.tasks.{module_name}')
		except ImportError as e:
			console.print(f'[bold red]Could not import secator.tasks.{module_name}:[/]')
			console.print(f'\t[bold red]{type(e).__name__}[/]: {str(e)}')
			continue
		for attribute_name in dir(module):
			attribute = getattr(module, attribute_name)
			if inspect.isclass(attribute):
				bases = inspect.getmro(attribute)
				if Runner in bases and hasattr(attribute, '__task__'):
					attribute.__external__ = False
					task_classes.append(attribute)

	# Sort task_classes by category
	task_classes = sorted(
		task_classes,
		# key=lambda x: (get_command_category(x), x.__name__)
		key=lambda x: x.__name__)
	return task_classes


@cache
def discover_external_tasks():
	"""Find external secator tasks."""
	output = []
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		try:
			task_name = path.stem
			module_name = f'secator.tasks.{task_name}'

			# console.print(f'Importing module {module_name} from {path}')
			spec = importlib.util.spec_from_file_location(module_name, path)
			module = importlib.util.module_from_spec(spec)
			if not spec:
				console.print(f'[bold red]Could not load external module {path.name}: invalid import spec.[/] ({path})')
				continue
			# console.print(f'Adding module "{module_name}" to sys path')
			sys.modules[module_name] = module

			# console.print(f'Executing module "{module}"')
			spec.loader.exec_module(module)

			# console.print(f'Checking that {module} contains task {task_name}')
			if not hasattr(module, task_name):
				console.print(f'[bold orange1]Could not load external task "{task_name}" from module {path.name}[/] ({path})')
				continue
			cls = getattr(module, task_name)
			console.print(f'[bold green]Successfully loaded external task "{task_name}"[/] ({path})')
			cls.__external__ = True
			output.append(cls)
		except Exception as e:
			console.print(f'[bold red]Could not load external module {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	return output

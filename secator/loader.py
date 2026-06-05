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


def _file_has_hooks(path):
	"""Check if a Python file contains a HOOKS variable (driver indicator)."""
	try:
		return 'HOOKS =' in path.read_text()
	except Exception:
		return False


def _file_has_driver_class(path):
	"""Check if a Python file contains a Driver subclass."""
	try:
		return '(Driver)' in path.read_text()
	except Exception:
		return False


def _file_has_exporter(path):
	"""Check if a Python file contains an Exporter subclass."""
	try:
		return '(Exporter)' in path.read_text()
	except Exception:
		return False


@cache
def find_templates():
	discover_tasks()  # always load tasks first
	discover_external_drivers()  # load external drivers
	discover_external_exporters()  # load external exporters
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
			'default_inputs': cls.default_inputs,
			'proxychains': getattr(cls, 'proxychains', True),
			'proxy_socks5': getattr(cls, 'proxy_socks5', True),
			'proxy_http': getattr(cls, 'proxy_http', True),
			'default_cmd': getattr(cls, 'cmd', None),
			'install_cmd': getattr(cls, 'install_cmd', None),
			'tags': getattr(cls, 'tags', []),
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
		if _file_has_hooks(path) or _file_has_exporter(path) or _file_has_driver_class(path):
			continue  # Skip driver/exporter files
		try:
			task_name = path.stem
			module_name = f'secator.tasks.{task_name}'

			# console.print(f'Importing module {module_name} from {path}')
			spec = importlib.util.spec_from_file_location(module_name, path)
			if not spec:
				console.print(f'[bold red]Could not load external module {path.name}: invalid import spec.[/] ({path})')
				continue
			module = importlib.util.module_from_spec(spec)
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


_external_driver_classes = {}  # registry for class-based external drivers


@cache
def discover_external_drivers():
	"""Find external secator drivers (both HOOKS-based and class-based Driver subclasses)."""
	output = []
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		is_hooks_based = _file_has_hooks(path)
		is_class_based = _file_has_driver_class(path)
		if not is_hooks_based and not is_class_based:
			continue
		try:
			driver_name = path.stem
			module_name = f'secator.hooks.{driver_name}'

			spec = importlib.util.spec_from_file_location(module_name, path)
			if not spec:
				console.print(f'[bold red]Could not load external driver {path.name}: invalid import spec.[/] ({path})')
				continue
			module = importlib.util.module_from_spec(spec)
			sys.modules[module_name] = module
			spec.loader.exec_module(module)

			if is_hooks_based:
				if not hasattr(module, 'HOOKS'):
					console.print(f'[bold orange1]Could not load external driver "{driver_name}" from {path.name}: missing HOOKS variable.[/] ({path})')  # noqa: E501
					continue
			elif is_class_based:
				# File defines a Driver subclass without HOOKS= - register for direct instantiation
				from secator.drivers._base import Driver
				driver_cls = None
				for attr_name in dir(module):
					attr = getattr(module, attr_name)
					if inspect.isclass(attr) and issubclass(attr, Driver) and attr is not Driver:
						driver_cls = attr
						break
				if driver_cls is None:
					console.print(f'[bold orange1]Could not load external driver "{driver_name}" from {path.name}: no Driver subclass found.[/] ({path})')  # noqa: E501
					continue
				_external_driver_classes[driver_name] = driver_cls

			console.print(f'[bold green]Successfully loaded external driver "{driver_name}"[/] ({path})')
			output.append(driver_name)
		except Exception as e:
			console.print(f'[bold red]Could not load external driver from {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	return output


@cache
def discover_external_exporters():
	"""Find external secator exporters."""
	import secator.exporters as exporters_pkg
	from secator.exporters._base import Exporter
	output = []
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		if not _file_has_exporter(path):
			continue
		try:
			module_path = path.stem
			module_name = f'secator.exporters.{module_path}'

			spec = importlib.util.spec_from_file_location(module_name, path)
			module = importlib.util.module_from_spec(spec)
			if not spec:
				console.print(f'[bold red]Could not load external exporter {path.name}: invalid import spec.[/] ({path})')
				continue
			sys.modules[module_name] = module
			spec.loader.exec_module(module)

			found = False
			for attr_name in dir(module):
				attr = getattr(module, attr_name)
				if inspect.isclass(attr) and issubclass(attr, Exporter) and attr is not Exporter:
					name_lower = attr_name.lower()
					exporter_name = name_lower[:-8] if name_lower.endswith('exporter') else name_lower
					lookup_name = exporter_name.capitalize() + 'Exporter'
					setattr(exporters_pkg, lookup_name, attr)
					console.print(f'[bold green]Successfully loaded external exporter "{exporter_name}"[/] ({path})')
					output.append(exporter_name)
					found = True

			if not found:
				console.print(f'[bold orange1]Could not load external exporter from {path.name}: no Exporter subclass found.[/] ({path})')  # noqa: E501
		except Exception as e:
			console.print(f'[bold red]Could not load external exporter from {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	return output


@cache
def get_available_drivers():
	"""Get all available drivers (internal + external)."""
	from secator.definitions import AVAILABLE_DRIVERS
	return AVAILABLE_DRIVERS + discover_external_drivers()


def get_driver_instance(driver_name):
	"""Instantiate a driver by name.

	Tries to import from secator.drivers first (lazy import to avoid loading
	optional dependencies like pymongo/google-cloud-storage unless needed), then
	falls back to loading the HOOKS dict from secator.hooks for backward
	compatibility with external drivers.

	Args:
		driver_name (str): Driver name (e.g. 'gcs', 'mongodb', 'api', 'discord').

	Returns:
		Driver instance or None if not found.
	"""
	import importlib
	from secator.drivers import DRIVER_REGISTRY
	if driver_name in DRIVER_REGISTRY:
		module_path, class_name = DRIVER_REGISTRY[driver_name]
		module = importlib.import_module(module_path)
		cls = getattr(module, class_name)
		return cls()

	# Check for externally registered class-based drivers
	if driver_name in _external_driver_classes:
		return _external_driver_classes[driver_name]()

	# Fall back to external driver (HOOKS-based): wrap in a compatible shim
	from secator.utils import import_dynamic
	hooks = import_dynamic(f'secator.hooks.{driver_name}', 'HOOKS')
	if hooks is not None:
		from secator.drivers._base import Driver
		_name = driver_name

		class _ExternalDriver(Driver):
			@property
			def name(self):
				return _name

			@property
			def hooks(self):
				return hooks

			def check(self):
				return True

		_ExternalDriver.__name__ = f'{driver_name.capitalize()}Driver'
		return _ExternalDriver()
	return None


@cache
def get_available_exporters():
	"""Get all available exporters (internal + external)."""
	from secator.definitions import AVAILABLE_EXPORTERS
	return AVAILABLE_EXPORTERS + discover_external_exporters()

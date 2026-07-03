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
import re
import sys


def _file_has_hooks(path):
	"""Check if a Python file contains a HOOKS variable (driver indicator)."""
	try:
		return bool(re.search(r'\bHOOKS\s*=', path.read_text()))
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
	external = discover_external_tasks()
	internal = discover_internal_tasks()
	return external + internal


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
		if _file_has_hooks(path) or _file_has_exporter(path):
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
				sys.modules.pop(module_name, None)
				console.print(f'[bold orange1]Could not load external task "{task_name}" from module {path.name}[/] ({path})')
				continue
			cls = getattr(module, task_name)
			if not inspect.isclass(cls):
				# cls is a module reference, not a class — likely caused by a circular
				# import (e.g. the file does `from secator.tasks import <task_name>`
				# while secator.tasks is still initialising).  Clean up sys.modules so
				# the entry doesn't shadow the real task later.
				sys.modules.pop(module_name, None)
				console.print(f'[bold orange1]Could not load external task "{task_name}" from {path.name}: not a class[/] ({path})')
				continue
			debug(f'[bold green]Successfully loaded external task "{task_name}"[/] ({path})', sub='loader')
			cls.__external__ = True
			output.append(cls)
		except Exception as e:
			sys.modules.pop(module_name, None)
			console.print(f'[bold red]Could not load external module {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	return output


@cache
def discover_external_drivers():
	"""Find external secator drivers."""
	output = []
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		if not _file_has_hooks(path):
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

			if not hasattr(module, 'HOOKS'):
				console.print(f'[bold orange1]Could not load external driver "{driver_name}" from {path.name}: missing HOOKS variable.[/] ({path})')  # noqa: E501
				continue
			debug(f'[bold green]Successfully loaded external driver "{driver_name}"[/] ({path})', sub='loader')
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
					debug(f'[bold green]Successfully loaded external exporter "{exporter_name}"[/] ({path})', sub='loader')
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


def order_drivers(drivers):
	"""Order driver names by canonical priority and dedupe.

	Backend selection and hook execution both follow the order of the runner's
	``context['drivers']`` list (hook lists are concatenated in driver order).
	The ranking (``DRIVER_PRIORITY``) ensures:

	- enrichment drivers (``gcs``) run before backends, so finding mutations
	  (e.g. ``screenshot_path``) are present when a backend persists them;
	- among backend-type drivers (databases then the relay API), the
	  authoritative DB (``mongodb``) prevails over the relay (``api``) — without
	  this a runner can execute fine yet stay stuck in PENDING because ``api``
	  shadowed ``mongodb``'s ``update_runner`` hook.

	Drivers not in ``DRIVER_PRIORITY`` (e.g. ``discord`` notifications, external
	drivers) are left unranked, keeping their relative order after ranked ones.

	Args:
		drivers (list[str]): Driver names, in arbitrary order.

	Returns:
		list[str]: Deduped driver names ordered by canonical priority.
	"""
	from secator.definitions import DRIVER_PRIORITY

	def sort_key(driver):
		try:
			return (0, DRIVER_PRIORITY.index(driver))
		except ValueError:
			return (1, 0)

	return sorted(dict.fromkeys(drivers), key=sort_key)


@cache
def get_available_exporters():
	"""Get all available exporters (internal + external)."""
	from secator.definitions import AVAILABLE_EXPORTERS
	return AVAILABLE_EXPORTERS + discover_external_exporters()


@cache
def load_external_addons():
	"""Load external addons from addons.json in the templates directory.

	Returns:
		dict: Mapping of addon name to addon config dict. Empty dict if file absent or invalid.
	"""
	import json
	addons_file = CONFIG.dirs.templates / 'addons.json'
	if not addons_file.exists():
		return {}
	try:
		with addons_file.open() as f:
			data = json.load(f)
		if not isinstance(data, dict):
			console.print(f'[bold red]addons.json must be a JSON object, got {type(data).__name__}[/]')
			return {}
		invalid = {k: v for k, v in data.items() if not isinstance(v, dict)}
		if invalid:
			for k, v in invalid.items():
				console.print(f'[bold red]Skipping addon "{k}": config must be an object, got {type(v).__name__}[/]')
		filtered = {k: v for k, v in data.items() if isinstance(v, dict)}
		debug(f'Loaded {len(filtered)} external addon(s) from {addons_file}', sub='template')
		return filtered
	except Exception as e:
		console.print(f'[bold red]Could not load addons.json: {e}[/]')
		return {}

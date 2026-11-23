from functools import cache
from pkgutil import iter_modules
from secator.rich import console
from secator.config import CONFIG, CONFIGS_FOLDER
from secator.template import TemplateLoader
from secator.utils import debug
from pathlib import Path
import ast
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


def _file_has_ai_tool(path):
	"""Check if a Python file defines an external AI tool (a BaseTool subclass).

	Cheap text gate first (no ``BaseTool`` reference → not a tool file, no parse), then an
	AST walk over the file's classes: a class is a tool class when any of its bases is
	``BaseTool`` (bare or dotted, in any position, e.g. ``class X(_Mixin, BaseTool)``) or a
	class of the same file that is itself a tool class (e.g. ``class X(SharedBase)`` with
	``class SharedBase(BaseTool)``). Nothing is imported or executed here.
	"""
	try:
		text = path.read_text()
		if 'BaseTool' not in text:
			return False
		classes = [node for node in ast.walk(ast.parse(text)) if isinstance(node, ast.ClassDef)]
	except Exception:
		return False

	def _base_name(base):
		if isinstance(base, ast.Name):
			return base.id
		if isinstance(base, ast.Attribute):
			return base.attr
		return None

	tool_classes = {'BaseTool'}
	changed = True
	while changed:  # fixpoint, so class order in the file does not matter
		changed = False
		for node in classes:
			if node.name not in tool_classes and any(_base_name(b) in tool_classes for b in node.bases):
				tool_classes.add(node.name)
				changed = True
	return len(tool_classes) > 1


def _ai_tool_dirs():
	"""Directories scanned for external AI tools.

	Always the templates dir (parity with external tasks/drivers/exporters). A
	colon-separated ``SECATOR_AI_TOOLS_DIRS`` env var adds more — the groundwork for an
	operator (or an unpacked override bundle) to point secator at a directory of extra
	tools without dropping them in the templates dir. Non-existent dirs are skipped.
	"""
	import os
	dirs = []
	if CONFIG.dirs.templates:
		dirs.append(Path(CONFIG.dirs.templates))
	for extra in (os.environ.get('SECATOR_AI_TOOLS_DIRS', '') or '').split(os.pathsep):
		extra = extra.strip()
		if extra:
			dirs.append(Path(extra))
	seen, out = set(), []
	for d in dirs:
		try:
			rd = d.resolve()
		except Exception:
			continue
		if rd not in seen and d.is_dir():
			seen.add(rd)
			out.append(d)
	return out


_warned_duplicate_names = set()


def _warn_duplicate_names(entries, _seen=None):
	"""Warn when a config name is defined more than once.

	A second scan/workflow/task with the same ``name`` silently shadows the first (name
	resolution keeps the first match), which is a confusing footgun — e.g. two workflow files
	with the same ``name:`` key, or an external task shadowing a built-in one.

	Args:
		entries: iterable of ``(label, source)`` where ``label`` uniquely identifies a config
			(e.g. ``workflow "host_recon"``) and ``source`` is the file/module it came from.
		_seen: set of already-reported labels so each duplicate is reported only once. Defaults
			to a module-level set that persists for the process lifetime.
	"""
	from collections import defaultdict
	if _seen is None:
		_seen = _warned_duplicate_names
	groups = defaultdict(list)
	for label, source in entries:
		groups[label].append(source)
	for label, sources in groups.items():
		# Dedupe sources so the same file counted twice (re-entrant discovery) isn't a false positive.
		distinct = list(dict.fromkeys(sources))
		if len(distinct) > 1 and label not in _seen:
			_seen.add(label)
			console.print(f'[bold orange1]⚠  Duplicate {label} defined in {len(distinct)} places — only the first is used:[/]')  # noqa: E501
			for source in distinct:
				console.print(f'   [dim]{source}[/]')


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
	_warn_duplicate_names(
		(f'{c.get("type")} "{c.get("name")}"', c.get('_path') or '<unknown>')
		for c in results if c.get('type') and c.get('name')
	)
	return results


@cache
def get_configs_by_type(type):
	if type == 'task':
		from secator.template import (
			get_applicable_profiles, get_config_options, get_supported_opt_names, serialize_config_options)
		tasks = discover_tasks()
		task_config = []
		for cls in tasks:
			tpl = TemplateLoader({
				'name': cls.__name__,
				'type': 'task',
				'description': cls.__doc__,
				'friendly_display_name': getattr(cls, 'friendly_display_name', None) or cls.__name__,
				'friendly_description': getattr(cls, 'friendly_description', None) or cls.__doc__,
				'input_types': cls.input_types,
				'output_types': [t.get_name() for t in cls.output_types],
				'default_inputs': cls.default_inputs,
				'proxychains': getattr(cls, 'proxychains', True),
				'proxy_socks5': getattr(cls, 'proxy_socks5', True),
				'proxy_http': getattr(cls, 'proxy_http', True),
				'default_cmd': getattr(cls, 'cmd', None),
				'install_cmd': getattr(cls, 'install_cmd', None),
				'tags': getattr(cls, 'tags', []),
			})  # noqa: E501
			opts = serialize_config_options(get_config_options(tpl))
			tpl['applicable_profiles'] = get_applicable_profiles(get_supported_opt_names(opts))
			task_config.append(tpl)
		return sorted(task_config, key=lambda x: x['name'])
	return sorted([t for t in find_templates() if t.type == type], key=lambda x: x.name)


@cache
def discover_tasks():
	"""Find all secator tasks (internal + external)."""
	external = discover_external_tasks()
	internal = discover_internal_tasks()
	tasks = external + internal
	# External tasks: use the real per-file paths (a reused same-stem module would otherwise make
	# every duplicate resolve to the first file and hide the shadowing). Internal tasks are properly
	# imported, so their module __file__ is reliable.
	entries = [(f'task "{name}"', source) for name, source in _external_task_sources]
	entries += [
		(f'task "{cls.__name__}"', getattr(sys.modules.get(cls.__module__), '__file__', None) or cls.__module__)
		for cls in internal
	]
	_warn_duplicate_names(entries)
	return tasks


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


# Candidate ``(task_name, file path)`` pairs seen by the last discover_external_tasks() run — one
# entry per source FILE, even when its module is reused (same stem in two dirs). Duplicate detection
# reads this instead of cls.__module__: a reused module points every same-stem file at the first
# file's path, which would hide exactly the shadowing we want to warn about.
_external_task_sources = []


@cache
def discover_external_tasks():
	"""Find external secator tasks."""
	global _external_task_sources
	output = []
	sources = []
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		if _file_has_hooks(path) or _file_has_exporter(path) or _file_has_ai_tool(path):
			continue  # Skip driver/exporter/ai-tool files
		try:
			task_name = path.stem
			module_name = f'secator.tasks.{task_name}'

			# Idempotent import: reuse an already-registered module instead of re-executing
			# the file. Re-exec mints a SECOND class object and overwrites sys.modules, so a
			# task instance built from the first object can no longer be pickled ("not the same
			# object as ...") — the #1286 sync-mode chunk crash (task_store_eager_result pickles
			# the eager chord result in-process). This runs twice when an external task imports a
			# secator.tasks.* submodule: that triggers secator/tasks/__init__.py -> discover_tasks()
			# re-entrantly while this @cache'd discovery is still executing (functools.cache is not
			# re-entrancy safe). If the module is mid-initialisation the class isn't defined yet, so
			# skip it here — the in-progress exec that registered it appends it when it completes.
			existing = sys.modules.get(module_name)
			if existing is not None:
				cls = getattr(existing, task_name, None)
				if inspect.isclass(cls):
					cls.__external__ = True
					output.append(cls)
					sources.append((task_name, str(path)))  # record THIS file, not the reused module's
				continue

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
			sources.append((task_name, str(path)))
		except Exception as e:
			sys.modules.pop(module_name, None)
			console.print(f'[bold red]Could not load external module {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	_external_task_sources = sources
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


def get_task_class(name):
	"""Return a discovered task class by name (built-in or custom), or None.

	Public accessor for extension authors — e.g. a custom AI tool that wants to run a
	custom task the org dropped into the templates dir. Triggers task discovery, so the
	returned class is the same object the ``run_task`` tool would resolve.
	"""
	for cls in discover_tasks():
		if getattr(cls, '__name__', None) == name:
			return cls
	return None


def get_driver_hooks(name):
	"""Return the ``HOOKS`` dict of a loaded external driver/hook module by name, or None.

	Public accessor so an extension — e.g. a custom AI tool — can reuse a custom reporting
	hook that core loaded from the templates dir (the same ``HOOKS`` secator applies as a
	driver). Triggers external-driver discovery first.
	"""
	discover_external_drivers()
	module = sys.modules.get(f'secator.hooks.{name}')
	return getattr(module, 'HOOKS', None) if module is not None else None


@cache
def discover_ai_tools():
	"""Find and register external AI tools (a ``*.py`` defining a BaseTool subclass).

	Mirrors :func:`discover_external_tasks`: any file under an AI-tools dir (the templates
	dir, plus ``SECATOR_AI_TOOLS_DIRS``) that defines a ``secator.ai.tools.BaseTool``
	subclass is imported and each subclass registered via ``register_ai_tool``, making the
	tool callable by the AI agent with no core edit — the same drop-in model as custom
	tasks. ``@cache`` → runs once. Fail-safe per file: a bad import, bad spec or invalid
	tool is skipped with a clear message, never crashing startup.

	One file may define several tools. A ``BaseTool`` subclass with no ``name`` is treated
	as an abstract helper (a base class sharing methods between the file's tools) and is
	skipped silently; only named subclasses are registered.

	LOAD ORDER: tasks and external drivers/hooks are discovered FIRST, so a tool file can
	reference custom tasks (:func:`get_task_class`) and custom hooks
	(:func:`get_driver_hooks`) that core has already loaded. A tool that references a
	missing task/hook raises inside its own file and is skipped with a clear message,
	leaving the other tools loaded.
	"""
	from secator.definitions import ADDONS_ENABLED
	if not ADDONS_ENABLED.get('ai'):
		return []
	# Tools load AFTER tasks + hooks so references resolve (see get_task_class /
	# get_driver_hooks). Both are @cache'd, so this is a no-op after the first call.
	discover_tasks()
	discover_external_drivers()
	from secator.ai.tools import register_ai_tool
	from secator.ai.tools.base import BaseTool
	registered = []
	seen_files = set()
	prev_state = sys.dont_write_bytecode
	sys.dont_write_bytecode = True
	for base_dir in _ai_tool_dirs():
		for path in base_dir.glob('**/*.py'):
			rp = path.resolve()
			if rp in seen_files or not _file_has_ai_tool(path):
				continue
			seen_files.add(rp)
			try:
				module_name = f'secator.ai.tools_ext.{path.stem}'
				spec = importlib.util.spec_from_file_location(module_name, path)
				if not spec:
					console.print(f'[bold red]Could not load external AI tool {path.name}: invalid import spec.[/] ({path})')
					continue
				module = importlib.util.module_from_spec(spec)
				sys.modules[module_name] = module
				spec.loader.exec_module(module)
				found = False
				for attr_name in dir(module):
					attr = getattr(module, attr_name)
					if inspect.isclass(attr) and issubclass(attr, BaseTool) and attr is not BaseTool:
						# Only register classes DEFINED in this file (not an imported BaseTool kin).
						if getattr(attr, '__module__', '') != module_name:
							continue
						# A nameless subclass is an abstract helper (a shared base for the
						# file's tools), not a tool: skip it quietly.
						name = getattr(attr, 'name', '')
						if not isinstance(name, str) or not name.strip():
							debug(f'Skipping nameless BaseTool subclass {attr.__name__} (shared base, not a tool) ({path})', sub='loader')  # noqa: E501
							continue
						tool = register_ai_tool(attr)
						if tool is not None:
							registered.append(tool.name)
							found = True
							debug(f'[bold green]Successfully loaded external AI tool "{tool.name}"[/] ({path})', sub='loader')
				if not found:
					console.print(f'[bold orange1]Could not load external AI tool from {path.name}: no valid BaseTool subclass.[/] ({path})')  # noqa: E501
			except Exception as e:
				console.print(f'[bold red]Could not load external AI tool from {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = prev_state
	return registered


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


# Backend drivers that provide their own queryable store. If one of these (or the
# mongodb addon) is active, we must NOT force the local json driver on top of it.
STORE_DRIVERS = {'mongodb', 'sqlite', 'api'}


def apply_default_drivers(drivers, mongodb_enabled):
	"""Default local runs to the ``json`` driver so there is ALWAYS a queryable store.

	Once the inter-task result payload is dropped, every consumer reads findings from
	the store instead of the returned results. Locally that store is the per-runner
	``report.json`` written live by the json driver — so a bare run needs the json
	driver active. Applied ONLY when no store backend is otherwise active: no
	mongodb/sqlite/api driver in ``drivers`` and the mongodb addon disabled. In server mode
	(mongodb addon enabled) mongodb still wins and json is not forced.

	Args:
		drivers (list[str]): Resolved driver names (config defaults + CLI --driver).
		mongodb_enabled (bool): Whether the mongodb addon is enabled.

	Returns:
		list[str]: Drivers unchanged if a store backend is already active; otherwise
			``json`` appended so there is always a queryable store.
	"""
	if STORE_DRIVERS & set(drivers):
		return drivers
	# No explicit store driver (even with the mongodb addon on but mongodb absent from
	# drivers.defaults): default to json so SOMETHING writes the store. With the celery
	# result payload dropped, an empty drivers list registers no persistence hooks and
	# the StreamView would read an empty backend (data integrity).
	if 'json' not in drivers:
		drivers = drivers + ['json']
	return drivers


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

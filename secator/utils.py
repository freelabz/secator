import fnmatch
import inspect
import importlib
import itertools
import logging
import operator
import os
import tldextract
import re
import select
import sys
import validators
import warnings

from datetime import datetime
from inspect import isclass
from pathlib import Path
from pkgutil import iter_modules
import traceback
from urllib.parse import urlparse, quote

import humanize
import ifaddr
import yaml
from rich.markdown import Markdown

from secator.definitions import (DEBUG, DEBUG_COMPONENT, VERSION, DEV_PACKAGE)
from secator.config import CONFIG, ROOT_FOLDER, LIB_FOLDER
from secator.rich import console

logger = logging.getLogger(__name__)

_tasks = []


class TaskError(ValueError):
	pass


def setup_logging(level):
	"""Setup logging.

	Args:
		level: logging level.

	Returns:
		logging.Logger: logger.
	"""
	logger = logging.getLogger('secator')
	logger.setLevel(level)
	ch = logging.StreamHandler()
	ch.setLevel(level)
	formatter = logging.Formatter('%(message)s')
	ch.setFormatter(formatter)
	logger.addHandler(ch)
	return logger


def expand_input(input):
	"""Expand user-provided input on the CLI:
	- If input is a path, read the file and return the lines.
	- If it's a comma-separated list, return the list.
	- Otherwise, return the original input.

	Args:
		input (str): Input.

	Returns:
		str: Input.
	"""
	if input is None:  # read from stdin
		console.print('Waiting for input on stdin ...', style='bold yellow')
		rlist, _, _ = select.select([sys.stdin], [], [], CONFIG.cli.stdin_timeout)
		if rlist:
			data = sys.stdin.read().splitlines()
		else:
			console.print(
				'No input passed on stdin. Showing help page.',
				style='bold red')
			return None
		return data
	elif os.path.exists(input):
		if os.path.isfile(input):
			with open(input, 'r') as f:
				data = f.read().splitlines()
			return data
		return input
	elif isinstance(input, str):
		input = input.split(',')

	# If the list is only one item, return it instead of the list
	# Usefull for commands that can take only one input at a time.
	if isinstance(input, list) and len(input) == 1:
		return input[0]

	return input


def sanitize_url(http_url):
	"""Removes HTTP(s) ports 80 and 443 from HTTP(s) URL because it's ugly.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	url = urlparse(http_url)
	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')


def deduplicate(array, attr=None):
	"""Deduplicate list of OutputType items.

	Args:
		array (list): Input list.

	Returns:
		list: Deduplicated list.
	"""
	from secator.output_types import OUTPUT_TYPES
	if attr and len(array) > 0 and isinstance(array[0], tuple(OUTPUT_TYPES)):
		memo = set()
		res = []
		for sub in array:
			if attr in sub.keys() and getattr(sub, attr) not in memo:
				res.append(sub)
				memo.add(getattr(sub, attr))
		return sorted(res, key=operator.attrgetter(attr))
	return sorted(list(dict.fromkeys(array)))


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
			if isclass(attribute):
				bases = inspect.getmro(attribute)
				if Runner in bases and hasattr(attribute, '__task__'):
					task_classes.append(attribute)

	# Sort task_classes by category
	task_classes = sorted(
		task_classes,
		key=lambda x: (get_command_category(x), x.__name__))

	return task_classes


def discover_external_tasks():
	"""Find external secator tasks."""
	output = []
	sys.dont_write_bytecode = True
	for path in CONFIG.dirs.templates.glob('**/*.py'):
		try:
			task_name = path.stem
			module_name = f'secator.tasks.{task_name}'

			# console.print(f'Importing module {module_name} from {path}')
			spec = importlib.util.spec_from_file_location(module_name, path)
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
			output.append(cls)
		except Exception as e:
			console.print(f'[bold red]Could not load external module {path.name}. Reason: {str(e)}.[/] ({path})')
	sys.dont_write_bytecode = False
	return output


def discover_tasks():
	"""Find all secator tasks (internal + external)."""
	global _tasks
	if not _tasks:
		_tasks = discover_internal_tasks() + discover_external_tasks()
	return _tasks


def import_dynamic(cls_path, cls_root='Command'):
	"""Import class dynamically from class path.

	Args:
		cls_path (str): Class path.
		cls_root (str): Root parent class.

	Returns:
		cls: Class object.
	"""
	try:
		package, name = cls_path.rsplit(".", maxsplit=1)
		cls = getattr(importlib.import_module(package), name)
		root_cls = inspect.getmro(cls)[-2]
		if root_cls.__name__ == cls_root:
			return cls
		return None
	except Exception:
		warnings.warn(f'"{package}.{name}" not found.')
		return None


def get_command_cls(cls_name):
	"""Get secator command by class name.

	Args:
		cls_name (str): Class name to load.

	Returns:
		cls: Class.
	"""
	tasks_classes = discover_tasks()
	for task_cls in tasks_classes:
		if task_cls.__name__ == cls_name:
			return task_cls
	return None


def get_command_category(command):
	"""Get the category of a command.

	Args:
		command (class): Command class.

	Returns:
		str: Command category.
	"""
	base_cls = command.__bases__[0].__name__.replace('Command', '').replace('Runner', 'misc')
	category = re.sub(r'(?<!^)(?=[A-Z])', '/', base_cls).lower()
	return category


def merge_opts(*options):
	"""Merge multiple options dict into a final one, overriding by order.

	Args:
		list: List of options dict.

	Returns:
		dict: Options.
	"""
	all_opts = {}
	for opts in options:
		if opts:
			opts_noempty = {k: v for k, v in opts.items() if v is not None}
			all_opts.update(opts_noempty)
	return all_opts


def flatten(array: list):
	"""Flatten list if it contains multiple sublists.

	Args:
		l (list): Input list.

	Returns:
		list: Output list.
	"""
	if isinstance(array, list) and len(array) > 0 and isinstance(array[0], list):
		return list(itertools.chain(*array))
	return array


def pluralize(word):
	"""Pluralize a word.

	Args:
		word (string): Word.

	Returns:
		string: Plural word.
	"""
	if word.endswith('y'):
		return word.rstrip('y') + 'ies'
	else:
		return f'{word}s'


def load_fixture(name, fixtures_dir, ext=None, only_path=False):
	fixture_path = f'{fixtures_dir}/{name}'
	exts = ['.json', '.txt', '.xml', '.rc']
	if ext:
		exts = [ext]
	for ext in exts:
		path = f'{fixture_path}{ext}'
		if os.path.exists(path):
			if only_path:
				return path
			with open(path) as f:
				content = f.read()
			if path.endswith(('.json', '.yaml')):
				return yaml.load(content, Loader=yaml.Loader)
			else:
				return content


def get_file_timestamp():
	return datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%f_%p")


def detect_host(interface=None):
	adapters = ifaddr.get_adapters()
	for adapter in adapters:
		iface = adapter.name
		if (interface and iface != interface) or iface == 'lo':
			continue
		return adapter.ips[0].ip
	return None


def print_results_table(results, title=None, exclude_fields=[], log=False):
	from secator.output_types import FINDING_TYPES
	from secator.rich import build_table
	_print = console.log if log else console.print
	_print()
	if title:
		title = ' '.join(title.capitalize().split('_')) + ' results'
		h1 = Markdown(f'# {title}')
		_print(h1, style='bold magenta', width=50)
		_print()
	tables = []
	for output_type in FINDING_TYPES:
		items = [
			item for item in results if item._type == output_type.get_name()
		]
		if CONFIG.runners.remove_duplicates:
			items = [item for item in items if not item._duplicate]
		if items:
			_table = build_table(
				items,
				output_fields=output_type._table_fields,
				exclude_fields=exclude_fields,
				sort_by=output_type._sort_by)
			tables.append(_table)
			title = pluralize(items[0]._type).upper()
			_print(f':wrench: {title}', style='bold gold3', justify='left')
			_print(_table)
			_print()
	return tables


def rich_to_ansi(text):
	"""Convert text formatted with rich markup to standard string."""
	from rich.console import Console
	tmp_console = Console(file=None, highlight=False, color_system='truecolor')
	with tmp_console.capture() as capture:
		tmp_console.print(text, end='', soft_wrap=True)
	return capture.get()


def debug(msg, sub='', id='', obj=None, obj_after=True, obj_breaklines=False, level=1):
	"""Print debug log if DEBUG >= level."""
	debug_comp_empty = DEBUG_COMPONENT == [""] or not DEBUG_COMPONENT
	if not debug_comp_empty and not any(sub.startswith(s) for s in DEBUG_COMPONENT):
		return
	elif debug_comp_empty and not DEBUG >= level:
		return
	s = ''
	if sub:
		s += f'[dim yellow4]{sub:13s}[/] '
	obj_str = ''
	if obj:
		sep = ', '
		if obj_breaklines:
			obj_str += '\n '
			sep = '\n '
		if isinstance(obj, dict):
			obj_str += sep.join(f'[dim blue]{k}[/] [dim yellow]->[/] [dim green]{v}[/]' for k, v in obj.items() if v is not None)
		elif isinstance(obj, list):
			obj_str += f'[dim]{sep.join(obj)}[/]'
	if obj_str and not obj_after:
		s = f'{s} {obj_str} '
	s += f'[dim yellow]{msg}[/] '
	if obj_str and obj_after:
		s = f'{s}: {obj_str}'
	if id:
		s += f' [italic dim gray11]\[{id}][/] '
	s = rich_to_ansi(f'[dim red]\[debug] {s}[/]')
	print(s)


def escape_mongodb_url(url):
	"""Escape username / password from MongoDB URL if any.

	Args:
		url (str): Full MongoDB URL string.

	Returns:
		str: Escaped MongoDB URL string.
	"""
	match = re.search('mongodb://(?P<userpass>.*)@(?P<url>.*)', url)
	if match:
		url = match.group('url')
		user, password = tuple(match.group('userpass').split(':'))
		user, password = quote(user), quote(password)
		return f'mongodb://{user}:{password}@{url}'
	return url


def print_version():
	"""Print secator version information."""
	from secator.installer import get_version_info
	console.print(f'[bold gold3]Current version[/]: {VERSION}', highlight=False, end='')
	info = get_version_info('secator', github_handle='freelabz/secator', version=VERSION)
	latest_version = info['latest_version']
	status = info['status']
	location = info['location']
	if status == 'outdated':
		console.print('[bold red] (outdated)[/]')
	else:
		console.print('')
	console.print(f'[bold gold3]Latest version[/]: {latest_version}', highlight=False)
	console.print(f'[bold gold3]Location[/]: {location}')
	console.print(f'[bold gold3]Python binary[/]: {sys.executable}')
	if DEV_PACKAGE:
		console.print(f'[bold gold3]Root folder[/]: {ROOT_FOLDER}')
	console.print(f'[bold gold3]Lib folder[/]: {LIB_FOLDER}')
	if status == 'outdated':
		console.print('[bold red]secator is outdated, run "secator update" to install the latest version.')


def extract_domain_info(input, domain_only=False):
	"""Extracts domain info from a given any URL or FQDN.

	Args:
		input (str): An URL or FQDN.

	Returns:
		tldextract.ExtractResult: Extracted info.
		str | None: Registered domain name or None if invalid domain (only if domain_only is set).
	"""
	result = tldextract.extract(input)
	if not result or not result.domain or not result.suffix:
		return None
	if domain_only:
		if not validators.domain(result.registered_domain):
			return None
		return result.registered_domain
	return result


def extract_subdomains_from_fqdn(fqdn, domain, suffix):
	"""Generates a list of subdomains up to the root domain from a fully qualified domain name (FQDN).

	Args:
		fqdn (str): The full domain name, e.g., 'console.cloud.google.com'.
		domain (str): The main domain, e.g., 'google'.
		suffix (str): The top-level domain (TLD), e.g., 'com'.

	Returns:
		List[str]: A list containing the FQDN and all its subdomains down to the root domain.
	"""
	# Start with the full domain and prepare to break it down
	parts = fqdn.split('.')

	# Initialize the list of subdomains with the full domain
	subdomains = [fqdn]

	# Continue stripping subdomains until reaching the base domain (domain + suffix)
	base_domain = f"{domain}.{suffix}"
	current = fqdn

	while current != base_domain:
		# Remove the leftmost part of the domain
		parts = parts[1:]
		current = '.'.join(parts)
		subdomains.append(current)

	return subdomains


def match_file_by_pattern(paths, pattern, type='both'):
	"""Match pattern on a set of paths.

	Args:
		paths (iterable): An iterable of Path objects to be searched.
		pattern (str): The pattern to search for in file names or directory names, supports Unix shell-style wildcards.
		type (str): Specifies the type to search for; 'file', 'directory', or 'both'.

	Returns:
		list of Path: A list of Path objects that match the given pattern.
	"""
	matches = []
	for path in paths:
		full_path = str(path.resolve())
		if path.is_dir() and type in ['directory', 'both'] and fnmatch.fnmatch(full_path, f'*{pattern}*'):
			matches.append(path)
		elif path.is_file() and type in ['file', 'both'] and fnmatch.fnmatch(full_path, f'*{pattern}*'):
			matches.append(path)

	return matches


def get_file_date(file_path):
	"""Retrieves the last modification date of the file and returns it in a human-readable format.

	Args:
		file_path (Path): Path object pointing to the file.

	Returns:
		str: Human-readable time format.
	"""
	# Get the last modified time of the file
	mod_timestamp = file_path.stat().st_mtime
	mod_date = datetime.fromtimestamp(mod_timestamp)

	# Determine how to display the date based on how long ago it was modified
	now = datetime.now()
	if (now - mod_date).days < 7:
		# If the modification was less than a week ago, use natural time
		return humanize.naturaltime(now - mod_date) + mod_date.strftime(" @ %H:%m")
	else:
		# Otherwise, return the date in "on %B %d" format
		return f"{mod_date.strftime('%B %d @ %H:%m')}"


def trim_string(s, max_length=30):
	"""
	Trims a long string to include the beginning and the end, with an ellipsis in the middle.
	The output string will not exceed the specified maximum length.

	Args:
		s (str): The string to be trimmed.
		max_length (int): The maximum allowed length of the trimmed string.

	Returns:
	str: The trimmed string.
	"""
	if len(s) <= max_length:
		return s  # Return the original string if it's short enough

	# Calculate the lengths of the start and end parts
	end_length = 30  # Default end length
	if max_length - end_length - 5 < 0:  # 5 accounts for the length of '[...] '
		end_length = max_length - 5  # Adjust end length if total max_length is too small
	start_length = max_length - end_length - 5  # Subtract the space for '[...] '

	# Build the trimmed string
	start_part = s[:start_length]
	end_part = s[-end_length:]
	return f"{start_part} [...] {end_part}"


def sort_files_by_date(file_list):
	"""Sorts a list of file paths by their modification date.

	Args:
		file_list (list): A list of file paths (strings or Path objects).

	Returns:
		list: The list of file paths sorted by modification date.
	"""
	file_list.sort(key=lambda x: x.stat().st_mtime)
	return file_list


def traceback_as_string(exc):
	"""Format an exception's traceback as a readable string.

	Args:
		Exception: an exception.

	Returns:
		string: readable traceback.
	"""
	return ' '.join(traceback.format_exception(exc, value=exc, tb=exc.__traceback__))

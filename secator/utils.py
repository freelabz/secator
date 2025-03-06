import fnmatch
import inspect
import importlib
import itertools
import json
import logging
import operator
import os
import tldextract
import re
import select
import sys
import validators
import warnings

from datetime import datetime, timedelta
from functools import reduce
from inspect import isclass
from pathlib import Path
from pkgutil import iter_modules
from time import time
import traceback
from urllib.parse import urlparse, quote

import humanize
import ifaddr
import yaml

from secator.definitions import (DEBUG_COMPONENT, VERSION, DEV_PACKAGE)
from secator.config import CONFIG, ROOT_FOLDER, LIB_FOLDER, download_file
from secator.rich import console

logger = logging.getLogger(__name__)

_tasks = []

TIMEDELTA_REGEX = re.compile(r'((?P<years>\d+?)y)?((?P<months>\d+?)M)?((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?')  # noqa: E501


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


def expand_input(input, ctx):
	"""Expand user-provided input on the CLI:
	- If input is a path, read the file and return the lines.
	- If it's a comma-separated list, return the list.
	- Otherwise, return the original input.

	Args:
		input (str): Input.
		ctx (click.Context): Click context.

	Returns:
		str: Input.
	"""
	if input is None:  # read from stdin
		if not ctx.obj['piped_input']:
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


def import_dynamic(path, name=None):
	"""Import class or module dynamically from path.

	Args:
		path (str): Path to class or module.
		name (str): If specified, does a getattr() on the package to get this attribute.
		cls_root (str): Root parent class.

	Examples:
		>>> import_dynamic('secator.exporters', name='CsvExporter')
		>>> import_dynamic('secator.hooks.mongodb', name='HOOKS')

	Returns:
		cls: Class object.
	"""
	try:
		res = importlib.import_module(path)
		if name:
			res = getattr(res, name)
			if res is None:
				raise
		return res
	except Exception:
		if name:
			path += f'.{name}'
		warnings.warn(f'"{path}" not found.', category=UserWarning, stacklevel=2)
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
	return f'{word}s'


def load_fixture(name, fixtures_dir, ext=None, only_path=False):
	"""Load fixture a fixture dir. Optionally load it's content if it's JSON / YAML.

	Args:
		name (str): Fixture name.
		fixtures_dir (str): Fixture parent directory.
		ext (str, Optional): Extension to load.
		only_path (bool, Optional): Return fixture path instead of fixture content.

	Returns:
		str: Fixture path or content.
	"""
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
	"""Get current timestamp into a formatted string."""
	return datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%f_%p")


def detect_host(interface=None):
	"""Detect hostname from ethernet adapters.

	Args:
		interface (str): Interface name to get hostname from.

	Returns:
		str | None: hostname or ip address, or None if not found.
	"""
	adapters = ifaddr.get_adapters()
	for adapter in adapters:
		iface = adapter.name
		if (interface and iface != interface) or iface == 'lo':
			continue
		return adapter.ips[0].ip
	return None


def rich_to_ansi(text):
	"""Convert text formatted with rich markup to standard string.

	Args:
		text (str): Text.

	Returns:
		str: Converted text (ANSI).
	"""
	from rich.console import Console
	tmp_console = Console(file=None, highlight=False)
	with tmp_console.capture() as capture:
		tmp_console.print(text, end='', soft_wrap=True)
	return capture.get()


def rich_escape(obj):
	"""Escape object for rich printing.

	Args:
		obj (any): Input object.

	Returns:
		any: Initial object, or escaped Rich string.
	"""
	if isinstance(obj, str):
		return obj.replace('[', r'\[').replace(']', r'\]')
	return obj


def format_object(obj, obj_breaklines=False):
	"""Format the debug object for printing.

	Args:
		obj (dict | list): Input object.
		obj_breaklines (bool): Split output with newlines for each item in input object.

	Returns:
		str: Rich-formatted string.
	"""
	sep = '\n ' if obj_breaklines else ', '
	if isinstance(obj, dict):
		return sep.join(f'[dim cyan]{k}[/] [dim yellow]->[/] [dim green]{v}[/]' for k, v in obj.items() if v is not None)  # noqa: E501
	elif isinstance(obj, list):
		return f'[dim green]{sep.join(obj)}[/]'
	return ''


def debug(msg, sub='', id='', obj=None, lazy=None, obj_after=True, obj_breaklines=False, verbose=False):
	"""Print debug log if DEBUG >= level."""
	if not DEBUG_COMPONENT or DEBUG_COMPONENT == [""]:
		return

	if sub:
		if verbose and sub not in DEBUG_COMPONENT:
			sub = f'debug.{sub}'
		if not any(sub.startswith(s) for s in DEBUG_COMPONENT):
			return

	if lazy:
		msg = lazy(msg)

	formatted_msg = f'[yellow4]{sub:13s}[/] ' if sub else ''
	obj_str = format_object(obj, obj_breaklines) if obj else ''

	# Constructing the message string based on object position
	if obj_str and not obj_after:
		formatted_msg += f'{obj_str} '
	formatted_msg += f'[yellow]{msg}[/]'
	if obj_str and obj_after:
		formatted_msg += f': {obj_str}'
	if id:
		formatted_msg += rf' [italic gray11]\[{id}][/]'

	console.print(rf'[dim]\[[magenta4]DBG[/]] {formatted_msg}[/]')


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
	info = get_version_info('secator', install_github_handle='freelabz/secator', version=VERSION)
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
	"""Trims a long string to include the beginning and the end, with an ellipsis in the middle. The output string will
	not exceed the specified maximum length.

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


def should_update(update_frequency, last_updated=None, timestamp=None):
	"""Determine if an object should be updated based on the update frequency and the last updated UNIX timestamp.

	Args:
		update_frequency (int): Update frequency in seconds.
		last_updated (Union[int, None]): UNIX timestamp or None if unset.
		timestamp (int): Item timestamp.

	Returns:
		bool: Whether the object should be updated.
	"""
	if not timestamp:
		timestamp = time()
	if last_updated and (timestamp - last_updated) < update_frequency:
		return False
	return True


def list_reports(workspace=None, type=None, timedelta=None):
	"""List all reports in secator reports dir.

	Args:
		workspace (str): Filter by workspace name.
		type (str): Filter by runner type.
		timedelta (None | datetime.timedelta): Keep results newer than timedelta.

	Returns:
		list: List all JSON reports.
	"""
	if type and not type.endswith('s'):
		type += 's'
	json_reports = []
	for root, _, files in os.walk(CONFIG.dirs.reports):
		for file in files:
			path = Path(root) / file
			if not path.parts[-1] == 'report.json':
				continue
			if workspace and path.parts[-4] != workspace:
				continue
			if type and path.parts[-3] != type:
				continue
			if timedelta and (datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)) > timedelta:
				continue
			json_reports.append(path)
	return json_reports


def get_info_from_report_path(path):
	"""Get some info from the report path, like workspace, run type and id.

	Args:
		path (pathlib.Path): Report path.

	Returns:
		dict: Info dict.
	"""
	try:
		ws, runner_type, number = path.parts[-4], path.parts[-3], path.parts[-2]
		workspace_path = '/'.join(path.parts[:-3])
		return {
			'workspace': ws,
			'workspace_path': workspace_path,
			'type': runner_type,
			'id': number
		}
	except IndexError:
		return {}


def human_to_timedelta(time_str):
	"""Convert human time to a timedelta object.

	Args:
		str: Time string in human format (like 2 years)

	Returns:
		datetime.TimeDelta: TimeDelta object.
	"""
	if not time_str:
		return None
	parts = TIMEDELTA_REGEX.match(time_str)
	if not parts:
		return
	parts = parts.groupdict()
	years = int(parts.pop('years') or 0)
	months = int(parts.pop('months') or 0)
	days = int(parts.get('days') or 0)
	days += years * 365
	days += months * 30
	parts['days'] = days
	time_params = {}
	for name, param in parts.items():
		if param:
			time_params[name] = int(param)
	return timedelta(**time_params)


def deep_merge_dicts(*dicts):
	"""Recursively merges multiple dictionaries by concatenating lists and merging nested dictionaries.

	Args:
		dicts (tuple): A tuple of dictionary objects to merge.

	Returns:
		dict: A new dictionary containing merged keys and values from all input dictionaries.
	"""
	def merge_two_dicts(dict1, dict2):
		"""Helper function that merges two dictionaries.

		Args:
			dict1 (dict): First dict.
			dict2 (dict): Second dict.
		Returns:
			dict: Merged dict.
		"""
		result = dict(dict1)  # Create a copy of dict1 to avoid modifying it.
		for key, value in dict2.items():
			if key in result:
				if isinstance(result[key], dict) and isinstance(value, dict):
					result[key] = merge_two_dicts(result[key], value)
				elif isinstance(result[key], list) and isinstance(value, list):
					result[key] += value  # Concatenating lists
				else:
					result[key] = value  # Overwrite if not both lists or both dicts
			else:
				result[key] = value
		return result

	# Use reduce to apply merge_two_dicts to all dictionaries in dicts
	return reduce(merge_two_dicts, dicts, {})


def process_wordlist(val):
	"""Pre-process wordlist option value to allow referencing wordlists from remote URLs or from config keys.

	Args:
		val (str): Can be a config value in CONFIG.wordlists.defaults or CONFIG.wordlists.templates, or a local path,
		or a URL.
	"""
	default_wordlist = getattr(CONFIG.wordlists.defaults, val)
	if default_wordlist:
		val = default_wordlist
	template_wordlist = getattr(CONFIG.wordlists.templates, val)
	if template_wordlist:
		return template_wordlist
	elif Path(val).exists():
		return val
	else:
		return download_file(
			val,
			target_folder=CONFIG.dirs.wordlists,
			offline_mode=CONFIG.offline_mode,
			type='wordlist'
		)


def convert_functions_to_strings(data):
	"""Recursively convert functions to strings in a dict.

	Args:
		data (dict): Dictionary to convert.

	Returns:
		dict: Converted dictionary.
	"""
	if isinstance(data, dict):
		return {k: convert_functions_to_strings(v) for k, v in data.items()}
	elif isinstance(data, list):
		return [convert_functions_to_strings(v) for v in data]
	elif callable(data):
		return json.dumps(data.__name__)  # or use inspect.getsource(data) if you want the actual function code
	else:
		return data

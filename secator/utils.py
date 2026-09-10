import fcntl
import importlib
import ipaddress
import itertools
import json
import orjson
import logging
import operator
import os
import re
import select
import signal
import socket
import sys
import tempfile
import threading
import tldextract
import traceback
import validators
import warnings

import dns.exception
import dns.resolver
import idna

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import reduce
from pathlib import Path
from time import monotonic, time
from urllib.parse import urlparse, quote

import humanize
import ifaddr
import platform
import unicodedata
import yaml

# fmt: off
from secator.definitions import (DEBUG, VERSION, DEV_PACKAGE, IP, HOST, CIDR_RANGE,
								 MAC_ADDRESS, SLUG, UUID, EMAIL, IBAN, URL, PATH, HOST_PORT, GCS_URL)
# fmt: on
from secator.config import CONFIG, ROOT_FOLDER, LIB_FOLDER, download_file
from secator.rich import console

logger = logging.getLogger(__name__)

_tasks = []

TIMEDELTA_REGEX = re.compile(r'((?P<years>\d+?)y)?((?P<months>\d+?)M)?((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?')  # noqa: E501
CAMEL_TO_SNAKE_REGEX = re.compile(r'(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')


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
	piped_input = ctx.obj['piped_input']
	dry_run = ctx.obj['dry_run']
	default_inputs = ctx.obj['default_inputs']
	input_required = ctx.obj['input_required']
	if input is None:  # read from stdin
		if not piped_input and input_required and not default_inputs and not dry_run:
			console.print('No input passed on stdin. Showing help page.', style='bold red')
			ctx.get_help()
			sys.exit(1)
		elif piped_input:
			rlist, _, _ = select.select([sys.stdin], [], [], CONFIG.cli.stdin_timeout)
			if rlist:
				data = sys.stdin.read().splitlines()
				return data
			else:
				console.print('No input passed on stdin.', style='bold red')
				sys.exit(1)
		elif default_inputs:
			console.print('[bold yellow]No inputs provided, using default inputs:[/]')
			for inp in default_inputs:
				console.print(f'  • {inp}')
			return default_inputs
		elif not dry_run:
			return []
	elif os.path.exists(input):
		input_types = ctx.obj['input_types']
		if not input_types or 'path' in input_types:
			return input
		elif os.path.isfile(input):
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

	if ctx.obj['dry_run'] and not input:
		return ['TARGET']

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


def sanitize_folder_name(
	name: str,
	replacement_char: str = '_',
	replace_spaces: bool = True,
	replace_hyphens: bool = True,
	max_length: int = 255,
	normalize_unicode: bool = True,
) -> str:
	"""
	Sanitizes a string to be used as a folder name across Windows, Linux, and macOS.

	Args:
		name: The input string to sanitize.
		replacement_char: Character to replace invalid chars (default: '_').
		replace_spaces: If True, replaces spaces with `replacement_char`.
		replace_hyphens: If True, replaces hyphens with `replacement_char`.
		max_length: Maximum allowed length (default: 255, None to disable).
		normalize_unicode: If True, normalizes Unicode (e.g., é → e).

	Returns:
		A sanitized folder name.
	"""
	if not name:
		return 'unnamed_folder'

	# Normalize Unicode (optional, helps with lookalike characters)
	if normalize_unicode:
		name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')

	# Replace spaces and hyphens if enabled
	if replace_spaces:
		name = re.sub(r'\s+', replacement_char, name)
	if replace_hyphens:
		name = name.replace('-', replacement_char)

	# Remove invalid characters (OS-specific)
	if platform.system() == 'Windows':
		# Windows: < > : " / \ | ? * and control chars (0-31)
		invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'
	else:
		# Unix: Only / and null byte are invalid
		invalid_chars = r'[/\x00]'

	sanitized = re.sub(invalid_chars, replacement_char, name)

	# Handle reserved names (Windows only)
	if platform.system() == 'Windows':
		reserved_names = {
			"CON", "PRN", "AUX", "NUL",
			"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		}  # fmt: off
		upper_name = sanitized.upper()
		if upper_name in reserved_names:
			sanitized = f'{sanitized}{replacement_char}'

	# Remove leading/trailing spaces, dots, and replacement chars
	sanitized = sanitized.strip().strip(f'.{replacement_char}')

	# Replace multiple replacement chars with a single one
	sanitized = re.sub(f'{re.escape(replacement_char)}+', replacement_char, sanitized)

	# Truncate if too long
	if max_length and len(sanitized) > max_length:
		sanitized = sanitized[:max_length].rstrip(f'.{replacement_char}')

	# Ensure the name is not empty
	if not sanitized:
		return 'unnamed_folder'

	return sanitized


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
			# keys() is now cached (a constant tuple per class), so the field-only
			# membership check is cheap again — no per-item fields() recompute. Keep
			# the declared-field contract (vs hasattr, which would also match
			# inherited attrs / invoke property getters) and read the value once.
			if attr in sub.keys():
				value = getattr(sub, attr)
				if value not in memo:
					res.append(sub)
					memo.add(value)
		return sorted(res, key=operator.attrgetter(attr))
	return sorted(list(dict.fromkeys(array)))


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


def get_command_category(command):
	"""Get the category of a command based on its Mixin base class.

	Args:
		command (class): Command class.

	Returns:
		str: Command category.
	"""
	category_name = 'misc'  # Default category
	for base in command.__mro__:
		base_name = base.__name__
		if base_name.endswith('Mixin'):
			category_name = base_name[:-5]  # Remove 'Mixin' suffix
			break  # Found the first category mixin in the MRO

	# Convert CamelCase to snake_case/path_case and lowercase
	category = re.sub(r'(?<!^)(?=[A-Z])', '/', category_name).lower()
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
	elif word.endswith('s'):
		return word + 'es'
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
	return datetime.now().strftime('%Y_%m_%d-%I_%M_%S_%f_%p')


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


def render_yaml(data, dump_kwargs=None, **syntax_kwargs):
	"""Render a dict — or a pre-dumped YAML string — as a syntax-highlighted rich ``Syntax``.

	Defaults to the CLI/config style (ansi-dark theme, no padding, terminal background). Pass
	``dump_kwargs`` for ``yaml.dump`` options and any ``Syntax`` kwargs (theme, line_numbers, …)
	to override per call site.

	Args:
		data (dict | str): a dict to dump, or an already-dumped YAML string (used verbatim).
		dump_kwargs (dict): extra kwargs for ``yaml.dump`` (defaults: sort_keys=False,
			default_flow_style=False).

	Returns:
		rich.syntax.Syntax: the highlighted YAML.
	"""
	from rich.syntax import Syntax
	if isinstance(data, str):
		yaml_str = data
	else:
		dump = {'sort_keys': False, 'default_flow_style': False, **(dump_kwargs or {})}
		yaml_str = yaml.dump(data, **dump).rstrip()
	opts = {'theme': 'ansi-dark', 'padding': 0, 'background_color': 'default', **syntax_kwargs}
	return Syntax(yaml_str, 'yaml', **opts)


def rich_to_ansi(text):
	"""Convert text formatted with rich markup to standard string.

	Args:
		text (str): Text.

	Returns:
		str: Converted text (ANSI).
	"""
	try:
		from rich.console import Console

		tmp_console = Console(file=None, highlight=False, force_terminal=True)
		with tmp_console.capture() as capture:
			tmp_console.print(text, end='', soft_wrap=True)
		return capture.get()
	except Exception:
		print(f'Could not convert rich text to ansi: {text}[/]', file=sys.stderr)
		return text


def strip_rich_markup(text):
	"""Strip rich markup from text.

	Args:
		text (str): Text.

	Returns:
		str: Text without rich markup.
	"""
	from rich.text import Text

	return Text.from_markup(text).plain


def rich_escape(obj):
	"""Escape object for rich printing.

	Args:
		obj (any): Input object.

	Returns:
		any: Initial object, or escaped Rich string.
	"""
	if isinstance(obj, str):
		return obj.replace('[', r'\[').replace(']', r'\]').replace(r'\[/', r'\[\/')
	return obj


def format_debug_object(obj, obj_breaklines=False):
	"""Format the debug object for printing.

	Args:
		obj (dict | list): Input object.
		obj_breaklines (bool): Split output with newlines for each item in input object.

	Returns:
		str: Rich-formatted string.
	"""
	sep = '\n ' if obj_breaklines else ', '
	if isinstance(obj, dict):
		return sep.join(f'[bold blue]{k}[/] [yellow]->[/] [blue]{v}[/]' for k, v in obj.items() if v is not None)  # noqa: E501
	elif isinstance(obj, list):
		return f'[dim green]{sep.join(obj)}[/]'
	return ''


def debug(msg, sub='', id='', obj=None, lazy=None, obj_after=True, obj_breaklines=False, verbose=False, log_hook=None):
	"""Print debug log if DEBUG >= level."""
	if log_hook:
		formatted_msg = ''
		if msg:
			formatted_msg += str(msg)
		if obj:
			formatted_msg += f'\n{json.dumps(obj, indent=4, default=str)}'
		log_hook(formatted_msg)

	if not DEBUG == ['all'] and not DEBUG == ['1'] and not DEBUG == ['*']:
		if not DEBUG or DEBUG == ['']:
			return
		if sub:
			for s in DEBUG:
				if '*' in s and re.match(s + '$', sub):
					break
				elif not verbose and sub.startswith(s):
					break
				elif verbose and sub == s:
					break
			else:
				return

	if lazy:
		msg = lazy(msg)

	formatted_msg = f'[yellow4]{sub:13s}[/] ' if sub else ''
	obj_str = format_debug_object(obj, obj_breaklines) if obj else ''

	# Constructing the message string based on object position
	if obj_str and not obj_after:
		formatted_msg += f'{obj_str} '
	formatted_msg += f'[yellow]{msg}[/]'
	if obj_str and obj_after:
		formatted_msg += f': {obj_str}'
	if id:
		formatted_msg += rf' [italic gray11]\[{id}][/]'

	try:
		console.print(rf'[dim]\[[magenta4]DBG[/]] {formatted_msg}[/]', highlight=False)
	except Exception:
		console.print(rf'[dim]\[[magenta4]DBG[/]] <MARKUP_DISABLED>{rich_escape(formatted_msg)}</MARKUP_DISABLED>[/]', highlight=False)  # noqa: E501
		if 'rich' in DEBUG:
			raise


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


def caml_to_snake(name):
	"""
	Convert CamelCase string to snake_case, handling acronyms properly.

	Examples:
		>>> caml_to_snake("MongoDB")
		'mongo_db'
		>>> caml_to_snake("MONGODB")
		'mongodb'
		>>> caml_to_snake("getHTTPResponseCode")
		'get_http_response_code'
		>>> caml_to_snake("XMLHttpRequest")
		'xml_http_request'
		>>> caml_to_snake("HTMLElement")
		'html_element'
	"""
	if not name:
		return ''
	name = CAMEL_TO_SNAKE_REGEX.sub(r'_', name)
	return name.lower().replace('__', '_')


def to_title_case_hyphenated(name):
	"""Convert a string to title case with hyphens.

	Args:
		name (str): String to convert.

	Returns:
		str: Title case string with hyphens.
	"""
	return '-'.join(word.capitalize() for word in name.split('-'))


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
		domain_only (bool): Return only the registered domain name.

	Returns:
		tldextract.ExtractResult: Extracted info.
		str | None: Registered domain name or None if invalid domain (only if domain_only is set).
	"""
	result = tldextract.extract(input)
	if not result or not result.domain or not result.suffix:
		return None
	if domain_only:
		if not validators.domain(result.top_domain_under_public_suffix):
			return None
		return result.top_domain_under_public_suffix
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
	base_domain = f'{domain}.{suffix}'
	current = fqdn

	while current != base_domain:
		# Remove the leftmost part of the domain
		parts = parts[1:]
		current = '.'.join(parts)
		subdomains.append(current)

	return subdomains


def humanize_date(dt):
	"""Returns a human-readable format for a datetime object or ISO format string.

	Args:
		dt (datetime | str): Datetime object or ISO format string.

	Returns:
		str: Human-readable time format.
	"""
	if dt is None:
		return ''
	if isinstance(dt, str):
		try:
			dt = datetime.fromisoformat(dt)
		except (ValueError, TypeError):
			return str(dt)
	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=timezone.utc)
	dt_local = dt.astimezone(tz=None)
	now = datetime.now(timezone.utc)
	diff = now - dt
	if diff.days < 1:
		return humanize.naturaltime(diff) + dt_local.strftime(' @ %H:%M')
	else:
		return f'{dt_local.strftime("%B %d @ %H:%M")}'


def trim_string(s, max_length=30, mode='middle'):
	"""Trims a long string with an ellipsis indicator.

	Args:
		s (str): The string to be trimmed.
		max_length (int): The maximum allowed length of the trimmed string.
		mode (str): Where to trim - 'start' (keep end), 'middle' (keep start+end), or 'end' (keep start).

	Returns:
		str: The trimmed string.
	"""
	if not isinstance(s, str):
		return s
	if len(s) <= max_length:
		return s

	ellipsis = '...'
	elen = len(ellipsis)

	if mode == 'start':
		offset = max_length - elen
		return ellipsis + s[-offset:]
	elif mode == 'end':
		return s[: max_length - elen] + ellipsis
	else:  # middle
		available = max_length - elen
		start_length = (available + 1) // 2
		end_length = available - start_length
		return rf'{s[:start_length]} {ellipsis} {s[-end_length:]}' if end_length > 0 else s[: max_length - elen] + ellipsis


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
	if update_frequency == -1:
		return False
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
	if workspace:
		workspace = sanitize_folder_name(workspace)
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
		return {'workspace': ws, 'workspace_path': workspace_path, 'type': runner_type, 'id': number}
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
					result[key] = result[key] + value
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
	print(val)
	default_wordlist = getattr(CONFIG.wordlists.defaults, val)
	if default_wordlist:
		val = default_wordlist
	template_wordlist = getattr(CONFIG.wordlists.templates, val)
	if template_wordlist:
		val = template_wordlist

	return download_file(val, target_folder=CONFIG.dirs.wordlists, offline_mode=CONFIG.offline_mode, type='wordlist')


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


def headers_to_dict(header_opt):
	# If already a dict, return as-is
	if isinstance(header_opt, dict):
		return header_opt
	headers = {}
	for header in header_opt.split(';;'):
		split = header.strip().split(':')
		key = split[0].strip()
		val = ':'.join(split[1:]).strip()
		headers[key] = val
	return headers


def parse_raw_http_request(raw_request):
	"""Parse a raw HTTP request (Burp-style format) and extract method, URL, headers, and body.

	Args:
		raw_request (str): Raw HTTP request string.

	Returns:
		dict: Dictionary containing 'method', 'url', 'headers', and 'data'.
	"""
	lines = raw_request.strip().split('\n')
	if not lines or not lines[0]:
		return {}

	# Parse request line (e.g., "POST /test HTTP/1.1")
	request_line = lines[0].strip()
	parts = request_line.split(' ')
	if len(parts) < 3:
		return {}

	method = parts[0]
	path = parts[1]

	# Parse headers
	headers = {}
	body_start = len(lines)  # Default to end of lines (no body)
	found_empty_line = False
	for i, line in enumerate(lines[1:], start=1):
		line_stripped = line.strip()
		if not line_stripped:
			# Empty line indicates end of headers
			body_start = i + 1
			found_empty_line = True
			break
		if ':' in line_stripped:
			key, value = line_stripped.split(':', 1)
			headers[key.strip()] = value.strip()
		else:
			# If we encounter a line without a colon and no empty line yet, it's not a valid header format
			# This shouldn't happen in properly formatted requests, but we'll handle it gracefully
			break

	# Extract host from headers to construct full URL
	host = headers.get('Host', '')
	if not host:
		return {}

	# Determine scheme (default to https if not specified)
	scheme = 'https'
	# If port 80 is explicitly in host, use http
	if ':80' in host and not host.startswith('['):
		scheme = 'http'

	# Construct full URL
	url = f'{scheme}://{host}{path}'

	# Parse body (everything after the empty line)
	body = ''
	if found_empty_line and body_start < len(lines):
		body = '\n'.join(lines[body_start:]).strip()

	return {'method': method, 'url': url, 'headers': headers, 'data': body}


def format_token_count(tokens, icon='', compact=False):
	"""Format a token count as a human-readable string (e.g., '8.5k tokens').

	Args:
		tokens: Number of tokens.
		icon: Optional Rich emoji icon prefix (e.g., 'arrow_up', 'arrow_down').
		compact: If True, omit 'tokens' suffix (e.g., '8.5k' instead of '8.5k tokens').

	Returns:
		str: Formatted token string.
	"""
	prefix = f':{icon}: ' if icon else ''
	if tokens >= 1000:
		return f'{prefix}{tokens / 1000:.1f}k tokens'
	return f'{prefix}{tokens} tokens'


def format_object(obj, color='magenta', skip_keys=[], predicate=lambda x: True):
	if isinstance(obj, list) and obj:
		return ' [' + ', '.join([f'[{color}]{rich_escape(item)}[/]' for item in obj if predicate(item)]) + ']'
	elif isinstance(obj, dict) and obj.keys():
		obj = {k: v for k, v in obj.items() if k.lower().replace('-', '_') not in skip_keys if predicate(v)}
		if obj:
			return ' [' + ', '.join([f'[bold {color}]{rich_escape(k)}[/]: [{color}]{rich_escape(trim_string(v))}[/]' for k, v in obj.items()]) + ']'  # noqa: E501
	return ''


def is_host_port(target):
	"""Check if a target is a host:port.

	Args:
		target (str): The target to check.

	Returns:
		bool: True if the target is a host:port, False otherwise.
	"""
	host, port = _split_host_port(target)
	if not port:
		return False
	if not (validators.domain(host) or validators.ipv4(host) or validators.ipv6(host) or host == 'localhost'):
		return False
	try:
		port = int(port)
		if port < 1 or port > 65535:
			return False
	except ValueError:
		return False
	return True


def _split_host_port(target):
	"""Split a host:port token into (host, port_str), unwrapping a bracketed IPv6 host.

	[2001:db8::1]:443 -> ('2001:db8::1', '443') -- the brackets, not the last colon, delimit the
	host, since an IPv6 literal contains colons of its own. A bare hostname/IP with no port yields
	(host, ''). Pure, no I/O.
	"""
	if target.startswith('[') and ']:' in target:
		host, _, port = target[1:].partition(']:')
		return host, port
	host, sep, port = target.rpartition(':')
	if not sep:
		return port, ''  # no colon -> rpartition puts the whole token in the last field
	return host, port


def autodetect_type(target):
	"""Autodetect the type of a target.

	Args:
		target (str): The target to autodetect the type of.

	Returns:
		str: The type of the target.
	"""
	if validators.url(target, simple_host=True):
		return URL
	elif target.startswith('gs://'):
		return GCS_URL
	elif validate_cidr_range(target):
		return CIDR_RANGE
	elif validators.ipv4(target) or validators.ipv6(target) or target == 'localhost':
		return IP
	elif validators.domain(target):
		return HOST
	elif is_host_port(target):
		return HOST_PORT
	elif validators.mac_address(target):
		return MAC_ADDRESS
	elif validators.email(target):
		return EMAIL
	elif validators.iban(target):
		return IBAN
	elif validators.uuid(target):
		return UUID
	elif len(target) < 255 and Path(target).exists():
		return PATH
	elif validators.slug(target):
		return SLUG

	return str(type(target).__name__).lower()


def validate_cidr_range(target):
	if '/' not in target:
		return False
	try:
		ipaddress.ip_network(target, False)
		return True
	except ValueError:
		return False


# Network types that name a routable target (as opposed to slug / email / iban / ...).
# HOST covers both bare hostnames and registrable domains (autodetect_type returns HOST for both).
NETWORK_TYPES = (IP, CIDR_RANGE, HOST, HOST_PORT, URL)


@dataclass
class TargetInfo:
	"""Result of classify_target(). Single source of truth the API imports (never reimplement)."""
	type: str          # autodetect_type() taxonomy: ip / cidr_range / host / url / slug / email / ...
	is_network: bool    # ip|cidr: valid by construction (no DNS). host|url: DNS resolved. else False.
	root: str           # url -> hostname ; cidr -> network address ; else the (canonical) token
	reachable: bool     # ip|cidr: validity. host|url: DNS success. else False.


def canonicalize_target(raw):
	"""Normalize a single raw target token to the form a scanner/resolver would actually hit.

	This closes classification-smuggling gaps: alternate IPv4 encodings (decimal 2130706433,
	octal 0177.0.0.1, short 127.1, hex 0x7f.0.0.1 -- all via inet_aton semantics), IDNA/Unicode
	hostnames, bracketed IPv6, and surrounding whitespace all collapse to their canonical string
	BEFORE type detection runs. Pure function, no network I/O.

	Args:
		raw (str): A single target token (not a list -- use split_targets first).

	Returns:
		str: Canonical target string.
	"""
	if raw is None:
		return ''
	token = str(raw).strip()
	if not token:
		return ''

	# Bracketed IPv6, but ONLY when the bracketed content is a real IP literal (what brackets are for).
	# Bare [2001:db8::1] -> 2001:db8::1 (brackets unwrapped). With a trailing :port the brackets are
	# the canonical RFC 3986 host:port separator and MUST be kept -- unwrapping [2001:db8::1]:443 to
	# 2001:db8::1:443 re-parses as a DIFFERENT valid IPv6 (443 becomes a hextet), absorbing the port.
	# So keep the bracketed form and let is_host_port / _target_host split host from port.
	# A non-IP like [a-z].example.com keeps its brackets -> caught as a scope entry.
	if token.startswith('['):
		end = token.find(']')
		if end != -1 and _is_ip_literal(token[1:end]) and token[end + 1:] == '':
			token = token[1:end]

	# Alternate IPv4 encodings -> dotted-quad, using inet_aton (same parser nmap/ping/libc use).
	# Only numeric-ish tokens reach a match; hostnames and out-of-range ints raise and fall through.
	try:
		token = socket.inet_ntoa(socket.inet_aton(token))
		return token
	except OSError:
		pass

	# IDNA-encode Unicode hostnames (bare host or URL netloc) to punycode.
	if not token.isascii():
		token = _idna_encode(token)

	return token


def _idna_encode(token):
	"""Best-effort IDNA (punycode) encoding of a Unicode host or URL netloc. Pure, no I/O."""
	scheme = rest = ''
	host = token
	if '://' in token:
		scheme, _, after = token.partition('://')
		scheme += '://'
		# split host from path/query/port
		slash = after.find('/')
		host, rest = (after, '') if slash == -1 else (after[:slash], after[slash:])
	try:
		encoded = idna.encode(host, uts46=True).decode('ascii')
	except (idna.IDNAError, UnicodeError):
		return token  # not a valid IDN host -> leave as-is (will classify non-network)
	return f'{scheme}{encoded}{rest}'


def split_targets(raw):
	"""Split a raw multi-target input into individual tokens on comma AND newline.

	Consolidates the two split styles core already used ad hoc (CLI split(',') and stdin/file
	splitlines()) into one reusable, whitespace-trimming, empty-dropping helper.

	Args:
		raw (str | list): Raw input, possibly containing commas and/or newlines, or a list thereof.

	Returns:
		list[str]: Non-empty, stripped tokens.
	"""
	if raw is None:
		return []
	if isinstance(raw, (list, tuple)):
		out = []
		for item in raw:
			out.extend(split_targets(item))
		return out
	# Char-class split, no backtracking -> ReDoS-safe.
	return [t.strip() for t in re.split(r'[,\n]', str(raw)) if t.strip()]


def _resolve_host(host, timeout):
	"""DNS-resolve a hostname (A then AAAA) with a short timeout. Network I/O.

	Returns:
		bool: True if it resolves, False on NXDOMAIN / no answer / timeout / any DNS error.
	"""
	if not host:
		return False
	resolver = dns.resolver.Resolver()
	resolver.timeout = timeout
	resolver.lifetime = timeout
	for rdtype in ('A', 'AAAA'):
		try:
			resolver.resolve(host, rdtype)
			return True
		except dns.resolver.NoAnswer:
			continue  # no A record, try AAAA
		except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
			return False
	return False


def _is_ip_literal(host):
	"""True if host is a v4 or v6 IP literal. Pure -- ipaddress does no DNS."""
	try:
		ipaddress.ip_address(host)
		return True
	except ValueError:
		return False


def _target_host(canonical, ttype):
	"""Extract the DNS-resolvable host from a canonical url / host / host:port token. Pure."""
	if ttype == URL:
		return (urlparse(canonical).hostname or '')
	if ttype == HOST_PORT:
		return _split_host_port(canonical)[0]
	return canonical


def classify_target(token, *, resolve=True, timeout=2.0):
	"""Classify a single target token. THE single-source classifier -- callers must not reimplement.

	Type detection reuses the pure regex `autodetect_type`; all network I/O lives here behind
	`resolve=True`. With `resolve=False` this is a pure no-I/O path (host/url reachability is left
	False/unknown; ip/cidr are still resolved by construction).

	Args:
		token (str): A single target token (use split_targets first for multi-target input).
		resolve (bool): If True, DNS-resolve host/url targets. If False, no network I/O at all.
		timeout (float): Per-query DNS timeout in seconds (short; server-side safe).

	Returns:
		TargetInfo: {type, is_network, root, reachable}.
	"""
	canonical = canonicalize_target(token)
	ttype = autodetect_type(canonical)
	info = TargetInfo(type=ttype, is_network=False, root=canonical, reachable=False)

	# Non-network types keep the False defaults. This also fails scope entries closed: wildcard /
	# regex forms (*.example.com, .*\.corp$, [a-z].example.com) are rejected by autodetect_type's
	# strict validators to STRING, so they are never in NETWORK_TYPES.
	if ttype not in NETWORK_TYPES:
		return info

	if ttype == IP:
		# Validity already proven by autodetect_type (validators/ipaddress) -- no DNS needed.
		info.is_network = info.reachable = True
	elif ttype == CIDR_RANGE:
		info.root = str(ipaddress.ip_network(canonical, strict=False).network_address)
		info.is_network = info.reachable = True
	elif ttype in (URL, HOST, HOST_PORT):
		host = _target_host(canonical, ttype)
		if ttype == URL:
			info.root = host
		if _is_ip_literal(host):
			# An IP literal hiding in url/host:port (8.8.8.8:443, http://8.8.8.8/) is network
			# BY CONSTRUCTION -- never gate its network-ness on DNS (it won't resolve as a name).
			info.is_network = info.reachable = True
		elif resolve:
			ok = _resolve_host(host, timeout)
			info.is_network = info.reachable = ok
		# genuine hostname + resolve=False -> pure path: leave is_network/reachable False (unverified).

	return info


def get_versions_from_string(string):
	"""Get versions from a string.

	Args:
		string (str): String to get versions from.

	Returns:
		list[str]: List of versions.
	"""
	regex = r'v?[0-9]+\.[0-9]+\.?[0-9]*\.?[a-zA-Z]*'
	matches = re.findall(regex, string)
	if not matches:
		return []
	return matches


def signal_to_name(signum):
	"""Convert a signal number to its name"""
	for name, value in vars(signal).items():
		if name.startswith('SIG') and not name.startswith('SIG_') and value == signum:
			return name
	return str(signum)


def trim_gif(input_path, output_path, max_pause_ms=3000):
	"""Cap long pauses in a GIF where the terminal output is static.

	Args:
		input_path (Path): Path to input GIF file.
		output_path (Path): Path to output GIF file.
		max_pause_ms (int): Maximum pause duration in milliseconds (default: 3000).

	Returns:
		bool: True if successful, False otherwise.
	"""
	try:
		from PIL import Image, ImageChops
	except ImportError:
		logger.warning('PIL/Pillow is not installed. GIF optimization is disabled. Install with: pip install Pillow')
		return False

	try:
		with Image.open(input_path) as im:
			frames = []
			durations = []

			# Load the first frame
			im.seek(0)
			prev_frame = im.convert('RGB')

			current_static_duration = 0

			for i in range(im.n_frames):
				im.seek(i)
				duration = im.info.get('duration', 100)
				curr_frame = im.convert('RGB')

				# Check if visual content has changed
				is_static = ImageChops.difference(prev_frame, curr_frame).getbbox() is None

				if is_static and i > 0:
					if current_static_duration + duration > max_pause_ms:
						remaining_allowed = max_pause_ms - current_static_duration
						if remaining_allowed > 0:
							durations.append(remaining_allowed)
							frames.append(im.copy())
							current_static_duration = max_pause_ms
					else:
						current_static_duration += duration
						durations.append(duration)
						frames.append(im.copy())
				else:
					current_static_duration = 0
					durations.append(duration)
					frames.append(im.copy())
					prev_frame = curr_frame

			if frames:
				frames[0].save(
					output_path,
					save_all=True,
					append_images=frames[1:],
					duration=durations,
					loop=im.info.get('loop', 0),
					optimize=True,
				)
				return True
		return False
	except Exception as e:
		logger.warning(f'Failed to optimize GIF: {str(e)}')
		return False


def get_gif_info(input_path):
	"""Get information about a GIF file (dimensions, frames, total pixels).

	Args:
		input_path (Path): Path to input GIF file.

	Returns:
		dict: Dictionary with 'width', 'height', 'frame_count', and 'total_pixels', or None on error.
	"""
	try:
		from PIL import Image
	except ImportError:
		logger.warning('PIL/Pillow is not installed. GIF info is disabled. Install with: pip install Pillow')
		return None

	try:
		with Image.open(input_path) as im:
			width, height = im.size
			frame_count = im.n_frames
			total_pixels = width * height * frame_count
			return {'width': width, 'height': height, 'frame_count': frame_count, 'total_pixels': total_pixels}
	except Exception as e:
		logger.warning(f'Failed to get GIF info: {str(e)}')
		return None


def reduce_gif_frames(input_path, output_path, max_frames=500):
	"""Reduce the number of frames in a GIF by accelerating it.

	Args:
		input_path (Path): Path to input GIF file.
		output_path (Path): Path to output GIF file.
		max_frames (int): Maximum number of frames to keep (default: 500).

	Returns:
		bool: True if successful, False otherwise.
	"""
	try:
		from PIL import Image
	except ImportError:
		logger.warning('PIL/Pillow is not installed. GIF frame reduction is disabled. Install with: pip install Pillow')
		return False

	try:
		with Image.open(input_path) as im:
			total_frames = im.n_frames

			# If already at or below max_frames, no need to reduce
			if total_frames <= max_frames:
				logger.info(f'GIF already has {total_frames} frames (<= {max_frames}), no reduction needed')
				return False

			# Calculate frame sampling interval
			# If we have 1000 frames and want 500, we take every 2nd frame (indices 0, 2, 4, ...)
			step = total_frames / max_frames

			frames = []
			durations = []

			# Collect all original durations first
			original_durations = []
			for i in range(total_frames):
				im.seek(i)
				duration = im.info.get('duration', 100)
				original_durations.append(duration)

			# Sample frames evenly
			kept_indices = []
			for i in range(max_frames):
				idx = int(i * step)
				if idx >= total_frames:
					idx = total_frames - 1
				kept_indices.append(idx)

			# Remove duplicates while preserving order
			seen = set()
			kept_indices = [x for x in kept_indices if not (x in seen or seen.add(x))]

			# Calculate acceleration factor
			# Total duration of kept frames should be proportional to reduction
			# If we keep 50% of frames, we can either:
			# 1. Keep same total duration (sum durations of skipped frames)
			# 2. Accelerate by reducing durations proportionally
			# We'll do option 2 for acceleration
			acceleration_factor = total_frames / len(kept_indices)

			# Load kept frames and adjust durations
			for idx in kept_indices:
				im.seek(idx)
				frames.append(im.copy())
				# Accelerate by reducing duration proportionally
				original_duration = original_durations[idx]
				new_duration = int(original_duration / acceleration_factor)
				# Ensure minimum duration of 10ms for GIF compatibility
				durations.append(max(10, new_duration))

			if frames:
				frames[0].save(
					output_path,
					save_all=True,
					append_images=frames[1:],
					duration=durations,
					loop=im.info.get('loop', 0),
					optimize=True,
				)
				logger.info(f'Reduced GIF from {total_frames} to {len(frames)} frames (accelerated by {acceleration_factor:.2f}x)')
				return True
		return False
	except Exception as e:
		logger.warning(f'Failed to reduce GIF frames: {str(e)}')
		return False


def vhs_tap_to_tape(tap_file, output_tape, width=None, height=None, font_size=12, line_height=1.4, sleep_before=200, sleep_after=500, wait_line=120):  # noqa: E501
	"""Convert .tap file to .tape file for VHS.

	Args:
		tap_file (Path): Path to input .tap file.
		output_tape (Path): Path to output .tape file.
		width (int, optional): Terminal width.
		height (int, optional): Terminal height.
		font_size (int): Font size (default: 12).
		line_height (float): Line height (default: 1.4).
		sleep_before (int): Sleep before command in milliseconds (default: 200).
		sleep_after (int): Sleep after command in milliseconds (default: 2000).
		wait_line (int): Wait line timeout in seconds (default: 30).
	"""
	from secator.output_types import Error, Info

	VHS_KEYWORDS = {
		'Output',
		'Require',
		'Set',
		'Type',
		'Left',
		'Right',
		'Up',
		'Down',
		'Backspace',
		'Enter',
		'Tab',
		'Space',
		'Ctrl',
		'Sleep',
		'Wait',
		'Hide',
		'Show',
		'Screenshot',
		'Copy',
		'Paste',
		'Source',
		'Env',
	}

	# Read tap file
	try:
		with open(tap_file, 'r') as f:
			lines = f.readlines()
	except Exception as e:
		console.print(Error(message=f'Failed to read {tap_file}: {str(e)}'))
		sys.exit(1)

	tape_lines = []

	# Add header: Output and Set Shell
	output_gif = output_tape.with_suffix('.gif').name
	tape_lines.append(f'Output {output_gif}')
	tape_lines.append('Set Shell fish')
	tape_lines.append('Set CursorBlink false')

	# Add terminal dimensions and font size if provided
	if width is not None:
		tape_lines.append(f'Set Width {width}')
	if height is not None:
		tape_lines.append(f'Set Height {height}')
	if font_size is not None:
		tape_lines.append(f'Set FontSize {font_size}')
	tape_lines.append(f'Set LineHeight {line_height}')

	tape_lines.append('')  # Empty line after header

	for line in lines:
		line = line.rstrip('\n\r')

		# Skip empty lines
		if not line.strip():
			continue

		# Check if line starts with a comment
		if line.startswith('#'):
			# Comment line: Type it, Enter, and add Wait
			comment_text = line
			tape_lines.append(f'Type "{comment_text}"')
			tape_lines.append('Enter')
			tape_lines.append(f'Wait+Line@{wait_line}s')
			continue

		# Check for inline comments and flags
		has_noenter = '# noenter' in line
		has_nowait = '# nowait' in line
		has_hide = '# hide' in line

		# Remove flags from the line
		line_clean = line.replace('# noenter', '').replace('# nowait', '').replace('# hide', '')
		line_stripped = line_clean
		if has_noenter or has_nowait or has_hide:
			line_stripped = line_stripped.rstrip()

		# Check if this is a "clear" command
		is_clear = line_stripped == 'clear'

		# Check if line starts with a VHS keyword (handles cases like "Ctrl+C" and "Up 3")
		is_vhs_keyword = any(line_stripped.startswith(keyword) for keyword in VHS_KEYWORDS)

		if is_clear:
			# Handle clear command: Hide, Type, Enter, Sleep, Show, Wait Line
			tape_lines.append('Hide')
			tape_lines.append(f'Type "{line_stripped}"')
			if not has_noenter:
				tape_lines.append('Enter')
			tape_lines.append(f'Wait+Line@{wait_line}s')
			tape_lines.append('Show')
		elif is_vhs_keyword:
			# VHS keyword: use as-is
			tape_lines.append(line_stripped)
		else:
			# Regular command: add Wait before (unless nowait), Type command, Enter (unless noenter), Wait after
			if not has_nowait:
				tape_lines.append(f'Sleep {sleep_before}ms')

			# Add Hide before command if # hide flag is present
			if has_hide:
				tape_lines.append('Hide')

			# Type the command
			tape_lines.append(f'Type "{line_stripped}"')

			# Add Enter unless noenter flag
			if not has_noenter:
				tape_lines.append('Enter')
				# Wait for command output
				if not has_nowait:
					tape_lines.append(f'Wait+Line@{wait_line}s')

			# Add Show after command if # hide flag is present
			if has_hide:
				tape_lines.append('Show')

			# Always add Wait after command
			tape_lines.append(f'Sleep {sleep_after}ms')

	# Write tape file
	try:
		with open(output_tape, 'w') as f:
			f.write('\n'.join(tape_lines) + '\n')
		console.print(Info(message=f'Converted {tap_file} to {output_tape}'))
	except Exception as e:
		console.print(Error(message=f'Failed to write {output_tape}: {str(e)}'))
		sys.exit(1)


def remove_duplicates(items):
	"""Remove duplicate items using hash-based grouping (O(n)).

	Handles both OutputType instances (uses _compare_key()) and plain dicts
	(loads into OutputType via _type field, then uses _compare_key()).

	Args:
		items (list): List of OutputType instances or dicts.

	Returns:
		list: Deduplicated list preserving first occurrence order.
	"""
	from collections import OrderedDict

	def _get_key(item):
		if hasattr(item, '_compare_key'):
			return item._compare_key()
		# Plain dict: try to load into the appropriate OutputType to use _compare_key()
		if isinstance(item, dict):
			from secator.output_types import OUTPUT_TYPES

			_type = item.get('_type')
			if _type:
				for cls in OUTPUT_TYPES:
					if cls.get_name() == _type:
						try:
							return cls.load(item)._compare_key()
						except Exception as e:
							debug(f'remove_duplicates: failed to load {_type}: {e}', sub='utils')
			# Fallback: JSON-serialize sorted items
			try:
				return json.dumps(sorted(item.items()), sort_keys=True, default=str)
			except Exception as e:
				debug(f'remove_duplicates: JSON fallback failed: {e}', sub='utils')
		return id(item)

	seen = OrderedDict()
	for item in items:
		key = _get_key(item)
		if key not in seen:
			seen[key] = item
	return list(seen.values())


# --- Atomic JSON: concurrency-safe read-modify-write of a JSON file ----------
#
# A layered lock makes a JSON file safe to update from many writers at once,
# correct under both Celery pools (prefork processes + gevent greenlets):
#   1. per-path in-process lock (``threading.Lock``) — gevent monkey-patches
#      threading, so this is greenlet-cooperative under the gevent pool and a
#      real mutex under prefork threads. It serializes same-process writers
#      BEFORE they touch the OS lock, so the blocking flock is only ever
#      contended across processes (rare), never stalling the gevent hub.
#   2. ``fcntl.flock(LOCK_EX)`` on a stable sidecar ``.lock`` file — mutual
#      exclusion across prefork processes. It is a *separate* file (never
#      replaced/unlinked), so os.replace() can't pull the locked inode out from
#      under a holder.
#   3. tempfile + ``os.replace`` — atomic on POSIX, so a concurrent reader
#      always sees a whole old-or-new file, never a torn write. That is why
#      read_json() below can snapshot lock-free.

# One lock object per path, so same-process writers (greenlets under gevent,
# threads under prefork) serialize before the cross-process flock.
_path_locks = {}
_path_locks_guard = threading.Lock()


def _get_path_lock(path):
	key = str(path)
	lock = _path_locks.get(key)
	if lock is None:
		with _path_locks_guard:
			lock = _path_locks.get(key)
			if lock is None:
				lock = threading.Lock()
				_path_locks[key] = lock
	return lock


def _read_json(path, default):
	"""Read a JSON file. Absent -> default(); corrupt -> raise.

	Absence is normal (first write), so it returns ``default()`` (a callable
	factory, e.g. ``dict``). Corruption is NOT normal — os.replace makes torn
	writes impossible, so a JSONDecodeError means a real anomaly. We let it
	propagate rather than reset to empty, so a read-modify-write never clobbers a
	corrupt-but-present file (and its accumulated data) with a blank one.
	"""
	try:
		with open(path, 'rb') as f:
			return orjson.loads(f.read())
	except FileNotFoundError:
		return default()


def _atomic_write(path, data):
	"""Write JSON to a temp file in the same dir, then os.replace() over the target."""
	path = Path(path)
	fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix='.report-', suffix='.json.tmp')
	try:
		with os.fdopen(fd, 'wb') as f:
			f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2, default=str))
			f.flush()
			os.fsync(f.fileno())
		os.replace(tmp, path)
	# Clean up the orphaned temp file on ANY failure (incl. KeyboardInterrupt /
	# SystemExit before os.replace lands), then re-raise — nothing is swallowed.
	except BaseException:
		try:
			os.unlink(tmp)
		except OSError:
			pass
		raise


@contextmanager
def atomic_json(path, default=dict):
	"""Locked read-modify-write of a JSON file, as a context manager.

	Yields the parsed data (default() if the file is absent; a present-but-corrupt
	file raises rather than being reset to empty, so a read-modify-write never
	clobbers accumulated data); the caller mutates it in place. On clean block exit
	the data is written back atomically
	(tempfile + fsync + os.replace). On exception, nothing is written — the file
	is left unchanged. The layered lock is always released in ``finally``.

	Wholesale replace is just ``data.clear(); data.update(new)`` inside the block.

	Args:
		path (str | Path): JSON file path (parent dirs are created).
		default (callable): factory for the fallback value when the file is
			absent, e.g. ``dict``, ``list``, ``lambda: {'info': {}, 'results': {}}``.

	Notes:
		- The block runs while the lock is HELD — keep it to the read-modify-write,
		  no slow I/O / subprocess inside, or you serialize every other writer.
		- The ``.lock`` sidecar file persists (never unlinked — unlinking races
		  holders); this is harmless.
		- Safe under both Celery pools (prefork processes + gevent greenlets).
	"""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	lock_path = str(path) + '.lock'
	# Perf instrumentation (SECATOR_DEBUG=perf): one line per call with the lock-acquire wait and
	# write time, to diagnose gevent-hub stalls / lock contention on the json write path in prod.
	_t0 = monotonic()
	lock_wait_ms = write_ms = 0.0
	with _get_path_lock(path):                        # (1) in-process (greenlet/thread cooperative)
		with open(lock_path, 'w') as lock_fd:
			fcntl.flock(lock_fd, fcntl.LOCK_EX)       # (2) cross-process (prefork); blocking under gevent
			lock_wait_ms = (monotonic() - _t0) * 1000
			try:
				data = _read_json(path, default)
				yield data
				_tw = monotonic()
				_atomic_write(path, data)             # (3) atomic swap (clean exit only)
				write_ms = (monotonic() - _tw) * 1000
			finally:
				fcntl.flock(lock_fd, fcntl.LOCK_UN)
	debug(
		f'atomic_json g={threading.get_ident() % 100000} {path.name} '
		f'lock_wait={lock_wait_ms:.1f}ms write={write_ms:.1f}ms',
		sub='perf',
	)


def append_ndjson(path, line):
	"""Append one line (a single JSON record, no trailing newline) to an NDJSON file.

	O(1): opens in append mode and writes one line — never reads or parses the existing
	content. Uses the SAME layered lock as ``atomic_json`` (in-process path lock +
	cross-process ``flock`` on the ``.lock`` sidecar) so concurrent appenders — prefork
	processes and gevent greenlets — never interleave a partial write. A record can exceed
	``PIPE_BUF`` (4 KB), so a bare ``write`` is not atomic on its own; the lock is required.
	"""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	lock_path = str(path) + '.lock'
	with _get_path_lock(path):
		with open(lock_path, 'w') as lock_fd:
			fcntl.flock(lock_fd, fcntl.LOCK_EX)
			try:
				with open(path, 'a') as f:
					f.write(line + '\n')
			finally:
				fcntl.flock(lock_fd, fcntl.LOCK_UN)


def read_json(path, default=dict):
	"""Lock-free snapshot read of a JSON file written by ``atomic_json``.

	Safe without a lock because writers use os.replace(), so a reader always sees a
	complete old-or-new file, never a torn write. Returns ``default()`` (a callable
	factory) if the file is absent; a present-but-corrupt file raises
	JSONDecodeError (a real anomaly, not silently masked).
	"""
	return _read_json(path, default)

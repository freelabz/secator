import importlib
import inspect
import itertools
import logging
import mimetypes
import os
import warnings
from importlib import import_module
from inspect import isclass
from pathlib import Path
from pkgutil import iter_modules
from urllib.parse import urlparse

import tabulate
from furl import furl

logger = logging.getLogger(__name__)


def setup_logging(level):
	"""Setup logging.

	Args:
		level: logging level.
	
	Returns:
		logging.Logger: logger.
	"""
	logger = logging.getLogger('secsy')
	logger.setLevel(level)
	ch = logging.StreamHandler()
	ch.setLevel(level)
	formatter = logging.Formatter('%(message)s')
	ch.setFormatter(formatter)
	logger.addHandler(ch)
	return logger


def maybe_read_file(input, splitlines=True):
	"""If input is a path, return the file lines. Otherwise, return the original
	input.

	Args:
		input (str): Input.
		splitlines (bool, Optional): Split lines and return list.

	Returns:
		str: Input.
	"""
	if os.path.exists(input):
		with open(input, 'r') as f:
			data = f.read()
			if splitlines:
				data = data.splitlines()
		return data
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


def match_extensions(response, allowed_ext=['.html']):
	"""Check if a URL is a file from the HTTP response by looking at the 
	content_type and the URL.

	Args:
		response (dict): httpx response.

	Returns:
		bool: True if is a file, False otherwise.
	"""
	content_type = response.get('content_type', '').split(';')[0]
	url = response.get('final_url') or response['url']
	ext = mimetypes.guess_extension(content_type)
	ext2 = os.path.splitext(urlparse(url).path)[1]
	if (ext and ext in allowed_ext) or (ext2 and ext2 in allowed_ext):
		return True
	return False


def filter_urls(urls, **remove_parts):
	"""Filter a list of URLs using `furl`.

	Args:
		urls (list): List of URLs to filter.
		remove_parts (dict): Dict of URL pieces to remove.

	Example:
		>>> urls = ['http://localhost/test.js', 'http://localhost/test?a=1&b=2']
		>>> filter_urls(urls, filter_ext=True)
		['http://localhost/test']

	Returns:
		list: List of filtered URLs.
	"""
	if not remove_parts:
		return urls
	furl_remove_args = {
		k.replace('remove_', ''): v for k, v in remove_parts.items()
	}
	return [
		sanitize_url(furl(url).remove(**furl_remove_args).url)
		for url in urls
	]


def fmt_table(data, output_table_fields=[], sort_by=None):
	"""Format data as table.

	Args:
		data (list): List of dict items.
		output_table_fields (list): List of output fields.
		sort_by (str): Sort by field.

	Returns:
		str: Formatted table.
	"""
	if sort_by:
		data = sorted(data, key=lambda x: x[sort_by])
	keys = output_table_fields if output_table_fields else data[0].keys()
	headers = [
		' '.join(k.split('_')).capitalize()
		for k in keys
	]
	fmt_data = []
	for item in data:
		new_item = {}
		for k in keys:
			value = item.get(k)
			if isinstance(value, list):
					value = ', '.join(sorted(value))
			elif isinstance(value, dict):
					value = '\n'.join(f'{k}:{v}' for k, v in value.items())
			new_item[k] = value
		fmt_data.append(new_item)
	values = [d.values() for d in fmt_data]
	return '\n' + tabulate.tabulate(values, headers=headers, tablefmt='fancy_grid') + '\n'


def deduplicate(l, key=None):
	"""Deduplicate list of dicts or simple list.

	Args:
		l (list): Input list.

	Returns:
		list: Deduplicated list.
	"""
	if key and len(l) > 0 and isinstance(l[0], dict):
		memo = set()
		res = []
		for sub in l:
			if key in sub and sub[key] not in memo:
				res.append(sub)
				memo.add(sub[key])
		return sorted(res, key=lambda x: x[key])
	return sorted(list(dict.fromkeys(l)))


def setup_logger(level='info', format='%(message)s'):
	logger = logging.getLogger('secsy')
	level = logging.getLevelName(level.upper())
	logger.setLevel(level)
	handler = logging.StreamHandler()
	formatter = logging.Formatter(format)
	handler.setFormatter(formatter)
	logger.addHandler(handler)
	return logger


def find_internal_commands():
	"""Find internal secsy commands."""
	from secsy.cmd import CommandRunner
	package_dir = Path(__file__).resolve().parent / 'tools'
	tools = []
	for (_, module_name, _) in iter_modules([str(package_dir)]):
		module = import_module(f"secsy.tools.{module_name}")
		for attribute_name in dir(module):
			attribute = getattr(module, attribute_name)
			if isclass(attribute):
				bases = inspect.getmro(attribute)
				for base in bases:
					if base == CommandRunner and attribute.cmd:
						tools.append(attribute)
	# Sort tools by category
	tools = sorted(tools, key=lambda x: (get_command_category(x), x.__name__))

	return tools


def find_external_commands():
	"""Find external secsy commands."""
	if not os.path.exists('config.secsy'):
		return []
	with open('config.secsy', 'r') as f:
		classes = f.read().splitlines()
	output = []
	for cls_path in classes:
		cls = import_dynamic(cls_path)
		if not cls:
			continue
		# logger.warning(f'Added external tool {cls_path}')
		output.append(cls)
	return output


def import_dynamic(cls_path, cls_root='CommandRunner'):
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
	except Exception as e:
		warnings.warn(f'"{package}.{name}" not found.')
		return None


def get_command_cls(cls_name):
	"""Get secsy command by class name.

	Args:
		cls_name (str): Class name to load.

	Returns:
		cls: Class.
	"""
	tools = find_internal_commands() + find_external_commands()
	for tool in tools:
		if tool.__name__ == cls_name:
			return tool
	return None


def get_command_category(command):
	"""Get the category of a command.

	Args:
		command (class): Command class.

	Returns:
		str: Command category.
	"""
	return command.__bases__[0].__name__.replace('Command', '').replace('Runner', 'misc').lower()


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
			opts_noemtpy = {k: v for k, v in opts.items() if v is not None}
			all_opts.update(opts_noemtpy)
	return all_opts


def flatten(l: list):
	"""Flatten list if it contains multiple sublists.

	Args:
		l (list): Input list.

	Returns:
		list: Output list.
	"""
	if isinstance(l, list) and len(l) > 0 and isinstance(l[0], list):
		return list(itertools.chain(*l))
	return l


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
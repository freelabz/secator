import json
import logging
import os
import re
import shlex
import subprocess
import sys
from time import sleep

from celery.result import AsyncResult
from dotmap import DotMap
from fp.fp import FreeProxy

from secsy.definitions import (DEBUG, DEFAULT_PROXY_TIMEOUT, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, TEMP_FOLDER)
from secsy.output_types import OutputType
from secsy.rich import console, console_stdout
from secsy.serializers import JSONSerializer
from secsy.utils import get_file_timestamp, pluralize, print_results_table

# from rich.markup import escape
# from rich.text import Text


logger = logging.getLogger(__name__)

HOOKS = [
	'on_init',
	'on_start',
	'on_end',
	'on_item_pre_convert',
	'on_item',
	'on_line',
	'on_iter',
	'on_error'
]

VALIDATORS = [
	'input',
	'item'
]


class TaskBase:
	# Input field (mostly for tests and CLI)
	input_type = None

	# Output types
	output_types = None

	# Dict return
	output_return_type = dict  # TODO: deprecate this

	def __init__(self, input=None, **cmd_opts):
		self.cmd_opts = cmd_opts.copy()
		self.results = []
		self.sync = self.cmd_opts.pop('sync', True)
		self.context = self.cmd_opts.pop('context', {})
		self.description = self.cmd_opts.pop('description', None)
		self.name = self.__class__.__name__
		self.output = ''
		self.done = False
		self.status = 'RUNNING'
		self.progress = 0
		self.error = ''
		self.results_count = 0

		# Proxy config (global)
		self.proxy = self.cmd_opts.pop('proxy', False)
		self.configure_proxy()

		# Process input
		self.input = input
		if isinstance(self.input, list) and len(self.input) == 1:
			self.input = self.input[0]

		# Yield dicts if CLI supports JSON
		if self.output_return_type is dict or (self.json_flag is not None):
			self.output_return_type = dict

		# Print options
		self.print_timestamp = self.cmd_opts.pop('print_timestamp', False)
		self.print_item = self.cmd_opts.pop('print_item', False)
		self.print_line = self.cmd_opts.pop('print_line', False)
		self.print_item_count = self.cmd_opts.pop('print_item_count', False)
		self.print_cmd = self.cmd_opts.pop('print_cmd', False)
		self.print_progress = self.cmd_opts.pop('print_progress', True)
		self.print_cmd_prefix = self.cmd_opts.pop('print_cmd_prefix', False)

		# Output options
		self.output_raw = self.cmd_opts.pop('raw', False)
		self.output_fmt = self.cmd_opts.pop('format', False)
		self.output_table = self.cmd_opts.pop('table', False)
		self.output_orig = self.cmd_opts.pop('orig', False)
		self.output_color = self.cmd_opts.pop('color', False)
		self.output_quiet = self.cmd_opts.pop('quiet', False)
		_json = self.cmd_opts.pop('json', True) or self.output_table or self.output_raw

		# Library output
		self.raw_yield = self.cmd_opts.pop('raw_yield', False)

		# Determine if JSON output or not
		self.output_json = self.output_return_type == dict
		if self.print_timestamp and not _json:
			self.output_json = False

		# Hooks
		self.hooks = {name: [] for name in HOOKS}
		hooks = self.cmd_opts.pop('hooks', {})
		for key in self.hooks:
			instance_func = getattr(self, key, None)
			if instance_func:
				self.hooks[key].append(instance_func)
			self.hooks[key].extend(hooks.get(key, []))

		# Validators
		self.validators = {name: [] for name in VALIDATORS}
		validators = self.cmd_opts.pop('validators', {})
		for key in self.validators:
			instance_func = getattr(self, f'validate_{key}', None)
			if instance_func:
				self.validators[key].append(instance_func)
			self.validators[key].extend(validators.get(key, []))

		# Chunks
		self.chunk = self.cmd_opts.pop('chunk', None)
		self.chunk_count = self.cmd_opts.pop('chunk_count', None)
		self._set_print_prefix()

		# Abort if inputs are invalid
		self.input_valid = True
		if not self.run_validators('input', self.input):
			self.run_hooks('on_end')
			self.input_valid = False

		# Callback before building the command line
		self.run_hooks('on_init')

	def toDict(self):
		return {
			'name': self.name,
			'description': self.description,
			'targets': self.input,
			'run_opts': self.cmd_opts,
			'status': self.status,
			'progress': self.progress,
			'results_count': self.results_count,
			'output': self.output,
			'error': self.error,
			'context': self.context,
			'done': self.done
		}

	def run(self):
		return list(self.__iter__())

	def __iter__(self):
		if not self.input_valid:
			return

		for item in self.yielder():

			if isinstance(item, dict):
				item = self._process_item(item)
				if not item:
					continue
				self.results_count += 1
				yield item

			elif isinstance(item, str):
				if self.print_line and not self.output_quiet:
					self._print(item, out=sys.stderr, ignore_raw=True)

				if self.output_return_type is not dict:
					self.results.append(item)
					yield item

			if item:
				self.output += str(item) + '\n'

			self.run_hooks('on_iter')

		self._process_results()
		self.status = 'SUCCESS' if not self.error else 'FAILED'
		self.done = True
		self.progress = 100
		self.run_hooks('on_end')

	def _convert_item_schema(self, item):
		"""Convert dict item to a new structure using the class output schema.

		Args:
			item (dict): Item.

		Returns:
			dict: Item with new schema.
		"""
		# Load item using available output types and get the first matching
		# output type based on the schema
		new_item = None
		output_types = getattr(self, 'output_types', [])
		for klass in output_types:
			output_map = getattr(self, 'output_map', {})
			output_map = output_map.get(klass, {})
			try:
				new_item = klass.load(item, output_map)
				break  # found an item that fits
			except (TypeError, KeyError):  # can't load using class
				# logger.debug(f'Failed loading item with {klass}: {str(e)}. Continuing')
				continue

		# No output type was found, so make no conversion
		if not new_item:
			new_item = DotMap(item)
			new_item._type = 'unknown'

		# Add source to item
		new_item._source = self.name

		# Add context to item
		new_item._context = self.context

		# If progress item, update task progress
		if new_item._type == 'progress':
			self.progress = new_item.percent

		return new_item

	#-------#
	# Hooks #
	#-------#
	def run_hooks(self, hook_type, *args):
		# logger.debug(f'Running hooks of type {hook_type}')
		result = args[0] if len(args) > 0 else None
		for hook in self.hooks[hook_type]:
			# logger.debug(hook)
			result = hook(self, *args)
		return result

	#------------#
	# Validators #
	#------------#
	def run_validators(self, validator_type, *args):
		# logger.debug(f'Running validators of type {validator_type}')
		for validator in self.validators[validator_type]:
			# logger.debug(validator)
			if not validator(self, *args):
				if validator_type == 'input':
					self._print(f'{validator.__doc__}', color='bold red')
				return False
		return True

	def _print(self, data, color=None, out=sys.stderr, ignore_raw=False, ignore_log=False):
		"""Print function.

		Args:
			data (str or dict): Input data.
			color (str, Optional): Termcolor color.
			out (str, Optional): Output pipe (sys.stderr, sys.stdout, ...)
			ignore_raw (bool, Optional): Ignore raw mode.
			ignore_log (bool, Optional): Ignore log stamps.
		"""
		# Choose rich console
		_console = console_stdout if out == sys.stdout else console
		log_json = console.print_json
		log = console.log if self.print_timestamp else _console.print

		# Print a rich table
		if self.output_table and isinstance(data, list) and isinstance(data[0], (OutputType, DotMap, dict)):
			print_results_table(self.results)

		# Print a JSON item
		elif isinstance(data, (OutputType, DotMap, dict)):
			# If object has a 'toDict' method, use it
			if getattr(data, 'toDict', None):
				data = data.toDict()

			# JSON dumps data so that it's consumable by other commands
			data = json.dumps(data)

			# Add prefix to output
			data = f'{self.prefix:>15} {data}' if self.prefix and not self.print_item else data

			# We might want to parse results with e.g 'jq' so we need pure JSON line with no logging info clarifies the
			# user intent to use it for visualizing results.
			log_json(data) if self.output_color and self.print_item else _console.print(data, highlight=False)

		# Print a line
		else:
			# If orig mode (--orig) or raw mode (--raw), we might want to parse results with e.g pipe redirections, so
			# we need a pure line with no logging info.
			if ignore_log or (not ignore_raw and (self.output_orig or self.output_raw)):
				data = f'{self.prefix} {data}' if self.prefix and not self.print_item else data
				_console.print(data, highlight=False, style=color)
			else:
				# data = escape(data)
				# data = Text.from_ansi(data)
				if color:
					data = f'[{color}]{data}[/]'
				data = f'{self.prefix} {data}' if self.prefix else data
				try:
					log(data)
				except:  # noqa: E722
					print(data)

	def _set_print_prefix(self):
		self.prefix = ''
		if self.print_cmd_prefix:
			self.prefix = f'[bold gold3]({self.name})[/]'
		if self.chunk and self.chunk_count:
			self.prefix += f' [{self.chunk}/{self.chunk_count}]'

	def configure_proxy(self):
		"""Configure proxy. Start with global settings like 'proxychains' or 'random', or fallback to tool-specific
		proxy settings.

		TODO: Move this to a subclass of Command, or to a configurable attribute to pass to derived classes as it's not
		related to core functionality.
		"""
		opt_key_map = getattr(self, 'opt_key_map', {})
		proxy_opt = opt_key_map.get('proxy', False)
		support_proxychains = getattr(self, 'proxychains', True)
		proxychains_flavor = getattr(self, 'proxychains_flavor', 'proxychains')
		support_proxy = proxy_opt and proxy_opt != OPT_NOT_SUPPORTED
		if self.proxy == 'proxychains':
			if not support_proxychains:
				return
			self.cmd = f'{proxychains_flavor} {self.cmd}'
		elif self.proxy and support_proxy:
			if self.proxy == 'random':
				self.cmd_opts['proxy'] = FreeProxy(timeout=DEFAULT_PROXY_TIMEOUT, rand=True, anonym=True).get()
			else:  # tool-specific proxy settings
				self.cmd_opts['proxy'] = self.proxy

	def _get_results_count(self):
		count_map = {}
		for output_type in self.output_types:
			if output_type.__name__ == 'Progress':
				continue
			name = output_type.get_name()
			count = len([r for r in self.results if r._type == name])
			count_map[name] = count
		return count_map

	def _process_results(self):
		# TODO: this is only for logging timestamp to show up properly !!!
		if self.print_timestamp:
			sleep(1)

		# Log results count
		if self.print_item_count and self.output_json and not self.output_raw and not self.output_orig:
			count_map = self._get_results_count()
			if all(count == 0 for count in count_map.values()):
				self._print(':adhesive_bandage: Found 0 results.', color='bold red')
			else:
				results_str = ':pill: Found ' + ' and '.join([
					f'{count} {pluralize(name) if count > 1 or count == 0 else name}'
					for name, count in count_map.items()
				]) + '.'
				self._print(results_str, color='bold green')

		# Print table if in table mode
		if self.output_table and self.results and len(self.results) > 0:
			if isinstance(self.results[0], str):
				self._print('\n'.join(self.results))
			else:
				self._print(self.results, out=sys.stdout)

	def _process_item(self, item: dict):
		# Run item validators
		if not self.run_validators('item', item):
			return None

		# Run item hooks
		item = self.run_hooks('on_item_pre_convert', item)
		if not item:
			return None

		# Convert output dict to another schema
		if not self.output_orig:
			item = self._convert_item_schema(item)

			# Run item convert hooks
			item = self.run_hooks('on_item', item)
		else:
			item = DotMap(item)

		# Get item klass
		item_klass = item.__class__.__name__

		# Add item to result
		if not item_klass == 'Progress':
			self.results.append(item)

		# Item to print
		item_str = item

		# In raw mode, print principal key or output format field.
		if self.output_raw:
			item_str = self._rawify(item)

		# In raw yield mode, extract principal key from dict (default 'on' for library usage)
		if self.raw_yield:
			item = self._rawify(item)
			item_str = item

		# Print item to console or log
		if item_klass == 'Progress' and self.print_progress:
			self._print(str(item_str), out=sys.stderr, ignore_log=True, color='dim cyan')
			item = None

		elif self.print_item and self.output_json and not self.output_table:
			self._print(item_str, out=sys.stdout)

		# Return item
		return item

	def _rawify(self, item=None):
		if not item:
			return [
				self._rawify(item)
				for item in self.results
			]
		if self.output_raw:
			if self.output_fmt:
				item = self.output_fmt.format(**item)
			elif isinstance(item, OutputType):
				item = str(item)
		return item


class Command(TaskBase):
	"""Base class to execute an external command."""
	# Base cmd
	cmd = None

	# Meta options
	meta_opts = {}

	# Additional command options
	opts = {}

	# Option prefix char
	opt_prefix = '-'

	# Option key map to transform option names
	opt_key_map = {}

	# Option value map to transform option values
	opt_value_map = {}

	# Output map to transform JSON output keys
	output_map = {}

	# Run in shell if True (not recommended)
	shell = False

	# Current working directory
	cwd = None

	# Output encoding
	encoding = 'utf-8'

	# Environment variables
	env = {}

	# Flag to take the input
	input_flag = None

	# Input path (if a file is constructed)
	input_path = None

	# Input chunk size (default None)
	input_chunk_size = None

	# Flag to take a file as input
	file_flag = None

	# Flag to enable output JSON
	json_flag = None

	# Install command
	install_cmd = None

	# Serializer
	item_loader = JSONSerializer()

	# Ignore return code
	ignore_return_code = False

	# Return code
	return_code = -1

	# Error
	error = ''

	# Output
	output = ''

	def __init__(self, input=None, **cmd_opts):
		super().__init__(input, **cmd_opts)

		# Current working directory for cmd
		self.cwd = self.cmd_opts.pop('cwd', None)

		# No capturing of stdout / stderr.
		self.no_capture = self.cmd_opts.pop('no_capture', False)

		# Build command input
		self._build_cmd_input()

		# Build command
		self._build_cmd()

	def toDict(self):
		res = super().toDict()
		res.update({
			'cmd': self.cmd,
			'cwd': self.cwd,
			'return_code': self.return_code
		})
		return res

	@classmethod
	def delay(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secsy.celery import run_command

		# TODO: running chunked group .apply() in run_command doesn't work if this isn't set explicitely to False
		kwargs['sync'] = False
		results = kwargs.get('results', [])
		return run_command.delay(results, cls.__name__, *args, opts=kwargs)

	@classmethod
	def s(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secsy.celery import run_command
		return run_command.s(cls.__name__, *args, opts=kwargs)

	@classmethod
	def si(cls, results, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secsy.celery import run_command
		return run_command.si(results, cls.__name__, *args, opts=kwargs)

	@classmethod
	def poll(cls, result):
		# TODO: Move this to TaskBase
		from time import sleep

		while not result.ready():
			data = AsyncResult(result.id).info
			if DEBUG > 1 and isinstance(data, dict):
				print(data)
			sleep(1)
		return result.get()

	def get_opt_value(self, opt_name):
		return Command._get_opt_value(
			self.cmd_opts,
			opt_name,
			dict(self.opts, **self.meta_opts),
			opt_prefix=self.name)

	#---------------#
	# Class methods #
	#---------------#
	@classmethod
	def install(cls):
		"""Install command by running the content of cls.install_cmd."""
		console.log(f':pill: Installing {cls.__name__}...', style='bold yellow')
		if not cls.install_cmd:
			console.log(f'{cls.__name__} install is not supported yet. Please install it manually.', style='bold red')
			return
		ret = cls.run_command(
			cls.install_cmd,
			name=cls.__name__,
			print_timestamp=True,
			print_cmd=True,
			print_line=True,
			cls_attributes={'shell': True}
		)
		if ret.return_code != 0:
			console.log(f'Failed to install {cls.__name__}.', style='bold red')
		else:
			console.log(f'{cls.__name__} installed successfully !', style='bold green')
		return ret

	@classmethod
	def run_command(cls, cmd, name='helperClass', cls_attributes={}, **kwargs):
		"""Run adhoc command. Can be used without defining an inherited class to run a command, while still enjoying
		all the good stuff in this class.
		"""
		cmd_instance = type(name, (Command,), {'cmd': cmd})(**kwargs)
		for k, v in cls_attributes.items():
			setattr(cmd_instance, k, v)
		cmd_instance.print_line = True
		cmd_instance.run()
		return cmd_instance

	#----------#
	# Internal #
	#----------#
	def yielder(self):
		"""Run command and yields its output in real-time. Also saves the command line, return code and output to the
		database.

		Args:
			cmd (str): Command to run.
			cwd (str, Optional): Working directory to run from.
			shell (bool, Optional): Run command in a shell.
			history_file (str): History file path.
			mapper_func (Callable, Optional): Function to map output before yielding.
			encoding (str, Optional): Output encoding.
			ctx (dict, Optional): Scan context.

		Yields:
			str: Command stdout / stderr.
			dict: Parsed JSONLine object.
		"""
		# TODO: this is rawuely for logging timestamp to show up properly !!!
		if self.print_timestamp:
			sleep(1)

		# Callback before running command
		self.run_hooks('on_start')

		# Log cmd
		if self.print_cmd:
			if self.sync and self.description:
				self._print(f'\n:wrench: {self.description} ...', color='bold gold3', ignore_log=True)
			self._print(self.cmd, color='bold cyan', ignore_raw=True)

		# Prepare cmds
		command = self.cmd if self.shell else shlex.split(self.cmd)

		# Output and results
		self.output = ''
		self.return_code = 0
		self.killed = False
		self.results = []

		# Run the command using subprocess
		try:
			env = os.environ
			env.update(self.env)
			process = subprocess.Popen(
				command,
				stdout=sys.stdout if self.no_capture else subprocess.PIPE,
				stderr=sys.stderr if self.no_capture else subprocess.STDOUT,
				universal_newlines=True,
				shell=self.shell,
				env=env,
				cwd=self.cwd)

		except FileNotFoundError as e:
			if self.name in str(e):
				error = f'{self.name} not installed.'
				if self.install_cmd:
					error += f' Install it with `secsy utils install {self.name}`.'
			else:
				error = str(e)
			self.error = error
			self.return_code = 1
			if error:
				self._print(error, color='bold red')
			return

		try:
			# No capture mode, wait for command to finish and return
			if self.no_capture:
				self._wait_for_end(process)
				return

			# Process the output in real-time
			for line in iter(lambda: process.stdout.readline(), b''):
				if not line:
					break

				# Strip line
				line = line.strip()

				# Some commands output ANSI text, so we need to remove those ANSI chars
				if self.encoding == 'ansi':
					# ansi_regex = r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[K]?'
					# line = re.sub(ansi_regex, '', line.strip())
					ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
					line = ansi_escape.sub('', line)
					line = line.replace('\\x0d\\x0a', '\n')

				# Run on_line hooks
				line = self.run_hooks('on_line', line)

				# Run item_loader to try parsing as dict
				items = None
				if self.output_json:
					if callable(self.item_loader):
						items = self.item_loader(line)
					else:
						items = self.item_loader.run(line)

				# Print line if no items parsed
				if not items and not self.output_quiet:
					yield line

				# Turn results into list if not already a list
				elif not isinstance(items, list):
					items = [items]

				# Yield items
				if items:
					yield from items

		except KeyboardInterrupt:
			process.kill()
			self._print('Process was killed manually (CTRL+C / CTRL+X)', color='bold red')
			self.output = ''
			self.error = 'Process killed manually'
			self.killed = True

		# Retrieve the return code and output
		self._wait_for_end(process)

	def _wait_for_end(self, process):
		"""Wait for process to finish and process output and return code."""
		process.wait()
		self.return_code = process.returncode

		if self.no_capture:
			self.output = ''
		else:
			self.output = self.output.strip()
			process.stdout.close()

		if self.ignore_return_code:
			self.return_code = 0

		if self.return_code != 0 and not self.killed:
			self.error = f'Command failed with return code {self.return_code}.'
			self._print(self.error, color='bold red')

	@staticmethod
	def _process_opts(
			opts,
			opts_conf,
			opt_key_map={},
			opt_value_map={},
			opt_prefix='-',
			command_name=None):
		"""Process a dict of options using a config, option key map / value map
		and option character like '-' or '--'.

		Args:
			opts (dict): Command options as input on the CLI.
			opts_conf (dict): Options config (Click options definition).
		"""
		opts_str = ''
		for opt_name, opt_conf in opts_conf.items():

			# Get opt value
			default_val = opt_conf.get('default')
			opt_val = Command._get_opt_value(
				opts,
				opt_name,
				opts_conf,
				opt_prefix=command_name,
				default=default_val)

			# Skip option if value is falsy
			if opt_val in [None, False, []]:
				# logger.debug(f'Option {opt_name} was passed but is falsy. Skipping.')
				continue

			# Convert opt value to expected command opt value
			mapped_opt_val = opt_value_map.get(opt_name)
			if callable(mapped_opt_val):
				opt_val = mapped_opt_val(opt_val)
			elif mapped_opt_val:
				opt_val = mapped_opt_val

			# Convert opt name to expected command opt name
			mapped_opt_name = opt_key_map.get(opt_name)
			if mapped_opt_name == OPT_NOT_SUPPORTED:
				# logger.debug(f'Option {opt_name} was passed but is unsupported. Skipping.')
				continue
			elif mapped_opt_name is not None:
				opt_name = mapped_opt_name

			# Avoid shell injections and detect opt prefix
			opt_name = str(opt_name).split(' ')[0]  # avoid cmd injection

			# Replace '_' with '-'
			opt_name = opt_name.replace('_', '-')

			# Add opt prefix if not already there
			if len(opt_name) > 0 and opt_name[0] not in ['-', '--']:
				opt_name = f'{opt_prefix}{opt_name}'

			# Append opt name + opt value to option string.
			# Note: does not append opt value if value is True (flag)
			opts_str += f' {opt_name}'
			if opt_val is not True:
				opt_val = shlex.quote(str(opt_val))
				opts_str += f' {opt_val}'

		return opts_str.strip()

	@staticmethod
	def _get_opt_value(opts, opt_name, opts_conf={}, opt_prefix='', default=None):
		aliases = [
			opts.get(f'{opt_prefix}_{opt_name}'),
			opts.get(f'{opt_prefix}.{opt_name}'),
			opts.get(opt_name),
		]
		alias = [conf.get('short') for _, conf in opts_conf.items() if conf.get('short') in opts]
		if alias:
			aliases.append(opts.get(alias[0]))
		if OPT_NOT_SUPPORTED in aliases:
			return None
		return next((v for v in aliases if v is not None), default)

	def _build_cmd(self):
		"""Build command string."""

		# Add JSON flag to cmd
		if self.output_json and self.json_flag:
			self.cmd += f' {self.json_flag}'

		# Add options to cmd
		opts_str = Command._process_opts(
			self.cmd_opts,
			self.opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.name)
		if opts_str:
			self.cmd += f' {opts_str}'

		# Add meta options to cmd
		meta_opts_str = Command._process_opts(
			self.cmd_opts,
			self.meta_opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.name)
		if meta_opts_str:
			self.cmd += f' {meta_opts_str}'

	def _build_cmd_input(self):
		"""Many commands take as input a string or a list. This function facilitate this based on wheter we pass a
		string or a list to the cmd.
		"""
		cmd = self.cmd
		input = self.input

		# If input is None, return the previous command
		if not input:
			return

		# If input is a list but has one element, use the standard string input
		if isinstance(input, list) and len(input) == 1:
			input = input[0]

		# If input is a list and the tool does not supports file input flag, use cat-piped input.
		# Otherwise pass the file path to the tool.
		if isinstance(input, list):
			timestr = get_file_timestamp()
			cmd_name = cmd.split(' ')[0].split('/')[-1]
			fpath = f'{TEMP_FOLDER}/{cmd_name}_{timestr}.txt'

			# Write the input to a file
			with open(fpath, 'w') as f:
				f.write('\n'.join(input))

			if self.file_flag == OPT_PIPE_INPUT:
				cmd = f'cat {fpath} | {cmd}'
			else:
				cmd += f' {self.file_flag} {fpath}'

			self.input_path = fpath

		# If input is a string but the tool does not support an input flag, use echo-piped input.
		# If the tool's input flag is set to None, assume it is a positional argument at the end of the command.
		# Otherwise use the input flag to pass the input.
		else:
			input = shlex.quote(input)
			if self.input_flag == OPT_PIPE_INPUT:
				cmd = f'echo {input} | {cmd}'
			elif not self.input_flag:
				cmd += f' {input}'
			else:
				cmd += f' {self.input_flag} {input}'

		self.cmd = cmd
		self.shell = ' | ' in self.cmd
		self.input = input

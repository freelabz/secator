# import celery
import json
import logging
import re
import shlex
import subprocess
from datetime import datetime
from time import sleep

from rich.markup import escape

from secsy.definitions import *
from secsy.rich import build_table, console
from secsy.serializers import JSONSerializer
from secsy.utils import pluralize

logger = logging.getLogger(__name__)

HOOKS = [
	'on_init',
	'on_start',
	'on_end',
	'on_item',
	'on_item_converted',
	'on_line',
	'on_end',
	'on_error'
]

VALIDATORS = [
	'input',
	'item'
]


class CommandRunner:
	# Base cmd
	cmd = None

	# Meta options
	meta_opts = {}

	# Additional tools options
	opts = {}

	# Option key map to transform option names
	opt_key_map = {}

	# Option character
	opt_prefix = '-'

	# Option value map to transform option values
	opt_value_map = {}

	# Output map to transform JSON output keys
	output_map = {}

	# Output format in 'raw' mode
	output_field = None

	# Output schema
	output_schema = []

	# Output type
	output_type = None

	# Run in shell if True (not recommended)
	shell = False

	# Current working directory
	cwd = None

	# Output encoding
	encoding = 'utf-8'

	# Flag to take the input
	input_flag = None

	# Input field (mostly for tests and CLI)
	input_type = None

	# Flag to take a file as input
	file_flag = None

	# Flag to enable output JSON
	json_flag = None

	# Install command
	install_cmd = None

	# Dict return
	output_return_type = dict

	# Table fields
	output_table_fields = output_schema
	output_table_sort_fields = ()

	# Serializer
	item_loader = JSONSerializer()

	# Command output formatting options
	_raw_output = False
	_orig_output = False
	_table_output = False
	_json_output = False
	_print_item = True
	_print_item_count = True
	_print_cmd_prefix = False
	_stop_on_first_match = False

	# Hooks, validators, formatter
	hooks = {}
	validators = {}

	@property
	def name(self):
		return f'{self.__class__.__name__}'

	def __init__(self, input=None, **cmd_opts):
		self.input = input
		self.cmd_opts = cmd_opts.copy()
		self.results = []

		# Yield dicts if CLI supports JSON
		if self.output_return_type is dict or (self.json_flag is not None):
			self.output_return_type = dict

		# Table output
		self._table_output = self.cmd_opts.pop('table', False)

		# Raw output
		self._raw_output = self.cmd_opts.pop('raw', False)

		# No convert to unified schema
		self._orig_output = self.cmd_opts.pop('orig', False)

		# JSON Output
		_json = self.cmd_opts.pop('json', False)

		# CLI mode: use nicer prints and colors (no logging statements)
		self._print_timestamp = self.cmd_opts.pop('print_timestamp', False)

		# Print JSON output
		self._print_item = self.cmd_opts.pop('print_item', False)

		# Print line output
		self._print_line = self.cmd_opts.pop('print_line', False)

		# Print results count
		self._print_item_count = self.cmd_opts.pop('print_item_count', False)

		# Print cmd name
		self._print_cmd = self.cmd_opts.pop('print_cmd', False)

		# Print task name before line output (useful for multiprocessed envs)
		self._print_task_name_prefix = self.cmd_opts.pop('print_task_name_prefix', False)

		# Print cmd prefix before each line (used in async mode)
		self._print_cmd_prefix = self.cmd_opts.pop('print_cmd_prefix', False)

		# Determine if JSON output or not
		self._json_output = self.output_return_type == dict
		if self._print_timestamp and not _json:
			self._json_output = False

		# Output formatting
		self.color = self.cmd_opts.pop('color', False)
		self.quiet = self.cmd_opts.pop('quiet', False)
		self.output_table_fields = self.cmd_opts.pop(
			'table_fields',
			self.output_table_fields)

		# Hooks
		self._hooks = {name: [] for name in HOOKS}
		hooks = self.cmd_opts.pop('hooks', {})
		for key in self._hooks:
			instance_func = getattr(self, key, None)
			if instance_func:
				self._hooks[key].append(instance_func)
			self._hooks[key].extend(hooks.get(key, []))
			self._hooks[key].extend(self.hooks.get(key, []))

		# Validators
		self._validators = {name: [] for name in VALIDATORS}
		validators = self.cmd_opts.pop('validators', {})
		for key in self._validators:
			instance_func = getattr(self, f'validate_{key}', None)
			if instance_func:
				self._validators[key].append(instance_func)
			self._validators[key].extend(validators.get(key, []))
			self._validators[key].extend(self.validators.get(key, []))

		# Output table sort fields
		if not self.output_table_sort_fields and self.output_field:
			self.output_table_sort_fields = (self.output_field,)

		# Current working directory for cmd
		self.cwd = self.cmd_opts.pop('cwd', None)

		# Callback before building the command line
		self.run_hooks('on_init')

		# Build command input
		self._build_cmd_input()

		# Build command
		self._build_cmd()

	def __iter__(self):
		yield from self._run_command()
		self._process_results()

	def run(self):
		return list(self.__iter__())

	@classmethod
	def delay(cls, *args, **kwargs):
		from secsy.celery import run_command
		return run_command.delay(cls.__name__, *args, opts=kwargs)

	@classmethod
	def s(cls, *args, **kwargs):
		from secsy.celery import run_command
		return run_command.s(cls.__name__, *args, opts=kwargs)

	@classmethod
	def si(cls, *args, **kwargs):
		from secsy.celery import run_command
		return run_command.si(cls.__name__, *args, opts=kwargs)

	def first(self):
		try:
			self._stop_on_first_match = True
			return self.run()[0]
		except IndexError:
			return None

	def get_opt_value(self, opt_name):
		return CommandRunner._get_opt_value(
			self.cmd_opts,
			opt_name,
			opt_prefix=self.name)

	#-------#
	# Hooks #
	#-------#
	def run_hooks(self, hook_type, **kwargs):
		result = next((val for val in kwargs.values() if val is not None), None)
		logger.debug(f'Running hooks of type {hook_type}')
		logger.debug(self._hooks[hook_type])
		for hook in self._hooks[hook_type]:
			result = hook(self, **kwargs)
		return result

	#------------#
	# Validators #
	#------------#
	def run_validators(self, validator_type, input=None):
		logger.debug(f'Running validators of type {validator_type}')
		logger.debug(self._validators[validator_type])
		type_map = {
			'input': self.input,
		}
		for validator in self._validators[validator_type]:
			if not validator(self, input or self.input):
				if validator_type == 'input':
					self._print(validator.__doc__, color='bold red')
				return False
		return True

	#---------------#
	# Class methods #
	#---------------#
	@classmethod
	def install(cls):
		"""Install command by running the content of cls.install_cmd."""
		if not cls.install_cmd:
			logger.warning(f'Installation of "{cls.__name__}" is not supported yet. Please install it manually.')
			return
		return cls.run_command(cls.install_cmd, print_timestamp=True)

	@classmethod
	def run_command(cls, cmd, **kwargs):
		"""Run adhoc command. Can be used without defining an inherited class 
		to run a command, while still enjoying all the good stuff in this class.
		"""
		helper_cls = type('helperClass', (CommandRunner,), {'cmd': cmd})(**kwargs)
		helper_cls._print_line = True
		helper_cls.run()
		return helper_cls

	#----------#
	# Internal #
	#----------#
	def _run_command(self):
		"""Run command and yields its output in real-time. Also saves the command 
		line, return code and output to the database.

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
		# TODO: this is uniquely for logging timestamp to show up properly !!!
		if self._print_timestamp:
			sleep(1)

		# Callback before running command
		self.run_hooks('on_start')

		# Log cmd
		if self._print_cmd:
			self._print(self.cmd, color='bold cyan', prefix=False)

		# Prepare cmds
		command = self.cmd if self.shell else shlex.split(self.cmd)

		# Output and results
		self.output = ''
		self.return_code = 0
		killed = False
		self.results = []

		# Abort if inputs not validated
		if not self.run_validators('input'):
			self._print('Input validation failed. Skipping.', color='bold red')
			self.run_hooks('on_end')
			return

		# Run the command using subprocess
		try:
			process = subprocess.Popen(
				command,
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT,
				universal_newlines=True,
				shell=self.shell,
				cwd=self.cwd)
		except FileNotFoundError:
			base_cmd = self.cmd.split(' ')[0]
			logger.error(f'{base_cmd} not found. Check if it is installed.')
			self.return_code = 1
			return

		# Process the output
		try:
			for line in iter(lambda: process.stdout.readline(), b''):
				if not line:
					break

				# Strip line
				line = line.strip()

				# Some tools output ANSI text, so we need to remove those ANSI chars
				if self.encoding == 'ansi':
					ansi_regex = r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?'
					line = re.sub(ansi_regex, '', line.strip())

				# Run on_line hooks
				line = self.run_hooks('on_line', line=line)

				# Run item_loader to try parsing as dict
				if callable(self.item_loader):
					item = self.item_loader(line)
				else:
					item = self.item_loader.run(line)

				# Process dict item or line
				if item:
					item = self._process_item(item)
					if not item:
						continue
					yield item
				else:
					if self._print_line and not (self.quiet and self._json_output):
						self._print(line)
					if not self.output_return_type is dict:
						self.results.append(line)
						yield line

				# Stop on first match
				if self._stop_on_first_match and len(self.results) == 1:
					process.kill()
					killed = True
					break

				# Add the log line to the output
				self.output += line + '\n'

		except KeyboardInterrupt:
			process.kill()
			logger.warning('Process was killed manually (CTRL+C / CTRL+X)')
			self.output = ''

		# Retrieve the return code and output
		process.wait()
		process.stdout.close()
		self.return_code = process.returncode
		self.output = self.output.strip()
		if self.return_code != 0 and not killed:
			cmd_name = self.cmd.split(' ')[0]
			logger.error(f'Command {cmd_name} failed with return code {self.return_code}. Output: {self.output}')

		# Callback after running cmd
		self.run_hooks('on_end')

	def _process_results(self):
		# TODO: this is uniquely for logging timestamp to show up properly !!!
		if self._print_timestamp:
			sleep(1)

		# Log results count
		if self._print_item_count and self._json_output and not self._raw_output:
			count = len(self.results)
			item_name = pluralize(self.output_type) if count > 1 else self.output_type
			if count > 0:
				self._print(f':pill: Found {count} {item_name} !', color='bold green')
			else:
				self._print(f':adhesive_bandage: Found 0 {item_name}.', color='bold red')
			console.print()

		# Print table if in table mode
		if self._table_output and self.results:
			fmt_table = getattr(self, 'on_table', None)
			data = self.results
			if callable(fmt_table):
				data = fmt_table(self.results)
			self._print(data)

	def _process_item(self, item: dict):
		# Run item validators
		if not self.run_validators('item', item):
			return None

		# Run item hooks
		item = self.run_hooks('on_item', item=item)
		if not item:
			return None

		# Convert output dict to another schema
		if not self._orig_output:
			item = self._convert_item_schema(item)

			# Run item convert hooks
			item = self.run_hooks('on_item_converted', item=item)

		# Add item to result
		self.results.append(item)

		# In raw output mode, extract principal key from dict.
		if self._raw_output and self.output_field is not None:
			if callable(self.output_field):
				item = self.output_field(item)
			else:
				item = item[self.output_field]

		# Print item to console or log, except in table output where we 
		# want to wait for all the results to come through before printing.
		if self._json_output and self._print_item and not self._table_output:
			self._print(item)

		# Return item
		return item


	@staticmethod
	def _process_opts(
			opts,
			opts_conf,
			opt_keys={},
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
			opt_val = CommandRunner._get_opt_value(
				opts,
				opt_name,
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
			mapped_opt_name = opt_keys.get(opt_name)
			if mapped_opt_name == OPT_NOT_SUPPORTED:
				logger.debug(f'Option {opt_name} was passed but is unsupported. Skipping.')
				continue
			elif mapped_opt_name is not None:
				opt_name = mapped_opt_name

			# Avoid shell injections and detect opt prefix
			opt_name = str(opt_name).split(' ')[0] # avoid cmd injection

			# Replace '_' with '-'
			opt_name = opt_name.replace('_', '-')

			# Add opt prefix if not already there
			if len(opt_name) > 0 and opt_name[0] not in ['-', '--']:
				opt_name = f'{opt_prefix}{opt_name}'

			# Append opt name + opt value to option string
			# Note: does not append opt value if value is True (flag)
			opts_str += f' {opt_name}'
			if opt_val is not True:
				opt_val = shlex.quote(str(opt_val))
				opts_str += f' {opt_val}'

		return opts_str.strip()

	@staticmethod
	def _get_opt_value(opts, opt_name, opt_prefix='', default=None):
		vals = [opts.get(f'{opt_prefix}_{opt_name}'), opts.get(opt_name)]
		if OPT_NOT_SUPPORTED in vals:
			return None
		return next((v for v in vals if v is not None), default)

	def _build_cmd(self):
		"""Build command string."""
		# Add JSON flag to cmd
		if self._json_output and self.json_flag:
			self.cmd += f' {self.json_flag}'

		# Add options to cmd
		opts_str = CommandRunner._process_opts(
			self.cmd_opts,
			self.opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.name)
		if opts_str:
			self.cmd += f' {opts_str}'

		# Add meta options to cmd
		meta_opts_str = CommandRunner._process_opts(
			self.cmd_opts,
			self.meta_opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.name)
		if meta_opts_str:
			self.cmd += f' {meta_opts_str}'

	def _build_cmd_input(self):
		"""Many commands take as input a string or a list. This function 
		facilitate this based on wheter we pass a string or a list to the cmd.
		"""
		cmd = self.cmd
		input = self.input

		# If input is None, return the previous command
		if not input:
			return

		# If input is a list but has one element, use the standard string input
		if isinstance(input, list) and len(input) == 1:
			input = input[0]

		# If input is a list and the tool does not supports file input flag, use 
		# cat-piped input.
		# Otherwise pass the file path to the tool.
		if isinstance(input, list):
			timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
			cmd_name = cmd.split(' ')[0].split('/')[-1]
			fname = f'{TEMP_FOLDER}/{cmd_name}_{timestr}.txt'

			# Write the input to a file
			with open(fname, 'w') as f:
				f.write('\n'.join(input))

			if self.file_flag == OPT_PIPE_INPUT:
				cmd = f'cat {fname} | {cmd}'
			else:
				cmd += f' {self.file_flag} {fname}'

		# If input is a string but the tool does not support an input flag, use
		# echo-piped input.
		# If the tool's input flag is set to None, assume it is a positional
		# argument at the end of the command.
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

	def _convert_item_schema(self, item):
		"""Convert dict item to a new structure using the class output schema.

		Args:
			item (dict): Item.

		Returns:
			dict: Item with new schema.
		"""
		new_item = {}
		if not self.output_schema:
			logger.debug(
				'Skipping converting schema as no output_schema is defined.')
			return item
		for key in self.output_schema:
			if key in self.output_map:
				mapped_key = self.output_map[key]
				if callable(mapped_key):
					mapped_val = mapped_key(item)
				else:
					mapped_val = item.get(mapped_key)
				new_item[key] = mapped_val
			elif key in item:
				new_item[key] = item[key]
			else:
				new_item[key] = None

		# Add source to item
		new_item['_source'] = self.name

		# Add output type to item if any
		if self.output_type:
			new_item['_type'] = self.output_type

		return new_item

	def _print(self, data, color=None, prefix=True):
		"""Print function.

		Args:
			data (str or dict): Input data.
			color (str, Optional): Termcolor color.
			prefix (bool, Optional): Add task name prefix before output.
		"""
		# Print a rich table
		if self._table_output and isinstance(data, list) and isinstance(data[0], dict):
			data = build_table(
				data,
				self.output_table_fields,
				sort_by=self.output_table_sort_fields)
			console.log(data)
			return

		# Print a JSON item
		elif isinstance(data, dict):

			# We might want to parse results with e.g 'jq' so we need pure JSON
			# line with no logging info, unless --color is passed in print_timestamp
			# which clarifies the user intent to use it for visualizing results.
			if self.color and self._print_item:
				console.print_json(json.dumps(data))
			else:
				print(json.dumps(data))

		# Print a line item
		elif isinstance(data, str):

			add_prefix = prefix and self._print_task_name_prefix
			if add_prefix:
				data = f'({self.name}) {data}'

			# If raw mode (--raw), we might want to parse results with e.g 
			# pipe redirections, so we need a pure line with no logging info
			if self._raw_output:
				print(data)
			else:
				if color:
					data = f'[{color}]{escape(data)}[/]'
				if self._print_timestamp:
					console.log(data)
				else:
					console.print(data)
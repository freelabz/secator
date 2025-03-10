import copy
import getpass
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import uuid

from time import time

import psutil
from fp.fp import FreeProxy

from secator.definitions import OPT_NOT_SUPPORTED, OPT_PIPE_INPUT
from secator.config import CONFIG
from secator.output_types import Info, Warning, Error, Target, Stat
from secator.runners import Runner
from secator.template import TemplateLoader
from secator.utils import debug, rich_escape as _s


logger = logging.getLogger(__name__)


class Command(Runner):
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

	# Flag to take the input
	input_flag = None

	# Input path (if a file is constructed)
	input_path = None

	# Input chunk size
	input_chunk_size = CONFIG.runners.input_chunk_size

	# Input required
	input_required = True

	# Flag to take a file as input
	file_flag = None

	# Flag to enable output JSON
	json_flag = None

	# Flag to show version
	version_flag = None

	# Install
	install_pre = None
	install_post = None
	install_cmd = None
	install_github_handle = None

	# Serializer
	item_loader = None
	item_loaders = []

	# Hooks
	hooks = [
		'on_cmd',
		'on_cmd_done',
		'on_line'
	]

	# Ignore return code
	ignore_return_code = False

	# Return code
	return_code = -1

	# Output
	output = ''

	# Proxy options
	proxychains = False
	proxy_socks5 = False
	proxy_http = False

	# Profile
	profile = 'io'

	def __init__(self, inputs=[], **run_opts):

		# Build runnerconfig on-the-fly
		config = TemplateLoader(input={
			'name': self.__class__.__name__,
			'type': 'task',
			'description': run_opts.get('description', None)
		})

		# Extract run opts
		hooks = run_opts.pop('hooks', {})
		caller = run_opts.get('caller', None)
		results = run_opts.pop('results', [])
		context = run_opts.pop('context', {})
		self.skip_if_no_inputs = run_opts.pop('skip_if_no_inputs', False)

		# Prepare validators
		input_validators = []
		if not self.skip_if_no_inputs:
			input_validators.append(self._validate_input_nonempty)
		if not caller:
			input_validators.append(self._validate_chunked_input)
		validators = {'validate_input': input_validators}

		# Call super().__init__
		super().__init__(
			config=config,
			inputs=inputs,
			results=results,
			run_opts=run_opts,
			hooks=hooks,
			validators=validators,
			context=context)

		# Cmd name
		self.cmd_name = self.__class__.cmd.split(' ')[0]

		# Inputs path
		self.inputs_path = None

		# Current working directory for cmd
		self.cwd = self.run_opts.get('cwd', None)

		# Print cmd
		self.print_cmd = self.run_opts.get('print_cmd', False)

		# Stat update
		self.last_updated_stat = None

		# Process
		self.process = None

		# Proxy config (global)
		self.proxy = self.run_opts.pop('proxy', False)
		self.configure_proxy()

		# Build command input
		self._build_cmd_input()

		# Build command
		self._build_cmd()

		# Run on_cmd hook
		self.run_hooks('on_cmd')

		# Build item loaders
		instance_func = getattr(self, 'item_loader', None)
		item_loaders = self.item_loaders.copy()
		if instance_func:
			item_loaders.append(instance_func)
		self.item_loaders = item_loaders

	def toDict(self):
		res = super().toDict()
		res.update({
			'cmd': self.cmd,
			'cwd': self.cwd,
			'return_code': self.return_code
		})
		return res

	def needs_chunking(self, sync):
		many_targets = len(self.inputs) > 1
		targets_over_chunk_size = self.input_chunk_size and len(self.inputs) > self.input_chunk_size
		has_file_flag = self.file_flag is not None
		chunk_it = (sync and many_targets and not has_file_flag) or (not sync and many_targets and targets_over_chunk_size)
		return chunk_it

	@classmethod
	def delay(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		results = kwargs.get('results', [])
		kwargs['sync'] = False
		name = cls.__name__
		return run_command.apply_async(args=[results, name] + list(args), kwargs={'opts': kwargs}, queue=cls.profile)

	@classmethod
	def s(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		return run_command.s(cls.__name__, *args, opts=kwargs).set(queue=cls.profile)

	@classmethod
	def si(cls, *args, results=[], **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		return run_command.si(results, cls.__name__, *args, opts=kwargs).set(queue=cls.profile)

	def get_opt_value(self, opt_name):
		return Command._get_opt_value(
			self.run_opts,
			opt_name,
			dict(self.opts, **self.meta_opts),
			opt_prefix=self.config.name)

	@classmethod
	def get_supported_opts(cls):
		def convert(d):
			for k, v in d.items():
				if hasattr(v, '__name__') and v.__name__ in ['str', 'int', 'float']:
					d[k] = v.__name__
			return d

		cls_opts = copy.deepcopy(cls.opts)
		opts = {k: convert(v) for k, v in cls_opts.items()}
		for k, v in opts.items():
			v['meta'] = cls.__name__
			v['supported'] = True

		cls_meta_opts = copy.deepcopy(cls.meta_opts)
		meta_opts = {k: convert(v) for k, v in cls_meta_opts.items() if cls.opt_key_map.get(k) is not OPT_NOT_SUPPORTED}
		for k, v in meta_opts.items():
			v['meta'] = 'meta'
			if cls.opt_key_map.get(k) is OPT_NOT_SUPPORTED:
				v['supported'] = False
			else:
				v['supported'] = True
		opts = dict(opts)
		opts.update(meta_opts)
		return opts

	#---------------#
	# Class methods #
	#---------------#

	@classmethod
	def execute(cls, cmd, name=None, cls_attributes={}, run=True, **kwargs):
		"""Execute an ad-hoc command.

		Can be used without defining an inherited class to run a command, while still enjoying all the good stuff in
		this class.

		Args:
			cls (object): Class.
			cmd (str): Command.
			name (str): Printed name.
			cls_attributes (dict): Class attributes.
			kwargs (dict): Options.

		Returns:
			secator.runners.Command: instance of the Command.
		"""
		name = name or cmd.split(' ')[0]
		kwargs['print_cmd'] = not kwargs.get('quiet', False)
		kwargs['print_line'] = True
		kwargs['no_process'] = kwargs.get('no_process', True)
		cmd_instance = type(name, (Command,), {'cmd': cmd, 'input_required': False})(**kwargs)
		for k, v in cls_attributes.items():
			setattr(cmd_instance, k, v)
		if run:
			cmd_instance.run()
		return cmd_instance

	def configure_proxy(self):
		"""Configure proxy. Start with global settings like 'proxychains' or 'random', or fallback to tool-specific
		proxy settings.

		TODO: Move this to a subclass of Command, or to a configurable attribute to pass to derived classes as it's not
		related to core functionality.
		"""
		opt_key_map = self.opt_key_map
		proxy_opt = opt_key_map.get('proxy', False)
		support_proxy_opt = proxy_opt and proxy_opt != OPT_NOT_SUPPORTED
		proxychains_flavor = getattr(self, 'proxychains_flavor', CONFIG.http.proxychains_command)
		proxy = False

		if self.proxy in ['auto', 'proxychains'] and self.proxychains:
			self.cmd = f'{proxychains_flavor} {self.cmd}'
			proxy = 'proxychains'

		elif self.proxy and support_proxy_opt:
			if self.proxy in ['auto', 'socks5'] and self.proxy_socks5 and CONFIG.http.socks5_proxy:
				proxy = CONFIG.http.socks5_proxy
			elif self.proxy in ['auto', 'http'] and self.proxy_http and CONFIG.http.http_proxy:
				proxy = CONFIG.http.http_proxy
			elif self.proxy == 'random' and self.proxy_http:
				proxy = FreeProxy(timeout=CONFIG.http.freeproxy_timeout, rand=True, anonym=True).get()
			elif self.proxy.startswith(('http://', 'socks5://')):
				proxy = self.proxy

		if proxy != 'proxychains':
			self.run_opts['proxy'] = proxy

		if proxy != 'proxychains' and self.proxy and not proxy:
			self._print(
				f'[bold red]Ignoring proxy "{self.proxy}" for {self.cmd_name} (not supported).[/]', rich=True)

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
			dict: Serialized object.
		"""
		try:

			# Abort if it has children tasks
			if self.has_children:
				return

			# Print task description
			self.print_description()

			# Abort if no inputs
			if len(self.inputs) == 0 and self.skip_if_no_inputs:
				yield Warning(message=f'{self.unique_name} skipped (no inputs)', _source=self.unique_name, _uuid=str(uuid.uuid4()))
				return

			# Yield targets
			for input in self.inputs:
				yield Target(name=input, _source=self.unique_name, _uuid=str(uuid.uuid4()))

			# Check for sudo requirements and prepare the password if needed
			sudo_password, error = self._prompt_sudo(self.cmd)
			if error:
				yield Error(
					message=error,
					_source=self.unique_name,
					_uuid=str(uuid.uuid4())
				)
				return

			# Prepare cmds
			command = self.cmd if self.shell else shlex.split(self.cmd)

			# Check command is installed and auto-install
			if not self.no_process and not self.is_installed():
				if CONFIG.security.auto_install_commands:
					from secator.installer import ToolInstaller
					yield Info(
						message=f'Command {self.name} is missing but auto-installing since security.autoinstall_commands is set',  # noqa: E501
						_source=self.unique_name,
						_uuid=str(uuid.uuid4())
					)
					status = ToolInstaller.install(self.__class__)
					if not status.is_ok():
						yield Error(
							message=f'Failed installing {self.cmd_name}',
							_source=self.unique_name,
							_uuid=str(uuid.uuid4())
						)
						return

			# Output and results
			self.return_code = 0
			self.killed = False

			# Run the command using subprocess
			env = os.environ
			self.process = subprocess.Popen(
				command,
				stdin=subprocess.PIPE if sudo_password else None,
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT,
				universal_newlines=True,
				shell=self.shell,
				env=env,
				cwd=self.cwd)
			self.print_command()

			# If sudo password is provided, send it to stdin
			if sudo_password:
				self.process.stdin.write(f"{sudo_password}\n")
				self.process.stdin.flush()

			# Process the output in real-time
			for line in iter(lambda: self.process.stdout.readline(), b''):
				# sleep(0)  # for async to give up control
				if not line:
					break
				yield from self.process_line(line)

			# Run hooks after cmd has completed successfully
			result = self.run_hooks('on_cmd_done')
			if result:
				yield from result

		except FileNotFoundError as e:
			yield from self.handle_file_not_found(e)

		except BaseException as e:
			self.debug(f'{self.unique_name}: {type(e).__name__}.', sub='error')
			self.stop_process()
			yield Error.from_exception(e, _source=self.unique_name, _uuid=str(uuid.uuid4()))

		finally:
			yield from self._wait_for_end()

	def is_installed(self):
		"""Check if a command is installed by using `which`.

		Args:
			command (str): The command to check.

		Returns:
			bool: True if the command is installed, False otherwise.
		"""
		result = subprocess.Popen(["which", self.cmd_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		result.communicate()
		return result.returncode == 0

	def process_line(self, line):
		"""Process a single line of output emitted on stdout / stderr and yield results."""

		# Strip line endings
		line = line.rstrip()

		# Some commands output ANSI text, so we need to remove those ANSI chars
		if self.encoding == 'ansi':
			ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
			line = ansi_escape.sub('', line)
			line = line.replace('\\x0d\\x0a', '\n')

		# Run on_line hooks
		line = self.run_hooks('on_line', line)
		if line is None:
			return

		# Run item_loader to try parsing as dict
		item_count = 0
		for item in self.run_item_loaders(line):
			yield item
			item_count += 1

		# Yield line if no items were yielded
		if item_count == 0:
			yield line

		# Skip rest of iteration (no process mode)
		if self.no_process:
			return

		# Yield command stats (CPU, memory, conns ...)
		# TODO: enable stats support with timer
		if self.last_updated_stat and (time() - self.last_updated_stat) < CONFIG.runners.stat_update_frequency:
			return

		yield from self.stats()
		self.last_updated_stat = time()

	def print_description(self):
		"""Print description"""
		if self.sync and not self.has_children:
			if self.caller and self.description:
				self._print(f'\n[bold gold3]:wrench: {self.description} [dim cyan]({self.config.name})[/][/] ...', rich=True)

	def print_command(self):
		"""Print command."""
		if self.print_cmd:
			cmd_str = _s(self.cmd)
			if self.sync and self.chunk and self.chunk_count:
				cmd_str += f' [dim gray11]({self.chunk}/{self.chunk_count})[/]'
			self._print(cmd_str, color='bold cyan', rich=True)
		self.debug('Command', obj={'cmd': self.cmd}, sub='init')

	def handle_file_not_found(self, exc):
		"""Handle case where binary is not found.

		Args:
			exc (FileNotFoundError): the exception.

		Yields:
			secator.output_types.Error: the error.
		"""
		self.return_code = 127
		if self.config.name in str(exc):
			message = 'Executable not found.'
			if self.install_cmd:
				message += f' Install it with "secator install tools {self.config.name}".'
			error = Error(message=message)
		else:
			error = Error.from_exception(exc)
		error._source = self.unique_name
		error._uuid = str(uuid.uuid4())
		yield error

	def stop_process(self):
		"""Sends SIGINT to running process, if any."""
		if not self.process:
			return
		self.debug(f'Sending SIGINT to process {self.process.pid}.', sub='error')
		self.process.send_signal(signal.SIGINT)

	def stats(self):
		"""Gather stats about the current running process, if any."""
		if not self.process or not self.process.pid:
			return
		proc = psutil.Process(self.process.pid)
		stats = Command.get_process_info(proc, children=True)
		for info in stats:
			name = info['name']
			pid = info['pid']
			cpu_percent = info['cpu_percent']
			mem_percent = info['memory_percent']
			net_conns = info.get('net_connections') or []
			extra_data = {k: v for k, v in info.items() if k not in ['cpu_percent', 'memory_percent', 'net_connections']}
			yield Stat(
				name=name,
				pid=pid,
				cpu=cpu_percent,
				memory=mem_percent,
				net_conns=len(net_conns),
				extra_data=extra_data
			)

	@staticmethod
	def get_process_info(process, children=False):
		"""Get process information from psutil.

		Args:
			process (subprocess.Process): Process.
			children (bool): Whether to gather stats about children processes too.
		"""
		try:
			data = {
				k: v._asdict() if hasattr(v, '_asdict') else v
				for k, v in process.as_dict().items()
				if k not in ['memory_maps', 'open_files', 'environ']
			}
			yield data
		except (psutil.Error, FileNotFoundError):
			return
		if children:
			for subproc in process.children(recursive=True):
				yield from Command.get_process_info(subproc, children=False)

	def run_item_loaders(self, line):
		"""Run item loaders against an output line.

		Args:
			line (str): Output line.
		"""
		if self.no_process:
			return
		for item_loader in self.item_loaders:
			if (callable(item_loader)):
				yield from item_loader(self, line)
			elif item_loader:
				name = item_loader.__class__.__name__.replace('Serializer', '').lower()
				default_callback = lambda self, x: [(yield x)]  # noqa: E731
				callback = getattr(self, f'on_{name}_loaded', None) or default_callback
				for item in item_loader.run(line):
					yield from callback(self, item)

	def _prompt_sudo(self, command):
		"""
		Checks if the command requires sudo and prompts for the password if necessary.

		Args:
			command (str): The initial command to be executed.

		Returns:
			tuple: (sudo password, error).
		"""
		sudo_password = None

		# Check if sudo is required by the command
		if not re.search(r'\bsudo\b', command):
			return None, []

		# Check if sudo can be executed without a password
		try:
			if subprocess.run(['sudo', '-n', 'true'], capture_output=False).returncode == 0:
				return None, None
		except ValueError:
			self._print('[bold orange3]Could not run sudo check test.[/][bold green]Passing.[/]')

		# Check if we have a tty
		if not os.isatty(sys.stdin.fileno()):
			error = "No TTY detected. Sudo password prompt requires a TTY to proceed."
			return -1, error

		# If not, prompt the user for a password
		self._print('[bold red]Please enter sudo password to continue.[/]', rich=True)
		for _ in range(3):
			user = getpass.getuser()
			self._print(rf'\[sudo] password for {user}: ▌', rich=True)
			sudo_password = getpass.getpass()
			result = subprocess.run(
				['sudo', '-S', '-p', '', 'true'],
				input=sudo_password + "\n",
				text=True,
				capture_output=True
			)
			if result.returncode == 0:
				return sudo_password, None  # Password is correct
			self._print("Sorry, try again.")
		error = "Sudo password verification failed after 3 attempts."
		return -1, error

	def _wait_for_end(self):
		"""Wait for process to finish and process output and return code."""
		if not self.process:
			return
		for line in self.process.stdout.readlines():
			yield from self.process_line(line)
		self.process.wait()
		self.return_code = self.process.returncode
		self.process.stdout.close()
		self.return_code = 0 if self.ignore_return_code else self.return_code
		self.output = self.output.strip()
		self.killed = self.return_code == -2 or self.killed
		self.debug(f'Command {self.cmd} finished with return code {self.return_code}', sub='command')

		if self.killed:
			error = 'Process was killed manually (CTRL+C / CTRL+X)'
			yield Error(
				message=error,
				_source=self.unique_name,
				_uuid=str(uuid.uuid4())
			)

		elif self.return_code != 0:
			error = f'Command failed with return code {self.return_code}'
			last_lines = self.output.split('\n')
			last_lines = last_lines[max(0, len(last_lines) - 2):]
			last_lines = [line for line in last_lines if line != '']
			yield Error(
				message=error,
				traceback='\n'.join(last_lines),
				traceback_title='Last stdout lines',
				_source=self.unique_name,
				_uuid=str(uuid.uuid4())
			)

	@staticmethod
	def _process_opts(
			opts,
			opts_conf,
			opt_key_map={},
			opt_value_map={},
			opt_prefix='-',
			command_name=None):
		"""Process a dict of options using a config, option key map / value map and option character like '-' or '--'.

		Args:
			opts (dict): Command options as input on the CLI.
			opts_conf (dict): Options config (Click options definition).
			opt_key_map (dict[str, str | Callable]): A dict to map option key with their actual values.
			opt_value_map (dict, str | Callable): A dict to map option values with their actual values.
			opt_prefix (str, default: '-'): Option prefix.
			command_name (str | None, default: None): Command name.
		"""
		opts_str = ''
		for opt_name, opt_conf in opts_conf.items():
			debug('before get_opt_value', obj={'name': opt_name, 'conf': opt_conf}, obj_after=False, sub='command.options', verbose=True)  # noqa: E501

			# Get opt value
			default_val = opt_conf.get('default')
			opt_val = Command._get_opt_value(
				opts,
				opt_name,
				opts_conf,
				opt_prefix=command_name,
				default=default_val)

			debug('after get_opt_value', obj={'name': opt_name, 'value': opt_val, 'conf': opt_conf}, obj_after=False, sub='command.options', verbose=True)  # noqa: E501

			# Skip option if value is falsy
			if opt_val in [None, False, []]:
				debug('skipped (falsy)', obj={'name': opt_name, 'value': opt_val}, obj_after=False, sub='command.options', verbose=True)  # noqa: E501
				continue

			# Apply process function on opt value
			if 'process' in opt_conf:
				func = opt_conf['process']
				opt_val = func(opt_val)

			# Convert opt value to expected command opt value
			mapped_opt_val = opt_value_map.get(opt_name)
			if mapped_opt_val:
				if callable(mapped_opt_val):
					opt_val = mapped_opt_val(opt_val)
				else:
					opt_val = mapped_opt_val

			# Convert opt name to expected command opt name
			mapped_opt_name = opt_key_map.get(opt_name)
			if mapped_opt_name is not None:
				if mapped_opt_name == OPT_NOT_SUPPORTED:
					debug('skipped (unsupported)', obj={'name': opt_name, 'value': opt_val}, sub='command.options', verbose=True)  # noqa: E501
					continue
				else:
					opt_name = mapped_opt_name
			debug('mapped key / value', obj={'name': opt_name, 'value': opt_val}, obj_after=False, sub='command.options', verbose=True)  # noqa: E501

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
			shlex_quote = opt_conf.get('shlex', True)
			if opt_val is not True:
				if shlex_quote:
					opt_val = shlex.quote(str(opt_val))
				opts_str += f' {opt_val}'
			debug('final', obj={'name': opt_name, 'value': opt_val}, sub='command.options', obj_after=False, verbose=True)

		return opts_str.strip()

	@staticmethod
	def _validate_chunked_input(self, inputs):
		"""Command does not suport multiple inputs in non-worker mode. Consider using .delay() instead."""
		if len(inputs) > 1 and self.sync and self.file_flag is None:
			return False
		return True

	@staticmethod
	def _validate_input_nonempty(self, inputs):
		"""Input is empty."""
		if not self.input_required:
			return True
		if not inputs or len(inputs) == 0:
			return False
		return True

	# @staticmethod
	# def _validate_input_types_valid(self, input):
	# 	pass

	@staticmethod
	def _get_opt_default(opt_name, opts_conf):
		for k, v in opts_conf.items():
			if k == opt_name:
				return v.get('default', None)
		return None

	@staticmethod
	def _get_opt_value(opts, opt_name, opts_conf={}, opt_prefix='', default=None):
		default = default or Command._get_opt_default(opt_name, opts_conf)
		opt_names = [
			f'{opt_prefix}.{opt_name}',
			f'{opt_prefix}_{opt_name}',
			opt_name,
		]
		opt_values = [opts.get(o) for o in opt_names]
		alias = [conf.get('short') for _, conf in opts_conf.items() if conf.get('short') in opts and _ == opt_name]
		if alias:
			opt_values.append(opts.get(alias[0]))
		if OPT_NOT_SUPPORTED in opt_values:
			debug('skipped (unsupported)', obj={'name': opt_name}, obj_after=False, sub='command.options', verbose=True)
			return None
		value = next((v for v in opt_values if v is not None), default)
		debug('got opt value', obj={'name': opt_name, 'value': value, 'aliases': opt_names, 'values': opt_values}, obj_after=False, sub='command.options', verbose=True)  # noqa: E501
		return value

	def _build_cmd(self):
		"""Build command string."""

		# Add JSON flag to cmd
		if self.json_flag:
			self.cmd += f' {self.json_flag}'

		# Add options to cmd
		opts_str = Command._process_opts(
			self.run_opts,
			self.opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.config.name)
		if opts_str:
			self.cmd += f' {opts_str}'

		# Add meta options to cmd
		meta_opts_str = Command._process_opts(
			self.run_opts,
			self.meta_opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			command_name=self.config.name)
		if meta_opts_str:
			self.cmd += f' {meta_opts_str}'

	def _build_cmd_input(self):
		"""Many commands take as input a string or a list. This function facilitate this based on whether we pass a
		string or a list to the cmd.
		"""
		cmd = self.cmd
		inputs = self.inputs

		# If inputs is empty, return the previous command
		if not inputs:
			return

		# If inputs has a single element but the tool does not support an input flag, use echo-piped_input input.
		# If the tool's input flag is set to None, assume it is a positional argument at the end of the command.
		# Otherwise use the input flag to pass the input.
		if len(inputs) == 1:
			input = shlex.quote(inputs[0])
			if self.input_flag == OPT_PIPE_INPUT:
				cmd = f'echo {input} | {cmd}'
			elif not self.input_flag:
				cmd += f' {input}'
			else:
				cmd += f' {self.input_flag} {input}'

		# If inputs has multiple elements and the tool has input_flag set to OPT_PIPE_INPUT, use cat-piped_input input.
		# Otherwise pass the file path to the tool.
		else:
			fpath = f'{self.reports_folder}/.inputs/{self.unique_name}.txt'

			# Write the input to a file
			with open(fpath, 'w') as f:
				f.write('\n'.join(inputs))

			if self.file_flag == OPT_PIPE_INPUT:
				cmd = f'cat {fpath} | {cmd}'
			elif self.file_flag:
				cmd += f' {self.file_flag} {fpath}'
			else:
				cmd += f' {fpath}'

			self.inputs_path = fpath

		self.cmd = cmd
		self.shell = ' | ' in self.cmd

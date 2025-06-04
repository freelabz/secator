import copy
import getpass
import logging
import os
import re
import shlex
import signal
import subprocess
import sys

from time import time

import psutil
from fp.fp import FreeProxy

from secator.definitions import OPT_NOT_SUPPORTED, OPT_PIPE_INPUT
from secator.config import CONFIG
from secator.output_types import Info, Warning, Error, Stat
from secator.runners import Runner
from secator.template import TemplateLoader
from secator.utils import debug, rich_escape as _s


logger = logging.getLogger(__name__)


class Command(Runner):
	"""Base class to execute an external command."""
	# Base cmd
	cmd = None

	# Tags
	tags = []
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
	file_eof_newline = False

	# Flag to enable output JSON
	json_flag = None

	# Flag to show version
	version_flag = None

	# Install
	install_pre = None
	install_post = None
	install_cmd = None
	install_github_handle = None
	install_version = None

	# Serializer
	item_loader = None
	item_loaders = []

	# Hooks
	hooks = [
		'on_cmd',
		'on_cmd_opts',
		'on_cmd_done',
		'on_line'
	]

	# Ignore return code
	ignore_return_code = False

	# Return code
	return_code = -1

	# Exit ok
	exit_ok = False

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
			'input_types': self.input_types,
			'description': run_opts.get('description', None)
		})

		# Extract run opts
		hooks = run_opts.pop('hooks', {})
		caller = run_opts.get('caller', None)
		results = run_opts.pop('results', [])
		context = run_opts.pop('context', {})
		node_id = context.get('node_id', None)
		node_name = context.get('node_name', None)
		if node_id:
			config.node_id = node_id
		if node_name:
			config.node_name = context.get('node_name')
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

		# Sudo
		self.requires_sudo = False

		# Proxy config (global)
		self.proxy = self.run_opts.pop('proxy', False)
		self.configure_proxy()

		# Build command input
		self._build_cmd_input()

		# Build command
		self._build_cmd()

		# Run on_cmd hook
		self.run_hooks('on_cmd', sub='init')

		# Add sudo to command if it is required
		if self.requires_sudo:
			self.cmd = f'sudo {self.cmd}'

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
		is_chunk = self.chunk
		chunk_it = (sync and many_targets and not has_file_flag and not is_chunk) or (not sync and many_targets and targets_over_chunk_size and not is_chunk)  # noqa: E501
		return chunk_it

	@classmethod
	def delay(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		results = kwargs.get('results', [])
		kwargs['sync'] = False
		name = cls.__name__
		profile = cls.profile(kwargs) if callable(cls.profile) else cls.profile
		return run_command.apply_async(args=[results, name] + list(args), kwargs={'opts': kwargs}, queue=profile)

	@classmethod
	def s(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		profile = cls.profile(kwargs) if callable(cls.profile) else cls.profile
		return run_command.s(cls.__name__, *args, opts=kwargs).set(queue=profile)

	@classmethod
	def si(cls, *args, results=None, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		profile = cls.profile(kwargs) if callable(cls.profile) else cls.profile
		return run_command.si(results or [], cls.__name__, *args, opts=kwargs).set(queue=profile)

	def get_opt_value(self, opt_name, preprocess=False, process=False):
		"""Get option value as inputed by the user.

		Args:
			opt_name (str): Option name.
			preprocess (bool): Preprocess the value with the option preprocessor function if it exists.
			process (bool): Process the value with the option processor function if it exists.

		Returns:
			Any: Option value.
		"""
		return Command._get_opt_value(
			self.run_opts,
			opt_name,
			dict(self.opts, **self.meta_opts),
			opt_aliases=self.opt_aliases,
			preprocess=preprocess,
			process=process)

	@classmethod
	def get_version_flag(cls):
		if cls.version_flag == OPT_NOT_SUPPORTED:
			return None
		return cls.version_flag or f'{cls.opt_prefix}version'

	@classmethod
	def get_version_info(cls, bleeding=False):
		from secator.installer import get_version_info
		return get_version_info(
			cls.cmd.split(' ')[0],
			cls.get_version_flag(),
			cls.install_github_handle,
			cls.install_cmd,
			cls.install_version,
			bleeding=bleeding
		)

	@classmethod
	def get_supported_opts(cls):
		# TODO: Replace this with get_command_options called on the command class
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
		kwargs['process'] = kwargs.get('process', False)
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
			warning = Warning(message=rf'Ignoring proxy "{self.proxy}" (reason: not supported) \[[bold yellow3]{self.unique_name}[/]]')  # noqa: E501
			self._print(repr(warning))

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

			# Abort if dry run
			if self.dry_run:
				self.print_description()
				self.print_command()
				yield Info(message=self.cmd)
				return

			# Abort if no inputs
			if len(self.inputs) == 0 and self.skip_if_no_inputs:
				yield Warning(message=f'{self.unique_name} skipped (no inputs)')
				return

			# Print command
			self.print_description()
			self.print_command()

			# Check for sudo requirements and prepare the password if needed
			sudo_password, error = self._prompt_sudo(self.cmd)
			if error:
				yield Error(message=error)
				return

			# Prepare cmds
			command = self.cmd if self.shell else shlex.split(self.cmd)

			# Check command is installed and auto-install
			if not self.no_process and not self.is_installed():
				if CONFIG.security.auto_install_commands:
					from secator.installer import ToolInstaller
					yield Info(message=f'Command {self.name} is missing but auto-installing since security.autoinstall_commands is set')  # noqa: E501
					status = ToolInstaller.install(self.__class__)
					if not status.is_ok():
						yield Error(message=f'Failed installing {self.cmd_name}')
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
			result = self.run_hooks('on_cmd_done', sub='end')
			if result:
				yield from result

		except FileNotFoundError as e:
			yield from self.handle_file_not_found(e)

		except BaseException as e:
			self.debug(f'{self.unique_name}: {type(e).__name__}.', sub='end')
			self.stop_process()
			yield Error.from_exception(e)

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
		line = self.run_hooks('on_line', line, sub='line.process')
		if line is None:
			return

		# Yield line if no items were yielded
		yield line

		# Run item_loader to try parsing as dict
		for item in self.run_item_loaders(line):
			yield item

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
		if self.sync and not self.has_children and self.caller and self.description and self.print_cmd:
			self._print(f'\n[bold gold3]:wrench: {self.description} [dim cyan]({self.config.name})[/][/] ...', rich=True)

	def print_command(self):
		"""Print command."""
		if self.print_cmd:
			cmd_str = f':zap: {_s(self.cmd)}'
			if self.sync and self.chunk and self.chunk_count:
				cmd_str += f' [dim gray11]({self.chunk}/{self.chunk_count})[/]'
			self._print(cmd_str, color='bold green', rich=True)
		self.debug('command', obj={'cmd': self.cmd}, sub='start')
		self.debug('options', obj=self.cmd_options, sub='start')

	def handle_file_not_found(self, exc):
		"""Handle case where binary is not found.

		Args:
			exc (FileNotFoundError): the exception.

		Yields:
			secator.output_types.Error: the error.
		"""
		self.debug('command not found', sub='end')
		self.return_code = 127
		if self.config.name in str(exc):
			message = 'Executable not found.'
			if self.install_cmd:
				message += f' Install it with "secator install tools {self.config.name}".'
			error = Error(message=message)
		else:
			error = Error.from_exception(exc)
		yield error

	def stop_process(self, exit_ok=False):
		"""Sends SIGINT to running process, if any."""
		if not self.process:
			return
		self.debug(f'Sending SIGINT to process {self.process.pid}.', sub='error')
		self.process.send_signal(signal.SIGINT)
		if exit_ok:
			self.exit_ok = True

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
		self.return_code = 0 if self.exit_ok else self.process.returncode
		self.process.stdout.close()
		self.return_code = 0 if self.ignore_return_code else self.return_code
		self.output = self.output.strip()
		self.killed = self.return_code == -2 or self.killed
		self.debug(f'return code: {self.return_code}', sub='end')

		if self.killed:
			error = 'Process was killed manually (CTRL+C / CTRL+X)'
			yield Error(message=error)

		elif self.return_code != 0:
			error = f'Command failed with return code {self.return_code}'
			last_lines = self.output.split('\n')
			last_lines = last_lines[max(0, len(last_lines) - 2):]
			last_lines = [line for line in last_lines if line != '']
			yield Error(message=error, traceback='\n'.join(last_lines), traceback_title='Last stdout lines')

	@staticmethod
	def _process_opts(
			opts,
			opts_conf,
			opt_key_map={},
			opt_value_map={},
			opt_prefix='-',
			opt_aliases=None,
			preprocess=False,
			process=True):
		"""Process a dict of options using a config, option key map / value map and option character like '-' or '--'.

		Args:
			opts (dict): Command options as input on the CLI.
			opts_conf (dict): Options config (Click options definition).
			opt_key_map (dict[str, str | Callable]): A dict to map option key with their actual values.
			opt_value_map (dict, str | Callable): A dict to map option values with their actual values.
			opt_prefix (str, default: '-'): Option prefix.
			opt_aliases (str | None, default: None): Aliases to try.
			preprocess (bool, default: True): Preprocess the value with the option preprocessor function if it exists.
			process (bool, default: True): Process the value with the option processor function if it exists.

		Returns:
			dict: Processed options dict.
		"""
		opts_dict = {}
		for opt_name, opt_conf in opts_conf.items():
			debug('before get_opt_value', obj={'name': opt_name, 'conf': opt_conf}, obj_after=False, sub='init.options', verbose=True)  # noqa: E501

			# Save original opt name
			original_opt_name = opt_name

			# Copy opt conf
			conf = opt_conf.copy()

			# Get opt value
			default_val = conf.get('default')
			opt_val = Command._get_opt_value(
				opts,
				opt_name,
				opts_conf,
				opt_aliases=opt_aliases,
				default=default_val,
				preprocess=preprocess,
				process=process)

			debug('after get_opt_value', obj={'name': opt_name, 'value': opt_val, 'conf': conf}, obj_after=False, sub='init.options', verbose=True)  # noqa: E501

			# Skip option if value is falsy
			if opt_val in [None, False, []]:
				debug('skipped (falsy)', obj={'name': opt_name, 'value': opt_val}, obj_after=False, sub='init.options', verbose=True)  # noqa: E501
				continue

			# Convert opt value to expected command opt value
			mapped_opt_val = opt_value_map.get(opt_name)
			if mapped_opt_val:
				conf.pop('pre_process', None)
				conf.pop('process', None)
				if callable(mapped_opt_val):
					opt_val = mapped_opt_val(opt_val)
				else:
					opt_val = mapped_opt_val
			elif 'pre_process' in conf:
				opt_val = conf['pre_process'](opt_val)

			# Convert opt name to expected command opt name
			mapped_opt_name = opt_key_map.get(opt_name)
			if mapped_opt_name is not None:
				if mapped_opt_name == OPT_NOT_SUPPORTED:
					debug('skipped (unsupported)', obj={'name': opt_name, 'value': opt_val}, sub='init.options', verbose=True)  # noqa: E501
					continue
				else:
					opt_name = mapped_opt_name
			debug('mapped key / value', obj={'name': opt_name, 'value': opt_val}, obj_after=False, sub='init.options', verbose=True)  # noqa: E501

			# Avoid shell injections and detect opt prefix
			opt_name = str(opt_name).split(' ')[0]  # avoid cmd injection

			# Replace '_' with '-'
			opt_name = opt_name.replace('_', '-')

			# Add opt prefix if not already there
			if len(opt_name) > 0 and opt_name[0] not in ['-', '--']:
				opt_name = f'{opt_prefix}{opt_name}'

			# Append opt name + opt value to option string.
			# Note: does not append opt value if value is True (flag)
			opts_dict[original_opt_name] = {'name': opt_name, 'value': opt_val, 'conf': conf}
			debug('final', obj={'name': original_opt_name, 'value': opt_val}, sub='init.options', obj_after=False, verbose=True)  # noqa: E501

		return opts_dict

	@staticmethod
	def _validate_chunked_input(self, inputs):
		"""Command does not support multiple inputs in non-worker mode. Consider running with a remote worker instead."""
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
		"""Get the default value of an option.

		Args:
			opt_name (str): The name of the option to get the default value of (no aliases allowed).
			opts_conf (dict): The options configuration, indexed by option name.

		Returns:
			any: The default value of the option.
		"""
		for k, v in opts_conf.items():
			if k == opt_name:
				return v.get('default', None)
		return None

	@staticmethod
	def _get_opt_value(opts, opt_name, opts_conf={}, opt_aliases=None, default=None, preprocess=False, process=False):
		"""Get the value of an option.

		Args:
			opts (dict): The options dict to search (input opts).
			opt_name (str): The name of the option to get the value of.
			opts_conf (dict): The options configuration, indexed by option name.
			opt_aliases (list): The aliases to try.
			default (any): The default value to return if the option is not found.
			preprocess (bool): Whether to preprocess the value using the option preprocessor function.
			process (bool): Whether to process the value using the option processor function.

		Returns:
			any: The value of the option.

		Example:
			opts = {'target': 'example.com'}
			opts_conf = {'target': {'type': 'str', 'short': 't', 'default': 'example.com', 'pre_process': lambda x: x.upper()}}  # noqa: E501
			opt_aliases = ['prefix_target', 'target']

			# Example 1:
			opt_name = 'target'
			opt_value = Command._get_opt_value(opts, opt_name, opts_conf, opt_aliases, preprocess=True)  # noqa: E501
			print(opt_value)
			# Output: EXAMPLE.COM

			# Example 2:
			opt_name = 'prefix_target'
			opt_value = Command._get_opt_value(opts, opt_name, opts_conf, opt_aliases)
			print(opt_value)
			# Output: example.com
		"""
		default = default or Command._get_opt_default(opt_name, opts_conf)
		opt_aliases = opt_aliases or []
		opt_names = []
		for prefix in opt_aliases:
			opt_names.extend([f'{prefix}.{opt_name}', f'{prefix}_{opt_name}'])
		opt_names.append(opt_name)
		opt_names = list(dict.fromkeys(opt_names))
		opt_values = [opts.get(o) for o in opt_names]
		opt_conf = [conf for _, conf in opts_conf.items() if _ == opt_name]
		if opt_conf:
			opt_conf = opt_conf[0]
			alias = opt_conf.get('short')
			if alias:
				opt_values.append(opts.get(alias))
		if OPT_NOT_SUPPORTED in opt_values:
			debug('skipped (unsupported)', obj={'name': opt_name}, obj_after=False, sub='init.options', verbose=True)
			return None
		value = next((v for v in opt_values if v is not None), default)
		if opt_conf:
			preprocessor = opt_conf.get('pre_process')
			processor = opt_conf.get('process')
			if preprocess and preprocessor:
				value = preprocessor(value)
			if process and processor:
				value = processor(value)
		debug('got opt value', obj={'name': opt_name, 'value': value, 'aliases': opt_names, 'values': opt_values}, obj_after=False, sub='init.options', verbose=True)  # noqa: E501
		return value

	def _build_cmd(self):
		"""Build command string."""

		# Add JSON flag to cmd
		if self.json_flag:
			self.cmd += f' {self.json_flag}'

		# Opts str
		opts_str = ''
		opts = {}

		# Add options to cmd
		opts_dict = Command._process_opts(
			self.run_opts,
			self.opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			opt_aliases=self.opt_aliases,
			preprocess=False,
			process=False)

		# Add meta options to cmd
		meta_opts_dict = Command._process_opts(
			self.run_opts,
			self.meta_opts,
			self.opt_key_map,
			self.opt_value_map,
			self.opt_prefix,
			opt_aliases=self.opt_aliases,
			preprocess=False,
			process=False)

		if opts_dict:
			opts.update(opts_dict)
		if meta_opts_dict:
			opts.update(meta_opts_dict)

		opts = self.run_hooks('on_cmd_opts', opts, sub='init')

		if opts:
			for opt_conf in opts.values():
				conf = opt_conf['conf']
				process = conf.get('process')
				if process:
					opt_conf['value'] = process(opt_conf['value'])
				internal = conf.get('internal', False)
				if internal:
					continue
				if conf.get('requires_sudo', False):
					self.requires_sudo = True
				opts_str += ' ' + Command._build_opt_str(opt_conf)
				if '{target}' in opts_str:
					opts_str = opts_str.replace('{target}', self.inputs[0])
		self.cmd_options = opts
		self.cmd += opts_str

	@staticmethod
	def _build_opt_str(opt):
		"""Build option string."""
		conf = opt['conf']
		shlex_quote = conf.get('shlex', True)
		value = opt['value']
		opt_name = opt['name']
		opts_str = ''
		value = [value] if not isinstance(value, list) else value
		for val in value:
			if val is True:
				opts_str += f'{opt_name}'
			else:
				if shlex_quote:
					val = shlex.quote(str(val))
				opts_str += f'{opt_name} {val} '
		return opts_str.strip()

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
				if self.file_eof_newline:
					f.write('\n')

			if self.file_flag == OPT_PIPE_INPUT:
				cmd = f'cat {fpath} | {cmd}'
			elif self.file_flag:
				cmd += f' {self.file_flag} {fpath}'
			else:
				cmd += f' {fpath}'

			self.inputs_path = fpath

		self.cmd = cmd
		self.shell = ' | ' in self.cmd

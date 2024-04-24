import getpass
import logging
import os
import re
import shlex
import subprocess
import sys

from time import sleep

from fp.fp import FreeProxy

from secator.template import TemplateLoader
from secator.definitions import OPT_NOT_SUPPORTED, OPT_PIPE_INPUT
from secator.config import CONFIG
from secator.runners import Runner
from secator.serializers import JSONSerializer
from secator.utils import debug


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

	# Environment variables
	env = {}

	# Flag to take the input
	input_flag = None

	# Input path (if a file is constructed)
	input_path = None

	# Input chunk size (default None)
	input_chunk_size = CONFIG.runners.input_chunk_size

	# Flag to take a file as input
	file_flag = None

	# Flag to enable output JSON
	json_flag = None

	# Flag to show version
	version_flag = None

	# Install
	install_cmd = None
	install_github_handle = None

	# Serializer
	item_loader = None
	item_loaders = [JSONSerializer(),]

	# Ignore return code
	ignore_return_code = False

	# Return code
	return_code = -1

	# Error
	error = ''

	# Output
	output = ''

	# Proxy options
	proxychains = False
	proxy_socks5 = False
	proxy_http = False

	# Profile
	profile = 'cpu'

	def __init__(self, input=None, **run_opts):
		# Build runnerconfig on-the-fly
		config = TemplateLoader(input={
			'name': self.__class__.__name__,
			'type': 'task',
			'description': run_opts.get('description', None)
		})

		# Run parent init
		hooks = run_opts.pop('hooks', {})
		results = run_opts.pop('results', [])
		context = run_opts.pop('context', {})
		super().__init__(
			config=config,
			targets=input,
			results=results,
			run_opts=run_opts,
			hooks=hooks,
			context=context)

		# Current working directory for cmd
		self.cwd = self.run_opts.get('cwd', None)

		# No capturing of stdout / stderr.
		self.no_capture = self.run_opts.get('no_capture', False)

		# No processing of output lines.
		self.no_process = self.run_opts.get('no_process', False)

		# Proxy config (global)
		self.proxy = self.run_opts.pop('proxy', False)
		self.configure_proxy()

		# Build command input
		self._build_cmd_input()

		# Build command
		self._build_cmd()

		# Build item loaders
		instance_func = getattr(self, 'item_loader', None)
		item_loaders = self.item_loaders.copy()
		if instance_func:
			item_loaders.append(instance_func)
		self.item_loaders = item_loaders

		# Print built cmd
		if self.print_cmd and not self.has_children:
			if self.sync and self.description:
				self._print(f'\n:wrench: {self.description} ...', color='bold gold3', rich=True)
			self._print(self.cmd.replace('[', '\\['), color='bold cyan', rich=True)

		# Print built input
		if self.print_input_file and self.input_path:
			input_str = '\n '.join(self.input).strip()
			debug(f'[dim magenta]File input:[/]\n [italic medium_turquoise]{input_str}[/]')

		# Print run options
		if self.print_run_opts:
			input_str = '\n '.join([
				f'[dim blue]{k}[/] -> [dim green]{v}[/]' for k, v in self.run_opts.items() if v is not None]).strip()
			debug(f'[dim magenta]Run opts:[/]\n {input_str}')

		# Print format options
		if self.print_fmt_opts:
			input_str = '\n '.join([
				f'[dim blue]{k}[/] -> [dim green]{v}[/]' for k, v in self.opts_to_print.items() if v is not None]).strip()
			debug(f'[dim magenta]Print opts:[/]\n {input_str}')

		# Print hooks
		if self.print_hooks:
			input_str = ''
			for hook_name, hook_funcs in self.hooks.items():
				hook_funcs_str = ', '.join([f'[dim green]{h.__module__}.{h.__qualname__}[/]' for h in hook_funcs])
				if hook_funcs:
					input_str += f'[dim blue]{hook_name}[/] -> {hook_funcs_str}\n '
			input_str = input_str.strip()
			if input_str:
				debug(f'[dim magenta]Hooks:[/]\n {input_str}')

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
		from secator.celery import run_command
		results = kwargs.get('results', [])
		name = cls.__name__
		return run_command.apply_async(args=[results, name] + list(args), kwargs={'opts': kwargs}, queue=cls.profile)

	@classmethod
	def s(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		return run_command.s(cls.__name__, *args, opts=kwargs).set(queue=cls.profile)

	@classmethod
	def si(cls, results, *args, **kwargs):
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

		opts = {k: convert(v) for k, v in cls.opts.items()}
		for k, v in opts.items():
			v['meta'] = cls.__name__
			v['supported'] = True

		meta_opts = {k: convert(v) for k, v in cls.meta_opts.items() if cls.opt_key_map.get(k) is not OPT_NOT_SUPPORTED}
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
	def execute(cls, cmd, name=None, cls_attributes={}, **kwargs):
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
		kwargs['no_process'] = kwargs.get('no_process', True)
		kwargs['print_cmd'] = not kwargs.get('quiet', False)
		kwargs['print_item'] = not kwargs.get('quiet', False)
		kwargs['print_line'] = not kwargs.get('quiet', False)
		delay_run = kwargs.pop('delay_run', False)
		cmd_instance = type(name, (Command,), {'cmd': cmd})(**kwargs)
		for k, v in cls_attributes.items():
			setattr(cmd_instance, k, v)
		if not delay_run:
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
			elif self.proxy == 'random':
				proxy = FreeProxy(timeout=CONFIG.http.freeproxy_timeout, rand=True, anonym=True).get()
			elif self.proxy.startswith(('http://', 'socks5://')):
				proxy = self.proxy

		if proxy != 'proxychains':
			self.run_opts['proxy'] = proxy

		if proxy != 'proxychains' and self.proxy and not proxy:
			self._print(
				f'[bold red]Ignoring proxy "{self.proxy}" for {self.__class__.__name__} (not supported).[/]', rich=True)

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
		# Set status to 'RUNNING'
		self.status = 'RUNNING'

		# Callback before running command
		self.run_hooks('on_start')

		# Check for sudo requirements and prepare the password if needed
		sudo_password = self._prompt_sudo(self.cmd)

		# Prepare cmds
		command = self.cmd if self.shell else shlex.split(self.cmd)

		# Output and results
		self.return_code = 0
		self.killed = False

		# Run the command using subprocess
		try:
			env = os.environ
			env.update(self.env)
			self.process = subprocess.Popen(
				command,
				stdin=subprocess.PIPE if sudo_password else None,
				stdout=sys.stdout if self.no_capture else subprocess.PIPE,
				stderr=sys.stderr if self.no_capture else subprocess.STDOUT,
				universal_newlines=True,
				shell=self.shell,
				env=env,
				cwd=self.cwd)

			# If sudo password is provided, send it to stdin
			if sudo_password:
				self.process.stdin.write(f"{sudo_password}\n")
				self.process.stdin.flush()

		except FileNotFoundError as e:
			if self.config.name in str(e):
				error = 'Executable not found.'
				if self.install_cmd:
					error += f' Install it with `secator install tools {self.config.name}`.'
			else:
				error = str(e)
			celery_id = self.context.get('celery_id', '')
			if celery_id:
				error += f' [{celery_id}]'
			self.errors.append(error)
			self.return_code = 1
			return

		try:
			# No capture mode, wait for command to finish and return
			if self.no_capture:
				self._wait_for_end()
				return

			# Process the output in real-time
			for line in iter(lambda: self.process.stdout.readline(), b''):
				sleep(0)  # for async to give up control
				if not line:
					break

				# Strip line endings
				line = line.rstrip()
				if self.no_process:
					yield line
					continue

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
					items = self.run_item_loaders(line)

				# Yield line if no items parsed
				if not items:
					yield line

				# Turn results into list if not already a list
				elif not isinstance(items, list):
					items = [items]

				# Yield items
				if items:
					yield from items

		except KeyboardInterrupt:
			self.process.kill()
			self.killed = True

		# Retrieve the return code and output
		self._wait_for_end()

	def run_item_loaders(self, line):
		"""Run item loaders on a string."""
		items = []
		for item_loader in self.item_loaders:
			result = None
			if (callable(item_loader)):
				result = item_loader(self, line)
			elif item_loader:
				result = item_loader.run(line)
			if isinstance(result, dict):
				result = [result]
			if result:
				items.extend(result)
		return items

	def _prompt_sudo(self, command):
		"""
		Checks if the command requires sudo and prompts for the password if necessary.

		Args:
			command (str): The initial command to be executed.

		Returns:
			str or None: The sudo password if required; otherwise, None.
		"""
		sudo_password = None

		# Check if sudo is required by the command
		if not re.search(r'\bsudo\b', command):
			return None

		# Check if sudo can be executed without a password
		if subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode == 0:
			return None

		# Check if we have a tty
		if not os.isatty(sys.stdin.fileno()):
			self._print("No TTY detected. Sudo password prompt requires a TTY to proceed.", color='bold red')
			sys.exit(1)

		# If not, prompt the user for a password
		self._print('[bold red]Please enter sudo password to continue.[/]')
		for _ in range(3):
			self._print('\[sudo] password: ')
			sudo_password = getpass.getpass()
			result = subprocess.run(
				['sudo', '-S', '-p', '', 'true'],
				input=sudo_password + "\n",
				text=True,
				capture_output=True
			)
			if result.returncode == 0:
				return sudo_password  # Password is correct
			self._print("Sorry, try again.")
		self._print("Sudo password verification failed after 3 attempts.")
		return None

	def _wait_for_end(self):
		"""Wait for process to finish and process output and return code."""
		self.process.wait()
		self.return_code = self.process.returncode

		if self.no_capture:
			self.output = ''
		else:
			self.output = self.output.strip()
			self.process.stdout.close()

		if self.ignore_return_code:
			self.return_code = 0

		if self.return_code == -2 or self.killed:
			error = 'Process was killed manually (CTRL+C / CTRL+X)'
			self.errors.append(error)
		elif self.return_code != 0:
			error = f'Command failed with return code {self.return_code}.'
			self.errors.append(error)

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
		input = self.input

		# If input is None, return the previous command
		if not input:
			return

		# If input is a list but has one element, use the standard string input
		if isinstance(input, list) and len(input) == 1:
			input = input[0]

		# If input is a list and the tool has input_flag set to OPT_PIPE_INPUT, use cat-piped input.
		# Otherwise pass the file path to the tool.
		if isinstance(input, list):
			fpath = f'{self.reports_folder}/.inputs/{self.unique_name}.txt'

			# Write the input to a file
			with open(fpath, 'w') as f:
				f.write('\n'.join(input))

			if self.file_flag == OPT_PIPE_INPUT:
				cmd = f'cat {fpath} | {cmd}'
			elif self.file_flag:
				cmd += f' {self.file_flag} {fpath}'
			else:
				self._print(f'{self.__class__.__name__} does not support multiple inputs.', color='bold red')
				self.input_valid = False

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

"""Attack tasks."""

import logging

from rich.panel import Panel

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT, HEADER, HOST, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
								 THREADS, TIMEOUT, USER_AGENT)
from secator.tasks._categories import VulnMulti
from secator.utils import get_file_timestamp

logger = logging.getLogger(__name__)


@task()
class msfconsole(VulnMulti):
	"""CLI to access and work with the Metasploit Framework."""
	cmd = 'msfconsole --quiet'
	version_flag = OPT_NOT_SUPPORTED
	input_type = HOST
	input_chunk_size = 1
	output_types = []
	opt_prefix = '--'
	opts = {
		'resource': {'type': str, 'help': 'Metasploit resource script.', 'short': 'r'},
		'execute_command': {'type': str, 'help': 'Metasploit command.', 'short': 'x'},
		'environment': {'type': str, 'help': 'Environment variables string KEY=VALUE.', 'short': 'e'}
	}
	opt_key_map = {
		'x': 'execute_command',
		'r': 'resource',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	encoding = 'ansi'
	ignore_return_code = True
	install_pre = {
		'apt|apk': ['libpq-dev', 'libpcap-dev', 'libffi-dev', 'g++', 'make'],
		'pacman': ['ruby-erb', 'postgresql-libs', 'make'],
		'yum|zypper': ['postgresql-devel', 'make'],
	}
	install_cmd = (
		f'git clone --depth 1 --single-branch https://github.com/rapid7/metasploit-framework.git {CONFIG.dirs.share}/metasploit-framework || true && '  # noqa: E501
		f'cd {CONFIG.dirs.share}/metasploit-framework && '
		f'gem install bundler --user-install -n {CONFIG.dirs.bin} && '
		f'bundle config set --local path "{CONFIG.dirs.share}" && '
		'bundle lock --normalize-platforms &&'
		'bundle install && '
		f'ln -sf $HOME/.local/share/metasploit-framework/msfconsole {CONFIG.dirs.bin}/msfconsole'
	)

	@staticmethod
	def on_init(self):
		command = self.get_opt_value('execute_command')
		script_path = self.get_opt_value('resource')
		environment = self.run_opts.pop('environment', '')
		env_vars = {}
		if environment:
			env_vars = dict(map(lambda x: x.split('='), environment.strip().split(',')))
		env_vars['RHOST'] = self.inputs[0]
		env_vars['RHOSTS'] = self.inputs[0]

		# Passing msfconsole command directly, simply add RHOST / RHOSTS from host input and run then exit
		if command:
			self.run_opts['msfconsole.execute_command'] = (
				f'setg RHOST {self.inputs[0]}; '
				f'setg RHOSTS {self.inputs[0]}; '
				f'{command.format(**env_vars)}; '
				f'exit;'
			)

		# Passing resource script, replace vars inside by our environment variables if any, write to a temp file, and
		# pass this temp file instead of the original one.
		elif script_path:

			# Read from original resource script
			with open(script_path, 'r') as f:
				content = f.read().replace('exit', '') + 'exit'

			# Make a copy and replace vars inside by env vars passed on the CLI
			timestr = get_file_timestamp()
			out_path = f'{self.reports_folder}/.inputs/msfconsole_{timestr}.rc'
			logger.debug(
				f'Writing formatted resource script to new temp file {out_path}'
			)
			with open(out_path, 'w') as f:
				content = content.format(**env_vars)
				f.write(content)

			script_name = script_path.split('/')[-1]
			self._print(Panel(content, title=f'[bold magenta]{script_name}', expand=False), rich=True)

			# Override original command with new resource script
			self.run_opts['msfconsole.resource'] = out_path

		# Nothing passed, error out
		else:
			raise ValueError('At least one of "execute_command" or "resource" must be passed.')


# TODO: This is better as it goes through an RPC API to communicate with
# metasploit rpc server, but it does not give any output.
# Seems like output is available only in Metasploit Pro, so keeping this in case
# we add support for it later.
#
# from pymetasploit3.msfrpc import MsfRpcClient
# class msfrpcd():
#
#     opts = {
#         'uri': {'type': str, 'default': '/api/', 'help': 'msfrpcd API uri'},
#         'port': {'type': int, 'default': 55553, 'help': 'msfrpcd port'},
#         'server': {'type': str, 'default': 'localhost', 'help': 'msfrpcd host'},
#         'token': {'type': str, 'help': 'msfrpcd token'},
#         'username': {'type': str, 'default': 'msf', 'help': 'msfrpcd username'},
#         'password': {'type': str, 'default': 'test', 'help': 'msfrpcd password'},
#         'module': {'type': str, 'required': True, 'help': 'Metasploit module to run'}
#     }
#
#     def __init__(self, input, ctx={}, **run_opts):
#         self.module = run_opts.pop('module')
#         pw = run_opts.pop('password')
#         self.run_opts = run_opts
#         self.RHOST = input
#         self.RHOSTS = input
#         self.LHOST = self.get_lhost()
#         # self.start_msgrpc()
#         self.client = MsfRpcClient(pw, ssl=True, **run_opts)
#
#     # def start_msgrpc(self):
#     #     code, out = Command.execute(f'msfrpcd -P {self.password}')
#     #     logger.info(out)
#
#     def get_lhost(self):
#         try:
#             u = miniupnpc.UPnP()
#             u.discoverdelay = 200
#             u.discover()
#             u.selectigd()
#             return u.externalipaddress()
#         except Exception:
#             return 'localhost'
#
#     def run(self):
#         """Run a metasploit module.
#
#         Args:
#             modtype: Module type amongst 'auxiliary', 'exploit', 'post',
#                 'encoder', 'nop', 'payload'.
#             modname: Module name e.g 'auxiliary/scanner/ftp/ftp_version
#             kwargs (dict): Module kwargs e.g RHOSTS, LHOST
#         Returns:
#             dict: Job results.
#         """
#         modtype = self.module.split('/')[0].rstrip('s')
#         job = self.client.modules.execute(
# 			modtype,
# 			self.module,
# 			RHOST=self.RHOST,
# 			RHOSTS=self.RHOSTS,
# 			LHOST=self.LHOST)
#         if job.get('error', False):
#             logger.error(job['error_message'])
#         job_info = self.client.jobs.info_by_uuid(job['uuid'])
#         while (job_info['status'] in ['running', 'ready']):
#             job_info = self.client.jobs.info_by_uuid(job['uuid'])
#         job_info.update(job)
#         print(type(job_info['result']['127.0.0.1']))
#         return job_info

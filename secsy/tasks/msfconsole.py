"""Attack tasks."""

import logging

from secsy.definitions import HOST, TEMP_FOLDER
from secsy.runners import Command
from secsy.utils import get_file_timestamp

logger = logging.getLogger(__name__)


class msfconsole(Command):
	"""CLI to access and work with the Metasploit Framework."""
	cmd = 'msfconsole --quiet'
	input_type = HOST
	output_types = []
	output_return_type = str
	opt_prefix = '--'
	opts = {
		'resource': {'type': str, 'help': 'Metasploit commands.', 'short': 'r'},
		'execute_command': {'type': str, 'help': 'Metasploit resource script.', 'short': 'x'},
		# 'environment': {'type': str, 'default': '', 'help': 'Environment variables string in the format KEY=VALUE.', 'short': 'env'}
	}
	opt_key_map = {
		'x': 'execute_command',
		'r': 'resource',
		# 'e': 'environment'
	}

	@staticmethod
	def on_init(self):
		command = self.get_opt_value('execute_command')
		script_path = self.get_opt_value('resource')
		env_vars = {
			k: v for k, v in (i.split('=') for i in self.cmd_opts.pop('env_vars', ()))
		}
		env_vars['host'] = self.input

		# Passing msfconsole command directly, simply add RHOST / RHOSTS from host input and run then exit
		if command:
			self.cmd_opts['execute_command'] = (
				f'setg RHOST {self.input}; '
				f'setg RHOSTS {self.input}; '
				f'{command.format(**env_vars)}; '
				f'exit;'
			)

		# Passing resource script, replace vars inside by our environment variables if any, write to a temp file, and
		# pass this temp file instead of the original one.
		elif script_path:

			# Read from original resource script
			with open(script_path, 'r') as f:
				content = f.read().rstrip('exit') + 'exit\n'

			# Make a copy and replace vars inside by env vars passed on the CLI
			timestr = get_file_timestamp()
			out_path = f'{TEMP_FOLDER}/msfconsole_{timestr}.rc'
			logger.debug(
				f'Writing formatted resource script to new temp file {out_path}'
			)
			with open(out_path, 'w') as f:
				content = content.format(**env_vars)
				print(content) if self._print_timestamp else logger.debug(content)
				f.write(content)

			# Override original command with new resource script
			self.cmd_opts['resource'] = out_path

		# Nothing passed, error out
		else:
			raise ValueError('At least one of "inline_script" or "resource_script" must be passed.')

		# Clear host input
		self.input = ''


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
#     def __init__(self, input, ctx={}, **cmd_opts):
#         self.module = cmd_opts.pop('module')
#         self.print_timestamp = ctx.get('print_timestamp', False)
#         pw = cmd_opts.pop('password')
#         self.cmd_opts = cmd_opts
#         self.RHOST = input
#         self.RHOSTS = input
#         self.LHOST = self.get_lhost()
#         # self.start_msgrpc()
#         self.client = MsfRpcClient(pw, ssl=True, **cmd_opts)
#
#     # def start_msgrpc(self):
#     #     code, out = run_command(f'msfrpcd -P {self.password}')
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
#         print(job_info) if self.print_timestamp else logger.debug(job_info)
#         print(type(job_info['result']['127.0.0.1']))
#         return job_info

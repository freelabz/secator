import re

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, IP, STRING, THREADS, HEADER, DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES, TIMEOUT, USER_AGENT, OPT_NOT_SUPPORTED  # noqa: E501
from secator.output_types import Vulnerability, Tag, Warning
from secator.tasks._categories import Vuln
from secator.utils import autodetect_type


STATUS_REGEX = re.compile(r'\s*(?P<os>.+?)\s\((?P<version>[^)]*)\)\s\(name:(?P<name>[^)]*)\)\s\(domain:(?P<domain>[^)]*)\)\s\(EncryptionReq:(?P<enc>[^)]*)\)(?:\s\(NTLM:(?P<ntlm>[^)]*)\))?')  # noqa: E501
LOGIN_SUCCESS_REGEX = re.compile(r'\s*(?P<domain>[\w.\-]+)\\(?P<username>[^:\n]*):?(?P<password>.*?)(?:\s+\((?P<status>[^)]*)\))?$')  # noqa: E501
LOGIN_FAILED_REGEX = re.compile(r'\s*(?P<domain>[\w.\-]+)\\(?P<username>[^:\n]*):?(?P<password>.*)?')


@task()
class nxc_mssql(Vuln):
	"""NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of large networks. FTP Submodule."""  # noqa: E501
	cmd = 'nxc mssql'
	encoding = 'ansi'  # nxc colorizes output; strip ANSI before parsing (CI forces color)
	input_chunk_size = 1
	input_types = [HOST, HOST_PORT, IP, STRING]
	output_types = [Vulnerability, Tag]
	ignore_return_code = True
	opt_prefix = '--'
	opts = {
		'username': {'type': str, 'short': 'u', 'default': 'anonymous', 'help': 'Username'},
		'password': {'type': str, 'short': 'p', 'default': '', 'help': 'Password'},
		'domain': {'type': str, 'default': None, 'help': 'Domain'},
		'mssql_port': {'type': int, 'default': 1433, 'help': 'MSSQL port'},
		'dns_server': {'type': str, 'default': None, 'help': 'DNS server (default from system)'},
		'dns_timeout': {'type': int, 'default': 3, 'help': 'DNS query timeout in seconds'},
		'cred_id': {'type': str, 'default': None, 'help': 'Database credential ID(s) to use for authentication'},
		'ignore_pw_decoding': {'is_flag': True, 'help': 'Ignore non UTF-8 characters when decoding the password file'},
		'no_bruteforce': {'is_flag': True, 'help': 'No spray when using file for username and password (user1 => password1, user2 => password2)'},  # noqa: E501
		'continue_on_success': {'is_flag': True, 'help': 'Continues auth attempts even after successes'},
		'kerberos': {'is_flag': True, 'help': 'Use Kerberos authentication'},
		'module': {'type': str, 'help': 'Module to use'},
		'module_option': {'type': str, 'help': 'Module option'},
		'local_auth': {'is_flag':  True, 'default': None, 'help': 'Local authentication'},
	}
	opt_key_map = {
		'username': '-u',
		'password': '-p',
		'domain': '-d',
		'module_option': '-o',
		'mssql_port': 'port',
		THREADS: 'threads',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'jitter',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	opt_value_map = {
		DELAY: lambda x: f'{str(x)}-{str(x)}',
	}
	github_handle = 'Pennyw0rth/NetExec'
	install_github_bin = False
	install_version = "30cf1465"
	install_cmd = "pipx install --force git+https://github.com/Pennyw0rth/NetExec@[install_version]"

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		if self.inputs:
			self.full_target = self.inputs[0]
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.inputs[0] = host
			opts['mssql_port']['value'] = int(port)
		self.login = False
		return opts

	@staticmethod
	def on_line(self, line):
		# Conn
		conn = '[*]' in line
		if conn:
			line_content = line.split('[*]')[-1]
			match = STATUS_REGEX.match(line_content)
			if match:
				data = match.groupdict()
				yield Tag(
					category='info',
					name='mssql_info',
					match=self.full_target,
					value='',
					extra_data=data
				)

		# Login status
		info = '[+]' in line
		if info:
			line_content = line.split('[+]')[-1]
			match = LOGIN_SUCCESS_REGEX.match(line_content)
			if match:
				data = match.groupdict()
				status = data.get('status') or 'UNKNOWN'
				if status == 'Pwn3d!':
					status = 'SUCCESS'
				data['status'] = status
				yield Tag(
					category='info',
					match=self.full_target,
					name='mssql_login',
					value=status,
					extra_data=data,
					tags=['network', 'mssql', 'login'],
				)

		# Errors
		error = '[-]' in line or 'ERROR' in line
		if error:
			line_content = line.split('[-]')[-1]
			login_status = LOGIN_FAILED_REGEX.match(line_content)
			status = 'FAILED'
			if login_status:
				data = login_status.groupdict()
				data['status'] = status
				yield Tag(
					category='info',
					name='mssql_login',
					match=self.full_target,
					value=status,
					extra_data=data,
					tags=['network', 'mssql', 'login'],
				)
			else:
				if '[-]' in line:
					yield Warning(message=line.split('[-]')[-1].strip())
				else:
					yield Warning(message=line.split('ERROR')[-1].strip())

		yield line

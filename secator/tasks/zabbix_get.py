import os

from pathlib import Path

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, IP, SLUG, STRING
from secator.output_types import Vulnerability, Tag
from secator.runners import Command
from secator.utils import autodetect_type


HTTP_PROXY = os.environ.get('http_proxy')
HTTPS_PROXY = os.environ.get('https_proxy')


@task()
class zabbix_get(Command):
	"""Zabbix get is a command-line utility, which can be used to communicate with Zabbix agent and retrieve required information from the agent."""  # noqa: E501
	cmd = 'zabbix_get'
	install_cmd = (
	    'wget https://repo.zabbix.com/zabbix/7.4/release/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.4+ubuntu26.04_all.deb && '  # noqa: E501
	    'sudo dpkg -i zabbix-release_latest_7.4+ubuntu26.04_all.deb && '
	    'sudo apt update && '
	    'sudo apt install zabbix-get'
	)
	input_flag = '-s'
	file_flag = None
	input_chunk_size = 1
	input_types = [HOST, HOST_PORT, IP, SLUG, STRING]
	output_types = [Vulnerability, Tag]
	opts = {
		'key': {'type': str, 'default': r"system.run[ls]", 'help': 'Key of the item to retrieve value for (e.g: system.run with ls, or vfs.file.contents of a path)'},  # noqa: E501
		'zabbix_port': {'type': int, 'default': 10050, 'help': 'Zabbix agent port'}
	}
	opt_key_map = {
		'zabbix_port': 'p',
		'key': 'k'
	}
	ignore_return_code = True

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		self.full_target = self.inputs[0]
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.full_target = self.inputs[0]
			self.inputs[0] = host
			opts['zabbix_port']['value'] = int(port)
		return opts

	@staticmethod
	def on_cmd_done(self):
		key = self.get_opt_value('key')
		markers = ('zbx_notsupported', 'permission denied', 'connection error', 'get value error', 'check access restrictions')  # noqa: E501
		output_lower = self.output.lower()
		if self.return_code != 0 or not self.output.strip() or any(m in output_lower for m in markers):
			return
		if key.startswith('vfs.file.contents'):
			filepath = key.split('vfs.file.contents')[-1].rstrip(']').lstrip('[')
			yield Vulnerability(
				name='Zabbix - Local File Inclusion',
				description=(
					'It is possible to list folders and read files remotely using the Zabbix agent by using the official zabbix_get tool from the same editor. \n'  # noqa: E501
					'On the default Zabbix agent configuration, the "vfs.file.contents" key is disabled, which does not allow folder and file reads. \n'  # noqa: E501
					'This means that someone has modified the default server configuration so that this RCE becomes possible.'
				),
				impact=(
					'This can cause significant security risks which varies based on the user rights running the Zabbix agent:\n',
					'- Reading and exfiltrating files containing sensitive data (app and config files, environment variables, logs, SSH keys, certificates, ...)\n'  # noqa: E501
					'- Causing a Denial of Service\n'
					'- Executing custom code'
				),
				remediation=(
					'Disable remote command execution immediately in the Zabbix agent configuration by setting:\n'
					'- Setting `EnableRemoteCommands=0` (if Zabbix agent version < 5)\n'
					'- Adding an `AllowKey` whitelist in Zabbix agent configuration (see [instructions](https://www.zabbix.com/documentation/current/en/manual/config/items/restrict_checks)) (if Zabbix agent version >= 5.0+)'  # noqa: E501
				),
				cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
				cvss_score=7.5,
				severity='high',
				confidence='high',
				matched_at=self.full_target,
				extra_data={
					'key': key,
					'filepath': filepath
				},
				tags=['zabbix', 'lfi', 'vuln', 'unauth'],
			)
			safe_path = filepath.replace('/', '_')
			file_path = Path(self.reports_folder) / '.outputs' / f'{self.fqn}_{safe_path}'
			with file_path.open('w') as f:
				f.write(self.output)

		elif key.startswith('system.run'):
			cmd = key.split('system.run')[-1].rstrip(']').lstrip('[')
			yield Vulnerability(
				name='Zabbix - Remote Code Execution',
				description=(
					'It is possible to execute remote commands using the Zabbix agent by using the official zabbix_get tool from the same editor. \n'  # noqa: E501
					'On the default Zabbix agent configuration, the "system.run" key is disabled, which does not allow remote execution. \n'  # noqa: E501
					'This means that someone has modified the default server configuration so that this RCE becomes possible.'
				),
				impact=(
					'This can cause significant security risks which varies based on the user rights running the Zabbix agent:\n',
					'- Reading and exfiltrating files containing sensitive data (app and config files, environment variables, logs, SSH keys, certificates, ...)\n'  # noqa: E501
					'- Causing a Denial of Service\n'
					'- Executing custom code'
				),
				remediation=(
					'Disable remote command execution immediately in the Zabbix agent configuration by setting:\n'
					'- Setting `EnableRemoteCommands=0` (if Zabbix agent version < 5)\n'
					'- Adding an `AllowKey` whitelist in Zabbix agent configuration (see [instructions](https://www.zabbix.com/documentation/current/en/manual/config/items/restrict_checks)) (if Zabbix agent version >= 5.0+)'  # noqa: E501
				),
				cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
				cvss_score=9.8,
				severity='critical',
				confidence='high',
				matched_at=self.full_target,
				extra_data={
					'key': key,
					'command': cmd,
				},
				tags=['zabbix', 'rce', 'vuln', 'unauth'],
			)
			yield Tag(
				category='secret',
				name='Zabbix remote code execution output',
				value='\n' + self.output,
				match=self.full_target,
				extra_data={
					'command': cmd
				},
			)

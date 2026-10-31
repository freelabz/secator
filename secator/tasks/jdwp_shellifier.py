from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST, IP, OPT_NOT_SUPPORTED, HOST_PORT
from secator.output_types import Info, Vulnerability, Warning
from secator.tasks._categories import Vuln
from secator.utils import autodetect_type


# Detection-only default. Open JDWP = unauthenticated RCE, and the
# handshake + version query (done before any breakpoint) already proves that.
# Pointing --break-on at a class the target will never load makes jdwp-shellifier
# do the handshake, leak the JVM version, then bail out fast (return False) instead
# of blocking forever waiting for a breakpoint to fire. Override `break_on` (+ set
# `exec_cmd`) if you actually want to exploit.
DETECT_BREAK_ON = 'secator.detect.JdwpProbe.probe'


@task()
class jdwp_shellifier(Vuln):
	"""Detect an exposed Java Debug Wire Protocol (JDWP) service (unauthenticated RCE)."""

	cmd = 'jdwp-shellifier'
	max_timeout = 120
	input_types = [HOST, IP, HOST_PORT]
	output_types = [Vulnerability]
	tags = ['jdwp', 'java', 'rce', 'exposure']
	input_flag = '-t'
	input_chunk_size = 1
	file_flag = None
	version_flag = OPT_NOT_SUPPORTED
	ignore_return_code = True
	meta_opts = {}  # jdwp-shellifier takes none of the standard http/proxy/thread opts
	opts = {
		'jdwp_port': {'type': int, 'short': 'p', 'default': 8000, 'help': 'JDWP port'},
		'break_on': {'type': str, 'default': None, 'help': 'Java method to break on (detection sentinel by default)'},  # noqa: E501
		'exec_cmd': {'type': str, 'default': None, 'help': 'Command to execute remotely (exploitation — off by default)'},  # noqa: E501
	}
	opt_key_map = {
		'jdwp_port': '-p',
		'break_on': '--break-on',
		'exec_cmd': '--cmd',
	}
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	install_version = 'master'
	# IOActive's jdwp-shellifier.py is Python 2; hugsy's fork is the maintained Python 3 port. All deps are stdlib.
	install_cmd = (
		f'git clone --depth 1 --single-branch -b [install_version] https://github.com/hugsy/jdwp-shellifier.git {CONFIG.dirs.share}/jdwp-shellifier_[install_version] || true && '  # noqa: E501
		f'chmod +x {CONFIG.dirs.share}/jdwp-shellifier_[install_version]/jdwp-shellifier.py && '
		f'ln -sf {CONFIG.dirs.share}/jdwp-shellifier_[install_version]/jdwp-shellifier.py {CONFIG.dirs.bin}/jdwp-shellifier'
	)
	install_github_bin = False
	github_handle = 'hugsy/jdwp-shellifier'
	profile = 'small'

	@staticmethod
	def on_cmd(self):
		self._handshake_ok = False
		self._jvm = {}
		self._warnings = []
		host = self.inputs[0] if self.inputs else ''
		port = self.get_opt_value('jdwp_port') or 8000
		self._matched_at = f'{host}:{port}'

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.full_target = self.inputs[0]
			self.inputs[0] = host
			opts['jdwp_port']['value'] = int(port)
		return opts

	@staticmethod
	def on_line(self, line):
		stripped = line.strip()
		if 'Handshake successful' in stripped:
			self._handshake_ok = True
			yield Info(message=f'JDWP handshake succeeded on {self._matched_at} — service is exposed')
			return
		# Version info lines look like: "\t• vmVersion: 1.8.0_212"
		if '•' in stripped and ':' in stripped:
			key, _, val = stripped.partition('•')[2].partition(':')
			key, val = key.strip(), val.strip()
			if key:
				self._jvm[key] = val
			return
		start_chars = ('[-] ', '[!] ', '[x] ')
		if stripped.startswith(start_chars):
			for char in start_chars:
				stripped = stripped.lstrip(char)
			warning = Warning(message=stripped)
			self._warnings.append(warning.message)
			yield warning
			return
		if stripped.startswith(('[+]', '[*]')):
			yield Info(message=stripped)
			return
		yield line

	@staticmethod
	def on_cmd_done(self):
		if not self._handshake_ok:
			yield Warning(message=f'No JDWP handshake on {self._matched_at} — service not exposed or unreachable')
			return
		yield Vulnerability(
			name='JDWP - Unauthenticated Access',
			matched_at=self._matched_at,
			provider='jdwp_shellifier',
			severity='critical',
			confidence='high',
			cvss_score=9.8,
			cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
			description='JDWP (Java Debug Wire Protocol) exposed to the network lets any client attach to the JVM and run arbitrary Java/OS commands with the JVM\'s privileges — no authentication.',  # noqa: E501
			impact='Full remote code execution on the host as the JVM user; data theft and lateral movement.',
			remediation='Never expose JDWP to untrusted networks; bind the debug agent to localhost; disable debug agents in production; firewall the debug port.',  # noqa: E501
			references=['https://github.com/IOActive/jdwp-shellifier'],
			tags=['jdwp', 'java', 'rce', 'exposure', 'unauth'],
			extra_data={'jvm_version': self._jvm.get('vmVersion') or self._jvm.get('description') or 'unknown', 'handshake': True, 'warnings': self._warnings},  # noqa: E501
		)

import re

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import URL
from secator.output_types import Info, Vulnerability, Warning
from secator.tasks._categories import Vuln


DRG_REPO_REGEX = re.compile(r'^\[\+\]\s+(\S+)\s*$')
DRG_ERROR_REGEX = re.compile(r'(Http Error|Error Connecting|Timeout Error|Unauthorized|Authentication failed)', re.I)


@task()
class dockerregistrygrabber(Vuln):
	"""Exposed Docker registries enumeration."""

	cmd = 'drg.py'
	input_chunk_size = 1
	input_types = [URL]
	output_types = [Vulnerability]
	tags = ['docker', 'registry', 'exposure']
	input_flag = None  # target URL is a positional argument
	version_flag = None
	meta_opts = {}  # drg.py accepts none of secator's standard HTTP/recon opts
	ignore_return_code = True
	opts = {
		'docker_port': {'type': int, 'short': 'p', 'default': 5000, 'help': 'Registry port (default: 5000)'},
		'docker_username': {'type': str, 'default': None, 'help': 'Docker registry username'},
		'docker_password': {'type': str, 'default': None, 'help': 'Docker registry password'},
		'docker_token': {'type': str, 'default': None, 'help': 'Docker registry authorization bearer token'},
		'list': {'is_flag': True, 'default': True, 'help': 'List all images'},
		'dump': {'type': str, 'default': None, 'help': 'Dump image locally'},
		'dump_all': {'is_flag': True, 'default': False, 'help': 'Dump all images locally'},
	}
	opt_key_map = {
		'list': '--list',
		'docker_port': '-p',
		'docker_username': '-U',
		'docker_password': '-P',
		'docker_token': '-A',
		'dump': '--dump',
		'dump_all': '--dump-all'
	}
	install_version = 'main'
	install_github_bin = False
	github_handle = 'Syzik/DockerRegistryGrabber'
	pypi_dependencies = ['requests', 'rich', 'urllib3']
	install_cmd = (
		f'git clone --depth 1 --single-branch https://github.com/Syzik/DockerRegistryGrabber.git {CONFIG.dirs.share}/DockerRegistryGrabber || true && '  # noqa: E501
		f'ln -sf {CONFIG.dirs.share}/DockerRegistryGrabber/drg.py {CONFIG.dirs.bin}/drg.py'
	)
	proxychains = False
	proxy_socks5 = False
	proxy_http = False

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		if self.inputs:
			split = self.inputs[0].split(':')
			if len(split) == 3:  # port is in URL
				url_wo_port = ':'.join([split[0], split[1]])
				self.cmd = self.cmd.replace(self.inputs[0], url_wo_port)
				self.full_target = self.inputs[0]
				self.inputs[0] = url_wo_port
				opts['docker_port']['value'] = int(split[2])
		return opts

	@staticmethod
	def on_start(self):
		self._repos = []

	@staticmethod
	def on_line(self, line):
		match = DRG_REPO_REGEX.match(line.strip())
		if match:
			repo = match.group(1)
			if repo not in self._repos:
				self._repos.append(repo)
			yield Info(message=f'Found repository: {repo}')
			return
		if DRG_ERROR_REGEX.search(line):
			yield Warning(message=line.strip())
			return
		yield line

	@staticmethod
	def on_cmd_done(self):
		# Only emit the finding when the registry actually answered as an open v2 registry
		if not self._repos:
			return
		host = self.inputs[0] if self.inputs else ''
		port = self.get_opt_value('docker_port') or 5000
		matched_at = f'{host}:{port}'
		yield Info(message=f'Exposed unauthenticated Docker registry at {matched_at} ({len(self._repos)} repositories)')
		yield Vulnerability(
			name='Docker Registry - Unauthenticated Access',
			matched_at=matched_at,
			provider='dockerregistrygrabber',
			severity='high',
			confidence='high',
			cvss_score=7.5,
			cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
			description=(
				'The Docker Registry v2 API at this host is readable anonymously (no authentication). '
				'An open registry leaks every hosted image and its layers, which frequently embed application '
				'source code, hardcoded secrets, API keys and cloud credentials.'
			),
			impact=(
				'Disclosure of source code, secrets and credentials baked into image layers. If the registry '
				'also accepts anonymous pushes, images can be tampered with for a supply-chain attack.'
			),
			remediation=(
				'Require authentication (htpasswd/token auth) and TLS on the registry, restrict it with a firewall '
				'or private network, and never expose port 5000 publicly.'
			),
			references=['https://github.com/Syzik/DockerRegistryGrabber'],
			tags=['docker', 'registry', 'exposure', 'unauth'],
			extra_data={
				'repositories': self._repos,
				'count': len(self._repos),
			},
		)

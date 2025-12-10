import re

from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT,
								 HEADER, METHOD,
								 OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
								 RETRIES, THREADS, TIMEOUT, URL,
								 USER_AGENT)
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnHttp

SQLMAP_SEVERITY_MAP = {
	1: 'low',
	2: 'medium',
	3: 'high'
}


@task()
class sqlmap(VulnHttp):
	"""Automatic SQL injection and database takeover tool."""
	cmd = 'sqlmap'
	input_types = [URL]
	output_types = [Vulnerability]
	tags = ['url', 'vuln', 'sqli']
	input_flag = '-u'
	file_flag = '-m'
	input_chunk_size = 1
	ignore_return_code = True
	version_flag = '--version'
	opt_prefix = '--'
	opts = {
		'batch': {'is_flag': True, 'default': True, 'help': 'Never ask for user input, use default behavior'},
		'level': {'type': int, 'default': 1, 'help': 'Level of tests to perform (1-5, default: 1)'},
		'risk': {'type': int, 'default': 1, 'help': 'Risk of tests to perform (1-3, default: 1)'},
		'technique': {'type': str, 'help': 'SQL injection techniques to use (default: BEUSTQ)'},
		'dbms': {'type': str, 'help': 'Force back-end DBMS to provided value'},
		'os': {'type': str, 'help': 'Force back-end DBMS operating system to provided value'},
		'tamper': {'type': str, 'help': 'Use given script(s) for tampering injection data'},
		'random_agent': {'is_flag': True, 'default': False, 'help': 'Use randomly selected HTTP User-Agent header value'},
		'flush_session': {'is_flag': True, 'default': False, 'help': 'Flush session files for current target'},
		'fresh_queries': {'is_flag': True, 'default': False, 'help': 'Ignore cached results'},
		'forms': {'is_flag': True, 'default': False, 'help': 'Parse and test forms on target URL'},
		'crawl': {'type': int, 'help': 'Crawl the website starting from the target URL'},
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent'
	}
	install_version = '1.8.2'
	install_cmd = 'pipx install sqlmap-tool==[install_version] --force'
	install_github_bin = False
	github_handle = 'sqlmapproject/sqlmap'
	encoding = 'ansi'
	proxychains = False
	proxychains_flavor = 'proxychains4'
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_init(self):
		self.current_url = None
		self.current_param = None
		self.current_type = None
		self.current_title = None
		self.current_payload = None
		self.current_dbms = None
		self.vuln_found = False
		self.risk_level = self.get_opt_value('risk') or 1
		self._yielded_vulns = set()
		self._vuln_buffer = None

	@staticmethod
	def item_loader(self, line):
		# Parse sqlmap output for vulnerability information
		if 'testing connection' in line.lower():
			return ''

		# Extract URL being tested
		url_match = re.search(r'testing (?:if )?(?:the )?URL[\'"]?\s+[\'"]?([^\'"]+)[\'"]?', line, re.IGNORECASE)
		if url_match:
			self.current_url = url_match.group(1)

		# Extract parameter being tested - format: "Parameter: id (GET)"
		param_match = re.search(r'^Parameter:\s+(\S+)\s+\(([^)]+)\)', line)
		if param_match:
			self.current_param = param_match.group(1)
			# Starting a new vulnerability block, reset
			self._vuln_buffer = {
				'param': self.current_param,
				'param_type': param_match.group(2)
			}
			return line

		# Extract injection type - appears with leading whitespace in block
		type_match = re.search(r'^\s+Type:\s+(.+)', line)
		if type_match and self._vuln_buffer:
			injection_type = type_match.group(1).strip()
			# If we already have data buffered, yield it first
			if 'type' in self._vuln_buffer and 'title' in self._vuln_buffer:
				yield from self._yield_vulnerability()
			# Start new vuln in buffer
			self._vuln_buffer['type'] = injection_type
			return line

		# Extract title - appears with leading whitespace in block
		title_match = re.search(r'^\s+Title:\s+(.+)', line)
		if title_match and self._vuln_buffer:
			self._vuln_buffer['title'] = title_match.group(1).strip()
			return line

		# Extract payload - appears with leading whitespace in block
		payload_match = re.search(r'^\s+Payload:\s+(.+)', line)
		if payload_match and self._vuln_buffer:
			self._vuln_buffer['payload'] = payload_match.group(1).strip()
			# We have complete info, yield the vulnerability
			yield from self._yield_vulnerability()
			return line

		# Extract DBMS
		dbms_match = re.search(r'back-end DBMS:\s+(.+)', line, re.IGNORECASE)
		if dbms_match:
			self.current_dbms = dbms_match.group(1).strip()

		return line

	def _yield_vulnerability(self):
		"""Helper to yield a vulnerability from the buffer."""
		if not self._vuln_buffer or 'type' not in self._vuln_buffer or 'title' not in self._vuln_buffer:
			return

		vuln_key = f"{self.current_param}:{self._vuln_buffer['type']}"
		if vuln_key in self._yielded_vulns:
			return

		self._yielded_vulns.add(vuln_key)

		severity = SQLMAP_SEVERITY_MAP.get(self.risk_level, 'medium')
		extra_data = {
			'injection_type': self._vuln_buffer['type'],
			'parameter': self.current_param,
			'parameter_type': self._vuln_buffer.get('param_type', 'unknown')
		}
		if 'payload' in self._vuln_buffer:
			extra_data['payload'] = self._vuln_buffer['payload']
		if self.current_dbms:
			extra_data['dbms'] = self.current_dbms

		yield Vulnerability(
			id=None,
			name='SQL Injection - ' + self._vuln_buffer['title'],
			provider='sqlmap',
			tags=['sqli', 'CWE-89'],
			confidence='high',
			matched_at=self.current_url or self.inputs[0],
			extra_data=extra_data,
			severity=severity
		)

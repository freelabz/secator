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
		self.risk_level = self.get_opt_value('risk', default=1)

	@staticmethod
	def on_line(self, line):
		# Parse sqlmap output for vulnerability information
		if 'testing connection' in line.lower():
			return ''

		# Extract URL being tested
		url_match = re.search(r'testing (?:if )?(?:the )?URL[\'"]?\s+[\'"]?([^\'"]+)[\'"]?', line, re.IGNORECASE)
		if url_match:
			self.current_url = url_match.group(1)

		# Extract parameter being tested
		param_match = re.search(r'[Pp]arameter:\s+([^\s]+)\s+', line)
		if param_match:
			self.current_param = param_match.group(1)
			self.vuln_found = False  # Reset for new parameter

		# Extract injection type
		type_match = re.search(r'Type:\s+(.+)', line)
		if type_match:
			self.current_type = type_match.group(1).strip()

		# Extract title
		title_match = re.search(r'Title:\s+(.+)', line)
		if title_match:
			self.current_title = title_match.group(1).strip()

		# Extract payload
		payload_match = re.search(r'Payload:\s+(.+)', line)
		if payload_match:
			self.current_payload = payload_match.group(1).strip()

		# Extract DBMS
		dbms_match = re.search(r'back-end DBMS:\s+(.+)', line, re.IGNORECASE)
		if dbms_match:
			self.current_dbms = dbms_match.group(1).strip()

		# Check if parameter is vulnerable
		if 'appears to be vulnerable' in line.lower() or 'is vulnerable' in line.lower():
			self.vuln_found = True

		# Check if we have all info to yield a vulnerability
		if self.vuln_found and self.current_param and self.current_type and self.current_title:
			if not hasattr(self, '_yielded_vulns'):
				self._yielded_vulns = set()

			vuln_key = f"{self.current_url}:{self.current_param}:{self.current_type}"
			if vuln_key not in self._yielded_vulns:
				self._yielded_vulns.add(vuln_key)

				severity = SQLMAP_SEVERITY_MAP.get(self.risk_level, 'medium')
				extra_data = {
					'injection_type': self.current_type,
					'parameter': self.current_param,
				}
				if self.current_payload:
					extra_data['payload'] = self.current_payload
				if self.current_dbms:
					extra_data['dbms'] = self.current_dbms

				yield Vulnerability(
					id=None,
					name=self.current_title or f'SQL Injection ({self.current_type})',
					provider='sqlmap',
					tags=['sqli', 'CWE-89'],
					confidence='high',
					matched_at=self.current_url or '',
					extra_data=extra_data,
					severity=severity
				)

				# Reset some fields but keep current_url and current_param for next potential vuln
				self.current_type = None
				self.current_title = None
				self.current_payload = None
				self.vuln_found = False

		return line

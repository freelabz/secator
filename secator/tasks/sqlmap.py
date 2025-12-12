import re
from telnetlib import IP

from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT,
								 HEADER, METHOD,
								 OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
								 RETRIES, THREADS, TIMEOUT, URL,
								 USER_AGENT)
from secator.output_types import Info, Warning, Error, Vulnerability, Tag, UserAccount, Ip
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
	output_types = [Vulnerability, Tag, Ip, UserAccount]
	tags = ['url', 'vuln', 'sqli']
	input_flag = '-u'
	file_flag = '-m'
	input_chunk_size = 1
	# ignore_return_code = True
	version_flag = '--version'
	opt_prefix = '--'
	opts = {
		# Target
		'google_dork': {'type': str, 'help': 'Google dork to use for search'},

		# Request
		'data': {'type': str, 'help': 'Data string to send along with the request'},
		'cookie': {'type': str, 'help': 'HTTP Cookie header value (e.g: "PHPSESSID=a1b2c3d4e5f6")'},
		'random_agent': {'is_flag': True, 'default': False, 'help': 'Use randomly selected HTTP User-Agent header value'},

		# Injection
		'test_parameters': {'type': str, 'help': 'Testable parameter(s)'},
		'dbms': {'type': str, 'help': 'Force back-end DBMS to provided value'},

		# Detection
		'level': {'type': int, 'help': 'Level of tests to perform (1-5, default: 1)'},
		'risk': {'type': int, 'help': 'Risk of tests to perform (1-3, default: 1)'},

		# Techniques
		'technique': {'type': str, 'help': 'SQL injection techniques to use (default: BEUSTQ)'},

		# Enumeration
		'all': {'is_flag': True, 'default': False, 'help': 'Retrieve everything'},
		'banner': {'is_flag': True, 'default': False, 'help': 'Retrieve DBMS banner'},
		'current_user': {'is_flag': True, 'default': False, 'help': 'Retrieve DBMS current user'},
		'current_db': {'is_flag': True, 'default': False, 'help': 'Retrieve DBMS current database'},
		'passwords': {'type': str, 'help': 'Enumerate DBMS user password hashes'},
		'dbs': {'is_flag': True, 'default': False, 'help': 'Enumerate DBMS databases'},
		'tables': {'type': str, 'help': 'Enumerate DBMS tables'},
		'columns': {'type': str, 'help': 'Enumerate DBMS columns'},
		'schema': {'type': str, 'help': 'Enumerate DBMS schema'},
		'dump': {'is_flag': True, 'default': False, 'help': 'Dump DBMS database table entries'},
		'dump_all': {'is_flag': True, 'default': False, 'help': 'Dump all DBMS database table entries'},
		'database': {'type': str, 'help': 'DBMS database to enumerate'},
		'table': {'type': str, 'help': 'DBMS table to enumerate'},
		'column': {'type': str, 'help': 'DBMS column to enumerate'},

		# General
		'batch': {'is_flag': True, 'default': True, 'help': 'Never ask for user input, use default behavior'},
	}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
		'google_dork': '-g',
		'database': '-D',
		'table': '-T',
		'column': '-C',
	}
	install_version = '1.8.2'
	install_pre = {'*': ['sqlmap']}
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
	def on_cmd(self):
		threads = self.get_opt_value('threads')
		if threads is not None and int(threads) > 10:
			self.add_result(Info(message='Threads should be less than 10 to avoid potential connection issues. Setting threads to 10.'))
			self.cmd = self.cmd.replace(f' --threads {threads}', ' --threads 10	')
		return self.cmd

	@staticmethod
	def item_loader(self, line):
		self.current_url = self.inputs[0]
		# Parse sqlmap output for vulnerability information
		if 'testing connection' in line.lower():
			return ''
		if '[INFO]' in line:
			if not 'current status: ' in line:
				self.add_result(Info(message=line.split('[INFO]')[1].strip()))
			return line
		if '[WARNING]' in line:
			self.add_result(Warning(message=line.split('[WARNING]')[1].strip()))
			return line
		if '[ERROR]' in line:
			self.add_result(Error(message=line.split('[ERROR]')[1].strip()))
			return line
		if '[CRITICAL]' in line:
			self.add_result(Error(message=line.split('[CRITICAL]')[1].strip() + ' [CRITICAL]'))
			return line
		if 'web server operating system' in line.lower():
			os = line.split('web server operating system: ')[1].strip()
			yield Tag(
				category='info',
				name='os',
				match=self.current_url,
				value=os,
				extra_data={'context': 'webserver'}
			)
			return line
		if 'web application technology' in line.lower():
			techs = line.split('web application technology: ')[1].split(', ')
			for tech in techs:
				product, version = self.find_product_version(tech)
				yield Tag(
					category='info',
					name='tech',
					match=self.current_url,
					value=tech,
					extra_data={'product': product, 'version': version}
				)
			return line
		if 'back-end DBMS operating system' in line:
			os = line.split('back-end DBMS operating system: ')[1].strip()
			yield Tag(
				category='info',
				name='os',
				match=self.current_url,
				value=os,
				extra_data={'context': 'dbms'}
			)
			return line
		if 'back-end DBMS:' in line:
			product, version = self.find_product_version(line.split('back-end DBMS: ')[1].strip())
			self.current_dbms = line.split('back-end DBMS: ')[1].strip()
			yield Tag(
				category='info',
				name='tech',
				match=self.current_url,
				value=f'{product} {version}',
				extra_data={'product': product, 'version': version, 'dbms': self.current_dbms}
			)
			return line
		if 'current user:' in line.lower():
			yield UserAccount(
				username=line.split('current user: ')[1].strip("'").strip(),
				site_name=self.current_url.split('://')[1].split('/')[0] + ':' + self.current_dbms,
				extra_data={'dbms': self.current_dbms, 'context': 'database_user'}
			)
			return line
		if 'current database' in line.lower():
			yield Tag(
				category='info',
				name='database_name',
				match=self.current_url,
				value=line.split('current database: ')[1].strip(),
				extra_data={'dbms': self.current_dbms}
			)
			return line
		if 'hostname:' in line.lower():
			ip = '.'.join(line.split('hostname: ')[1].strip().replace('ip-', '').split('-')).strip("'")
			yield Ip(
				ip=ip,
				host=self.current_url.split('://')[1].split('/')[0],
				alive=True
			)
			return line

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

		return Info(message=line)

	@staticmethod
	def find_product_version(tech):
		version = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', tech)
		if version:
			tech = tech.replace(version.group(1), '')
			tech = tech.strip()
			version = version.group(1)
			product = tech.replace(version, '').strip()
		else:
			product = tech.strip()
			version = ''
		return product, version

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

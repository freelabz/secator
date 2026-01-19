import re
import validators

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
								FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
								HEADER, HOST, MATCH_CODES, MATCH_REGEX,
								MATCH_SIZE, MATCH_WORDS, METHOD,
								OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
								RETRIES, THREADS, TIMEOUT, USER_AGENT,
								WORDLIST, URL, CONTENT_LENGTH, STATUS_CODE)
from secator.output_types import Subdomain, Url, Record, Info
from secator.tasks._categories import HttpFuzzer, ReconDns
from secator.utils import extract_domain_info


@task()
class gobuster(HttpFuzzer, ReconDns):
	"""Directory/File, DNS and VHost busting tool written in Go."""
	cmd = 'gobuster'
	input_types = [URL, HOST]
	output_types = [Url, Subdomain, Record]
	tags = ['url', 'fuzz', 'dns', 'recon']
	input_flag = None  # Set dynamically based on mode
	file_flag = None
	opt_prefix = '--'
	opts = {
		'mode': {'type': str, 'default': 'dns', 'internal': True, 'help': 'Gobuster mode (dns, dir, vhost, fuzz, s3, gcs, tftp)'},
		'extensions': {'type': str, 'short': 'x', 'help': 'File extension(s) to search for (dir mode)'},
		'expanded': {'is_flag': True, 'short': 'e', 'default': False, 'help': 'Expanded mode, print full URLs (dir mode)'},
		'no_status': {'is_flag': True, 'short': 'n', 'default': False, 'help': 'Do not print status codes (dir mode)'},
		'hide_length': {'is_flag': True, 'default': False, 'help': 'Hide the length of the body in the output (dir mode)'},
		'add_slash': {'is_flag': True, 'short': 'f', 'default': False, 'help': 'Append / to each request (dir mode)'},
		'discover_backup': {'is_flag': True, 'default': False, 'help': 'Upon finding a file search for backup files (dir mode)'},
		'exclude_length': {'type': str, 'help': 'Exclude the following content lengths (dir mode)'},
		'check_cname': {'is_flag': True, 'short': 'c', 'default': False, 'help': 'Also check CNAME records (dns mode)'},
		'wildcard': {'is_flag': True, 'default': False, 'help': 'Force continued operation when wildcard found (dns mode)'},
		'no_fqdn': {'is_flag': True, 'default': False, 'help': 'Do not automatically add a trailing dot to the domain (dns mode)'},
		'resolver': {'type': str, 'help': 'Use custom DNS server (dns mode)'},
	}
	opt_key_map = {
		#HEADER: 'headers', # supported only in dns mode
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'delay',
		DEPTH: OPT_NOT_SUPPORTED,
		FILTER_CODES: 'status-codes-blacklist',
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirect',
		MATCH_CODES: 'status-codes',
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		METHOD: 'method',
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'useragent',
		WORDLIST: 'wordlist',
	}
	encoding = 'ansi'
	install_version = 'v3.8.2'
	install_cmd = 'go install -v github.com/OJ/gobuster/v3@[install_version]'
	github_handle = 'OJ/gobuster'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def before_init(self):
		mode = self.get_opt_value('mode', 'dns')
		
		# Update the base command with the mode
		self.cmd = f'gobuster {mode}'
		
		# Set input flag based on mode
		if mode == 'dns':
			self.input_flag = '--domain'
		elif mode == 'dir':
			self.input_flag = '--url'
		elif mode == 'vhost':
			self.input_flag = '--url'
		elif mode == 'fuzz':
			self.input_flag = '--url'
		elif mode in ['s3', 'gcs']:
			self.input_flag = None  # These modes don't use input flag
		elif mode == 'tftp':
			self.input_flag = '--server'
		
	@staticmethod
	def on_cmd_opts(self, opts):
		if self.get_opt_value('wordlist') == 'http':
			self.add_result(Info(message='Changing wordlist to combined_subdomains as the default http wordlist is not suitable for fuzzing host header'))  # noqa: E501
			opts['wordlist']['value'] = 'combined_subdomains'
		return opts

	@staticmethod
	def on_line(self, line):
		"""Parse gobuster output line by line."""
		if not line or line.startswith('==============='):
			return line
		if line.startswith('[+]') or line.startswith('[-]') or line.startswith('[INFO]'):
			return line
		
		mode = self.get_opt_value('mode', 'dns')
		
		if mode == 'dns':
			# DNS mode output: "subdomain.example.com"
			# or with IPs: "subdomain.example.com [192.168.1.1, 192.168.1.2]"
			match = re.match(r'^([a-zA-Z0-9\.\-_]+)(?:\s+\[([^\]]+)\])?', line)
			if match:
				subdomain_host = match.group(1)
				ips = match.group(2)
				
				domain = extract_domain_info(subdomain_host, domain_only=False)
				result = {
					'_type': 'subdomain',
					'host': subdomain_host,
					'domain': str(domain),
					'verified': True,
					'sources': ['dns'],
				}
				
				if ips:
					result['extra_data'] = {'ips': [ip.strip() for ip in ips.split(',')]}
				
				return Subdomain(**result)
		
		elif mode == 'dir':
			# Dir mode output: "/admin               (Status: 200) [Size: 1234]"
			# or expanded: "http://example.com/admin (Status: 200) [Size: 1234]"
			match = re.match(r'^(https?://[^\s]+|/[^\s]*)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?', line)
			if match and validators.url(match):
				path_or_url = match.group(1)
				status_code = int(match.group(2))
				size = int(match.group(3)) if match.group(3) else None
				
				# If it's a path, construct full URL
				if not path_or_url.startswith('http'):
					# Get the base URL from inputs
					base_url = self.inputs[0] if len(self.inputs) > 0 else ''
					url = base_url.rstrip('/') + path_or_url
				else:
					url = path_or_url
				
				result = {
					'_type': 'url',
					'url': url,
					'status_code': status_code,
					'method': self.get_opt_value(METHOD) or 'GET',
				}
				
				if size is not None:
					result['content_length'] = size
				
				return Url(**result)
		
		elif mode == 'vhost':
			# VHost mode output: "Found: subdomain.example.com (Status: 200) [Size: 1234]"
			match = re.match(r'^([^\s]+)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?', line)
			if match:
				vhost = match.group(1)
				status_code = int(match.group(2))
				size = int(match.group(3)) if match.group(3) else None
				
				# Get the base URL from inputs
				base_url = self.inputs[0] if len(self.inputs) > 0 else ''
				
				result = {
					'_type': 'subdomain',
					'host': vhost,
					'domain': extract_domain_info(vhost, domain_only=True),
					'verified': False,
					'sources': ['vhost'],
					'extra_data': {
						'status_code': status_code,
						'base_url': base_url
					}
				}
				
				if size is not None:
					result['extra_data']['size'] = size	
				return Subdomain(**result)
		
		return line


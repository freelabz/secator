from urllib.parse import urlparse

from secsy.decorators import task
from secsy.definitions import (CONFIDENCE, DELAY, EXTRA_DATA, FOLLOW_REDIRECT,
							   HEADER, ID, MATCHED_AT, METHOD, NAME,
							   OPT_NOT_SUPPORTED, PROVIDER, PROXY, RATE_LIMIT,
							   SEVERITY, TAGS, THREADS, TIMEOUT, URL,
							   USER_AGENT, DEFAULT_SOCKS5_PROXY)
from secsy.output_types import Vulnerability
from secsy.tasks._categories import VulnHttp

DALFOX_TYPE_MAP = {
	'G': 'Grep XSS',
	'R': 'Reflected XSS',
	'V': 'Verified XSS'
}


@task()
class dalfox(VulnHttp):
	"""Powerful open source XSS scanning tool."""
	cmd = 'dalfox --silence'
	input_type = URL
	input_flag = 'url'
	file_flag = 'file'
	json_flag = '--format json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		FOLLOW_REDIRECT: 'follow-redirects',
		METHOD: 'method',
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		THREADS: 'worker',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent'
	}
	output_map = {
		Vulnerability: {
			ID: lambda x: None,
			NAME: lambda x: DALFOX_TYPE_MAP[x['type']],
			PROVIDER: 'dalfox',
			TAGS: lambda x: [x['cwe']] if x['cwe'] else [],
			CONFIDENCE: lambda x: 'high',
			MATCHED_AT: lambda x: urlparse(x['data'])._replace(query='').geturl(),
			EXTRA_DATA: lambda x: {
				k: v for k, v in x.items()
				if k not in ['type', 'severity', 'cwe']
			},
			SEVERITY: lambda x: x['severity'].lower()
		}
	}
	install_cmd = 'go install -v github.com/hahwul/dalfox/v2@latest'
	encoding = 'ansi'
	proxychains = True
	proxychains_flavor = 'proxychains4'

	@staticmethod
	def on_init(self):
		proxy = self.get_opt_value('proxy')
		if proxy == 'proxychains' and DEFAULT_SOCKS5_PROXY:
			self.run_opts['proxy'] = DEFAULT_SOCKS5_PROXY

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line

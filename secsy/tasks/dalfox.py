from urllib.parse import urlparse

from secsy.definitions import (DELAY, FOLLOW_REDIRECT, HEADER, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, THREADS,
							   TIMEOUT, URL, USER_AGENT, VULN_CONFIDENCE,
							   VULN_EXTRACTED_RESULTS, VULN_ID,
							   VULN_MATCHED_AT, VULN_NAME, VULN_PROVIDER,
							   VULN_SEVERITY, VULN_TAGS)
from secsy.output_types import Vulnerability
from secsy.tasks._categories import VulnCommand


class dalfox(VulnCommand):
	"""Powerful open source XSS scanning tool."""
	cmd = 'dalfox'
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
			VULN_ID: 'XSS Injection',
			VULN_NAME: 'XSS Injection',
			VULN_PROVIDER: 'dalfox',
			VULN_TAGS: lambda x: [x['cwe']],
			VULN_CONFIDENCE: lambda x: 'high',
			VULN_MATCHED_AT: lambda x: urlparse(x['data'])._replace(query='').geturl(),
			VULN_EXTRACTED_RESULTS: lambda x: {
				k: v for k, v in x.items()
				if k not in ['type', 'severity', 'cwe']
			},
			VULN_SEVERITY: lambda x: x['severity'].lower()
		}
	}
	install_cmd = 'go install -v github.com/hahwul/dalfox/v2@latest'

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line

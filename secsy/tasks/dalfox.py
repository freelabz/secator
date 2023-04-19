from urllib.parse import urlparse

from secsy.decorators import task
from secsy.definitions import (DELAY, FOLLOW_REDIRECT, HEADER, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, THREADS,
							   TIMEOUT, URL, USER_AGENT, VULN_CONFIDENCE,
							   VULN_EXTRACTED_RESULTS, ID,
							   VULN_MATCHED_AT, NAME, PROVIDER,
							   VULN_SEVERITY, TAGS)
from secsy.output_types import Vulnerability
from secsy.tasks._categories import VulnHttp


DALFOX_TYPE_MAP = {
	'G': 'grep',
	'R': 'reflected',
	'V': 'verify'
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
	encoding = 'ansi'

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line

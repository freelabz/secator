from urllib.parse import urlparse

from secsy.definitions import *
from secsy.tasks._categories import VulnCommand


class dalfox(VulnCommand):
	"""DalFox is a powerful open source XSS scanning tool."""
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
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent'
	}
	output_map = {
		VULN_ID: 'XSS Injection',
		VULN_NAME: 'XSS Injection',
		VULN_PROVIDER: 'dalfox',
		VULN_TAGS: lambda x: [x['cwe']],
		VULN_CONFIDENCE: 'high',
		VULN_MATCHED_AT: lambda x: urlparse(x['data'])._replace(query='').geturl(),
		VULN_EXTRACTED_RESULTS: lambda x: {
			k: v for k, v in x.items()
			if k not in ['type', 'severity', 'cwe']
		},
		VULN_SEVERITY: lambda x: x['severity'].lower()
	}

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line
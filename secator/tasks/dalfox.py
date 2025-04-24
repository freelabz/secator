from urllib.parse import urlparse

from secator.decorators import task
from secator.definitions import (CONFIDENCE, DELAY, EXTRA_DATA, FOLLOW_REDIRECT,
							   HEADER, ID, MATCHED_AT, METHOD, NAME,
							   OPT_NOT_SUPPORTED, PROVIDER, PROXY, RATE_LIMIT,
							   SEVERITY, TAGS, THREADS, TIMEOUT, URL,
							   USER_AGENT)
from secator.output_types import Vulnerability
from secator.serializers import JSONSerializer
from secator.tasks._categories import VulnHttp

DALFOX_TYPE_MAP = {
	'G': 'Grep XSS',
	'R': 'Reflected XSS',
	'V': 'Verified XSS'
}


@task()
class dalfox(VulnHttp):
	"""Powerful open source XSS scanning tool."""
	cmd = 'dalfox'
	input_type = URL
	input_flag = 'url'
	file_flag = 'file'
	# input_chunk_size = 1
	json_flag = '--format json'
	version_flag = 'version'
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
	item_loaders = [JSONSerializer()]
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
	install_github_handle = 'hahwul/dalfox'
	encoding = 'ansi'
	proxychains = False
	proxychains_flavor = 'proxychains4'
	proxy_socks5 = True
	proxy_http = True
	profile = 'cpu'

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line

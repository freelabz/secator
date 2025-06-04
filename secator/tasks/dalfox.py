from urllib.parse import urlparse

from secator.decorators import task
from secator.definitions import (CONFIDENCE, DELAY, EXTRA_DATA, FOLLOW_REDIRECT,
							   HEADER, ID, MATCHED_AT, METHOD, NAME,
							   OPT_NOT_SUPPORTED, PROVIDER, PROXY, RATE_LIMIT,
							   RETRIES, SEVERITY, TAGS, THREADS, TIMEOUT, URL,
							   USER_AGENT)
from secator.output_types import Vulnerability, Url
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
	input_types = [URL]
	output_types = [Vulnerability, Url]
	tags = ['url', 'fuzz']
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
		RETRIES: OPT_NOT_SUPPORTED,
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
			EXTRA_DATA: lambda x: dalfox.extra_data_extractor(x),
			SEVERITY: lambda x: x['severity'].lower()
		}
	}
	install_version = 'v2.11.0'
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

	@staticmethod
	def on_json_loaded(self, item):
		if item.get('type', '') == 'V':
			item['request_headers'] = self.get_opt_value(HEADER, preprocess=True)
			yield Url(
				url=item['data'],
				method=item['method'],
				request_headers=item['request_headers'],
				extra_data={k: v for k, v in item.items() if k not in ['type', 'severity', 'cwe', 'request_headers', 'method', 'data']}  # noqa: E501
			)
		yield item

	@staticmethod
	def extra_data_extractor(item):
		extra_data = {}
		for key, value in item.items():
			if key not in ['type', 'severity', 'cwe']:
				extra_data[key] = value
		return extra_data

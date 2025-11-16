from secator.decorators import task
from secator.definitions import (URL, HOST, IP, HOST_PORT, WORDLIST, OPT_NOT_SUPPORTED)
from secator.output_types import Url, Subdomain, Tag
from secator.serializers import JSONSerializer
from secator.runners import Command
from secator.utils import process_wordlist
from urllib.parse import urlparse, urlunparse


@task()
class x8(Command):
	"""Hidden parameters discovery suite written in Rust."""
	cmd = 'x8'
	input_types = [HOST, HOST_PORT, IP, URL]
	output_types = [Url, Subdomain, Tag]
	tags = ['url', 'fuzz', 'params']
	file_flag = '-u'
	input_flag = '-u'
	json_flag = '-O json'
	opt_prefix = '--'
	version_flag = OPT_NOT_SUPPORTED
	opts = {
		WORDLIST: {'type': str, 'short': 'w', 'default': None, 'process': process_wordlist, 'help': 'Wordlist to use'},  # noqa: E501
	}
	item_loaders = [JSONSerializer()]
	install_version = '4.3.0'
	install_cmd = 'cargo install x8@[install_version]'
	install_github_handle = 'projectdiscovery/x8'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	example="""
[{"method":"GET","url":"http://testphp.vulnweb.com/hpp/?pp=1","status":200,"size":602,"found_params":[{"name":"pp","value":null,"diffs":"","status":200,"size":617,"reason_kind":"Reflected"}],"injection_place":"Path"}]
"""

	@staticmethod
	def on_init(self):
		self.urls = []

	@staticmethod
	def on_json_loaded(self, item):
		url = item['url']
		if url not in self.urls:
			self.urls.append(url)
			yield Url(url=url, method=item['method'], status_code=item['status'], content_length=item['size'])
		for param in item.get('found_params', []):
			parsed_url = urlparse(url)
			url_without_param = urlunparse(parsed_url._replace(query=''))
			extra_data = {k: v for k, v in param.items() if k != 'name'}
			extra_data['content'] = param['value']
			extra_data['subtype'] = 'param'
			yield Tag(name=param['name'], match=url_without_param, category=f'url_param', extra_data=extra_data)

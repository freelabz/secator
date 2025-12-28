from urllib.parse import urlparse, urlunparse

from secator.decorators import task
from secator.definitions import (URL, PROXY, DATA, WORDLIST, RETRIES, OPT_NOT_SUPPORTED, USER_AGENT, THREADS, DELAY, TIMEOUT, RATE_LIMIT, METHOD, HEADER, FOLLOW_REDIRECT, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, DEPTH)  # noqa: E501
from secator.output_types import Url, Tag
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpParamsFuzzer


@task()
class x8(HttpParamsFuzzer):
	"""Hidden parameters discovery suite written in Rust."""
	cmd = 'x8'
	input_types = [URL]
	output_types = [Url, Tag]
	tags = ['url', 'fuzz', 'params']
	file_flag = '-u'
	input_flag = '-u'
	json_flag = '-O json'
	opt_prefix = '-'
	version_flag = '-V'
	opt_key_map = {
		DATA: '--body',
		USER_AGENT: OPT_NOT_SUPPORTED,
		THREADS: 'c',
		DEPTH: OPT_NOT_SUPPORTED,
		DELAY: '--delay',
		TIMEOUT: '--timeout',
		PROXY: 'x',
		METHOD: '--method',
		WORDLIST: 'w',
		FILTER_CODES: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		HEADER: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		# HEADER: 'H',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: '--follow-redirects',
	}
	opt_value_map = {
		HEADER: lambda headers: ';'.join(headers.split(';;'))
	}
	item_loaders = [JSONSerializer()]
	install_pre_cmd = {
		'apk': ['build-base', 'pkgconf', 'libssl3', 'libcrypto3', 'openssl-dev'],
		'apt': ['build-essential', 'pkg-config', 'libssl-dev'],
		'pacman': ['base-devel', 'pkg-config', 'openssl'],
		'zypper': ['gcc', 'pkg-config', 'libopenssl-devel'],
		'*': ['gcc', 'pkg-config', 'openssl-devel'],
	}
	install_version = '4.3.0'
	install_cmd = 'cargo install x8@[install_version] --force'
	install_github_bin = False  # TODO: enable this once https://github.com/Sh1Yo/x8/issues/65 is fixed
	# install_github_version_prefix = 'v'
	# install_ignore_bin = ['alpine', 'ubuntu']
	github_handle = 'Sh1Yo/x8'
	proxychains = False
	proxy_socks5 = False
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_init(self):
		self.urls = []
		self.request_headers = {}
		for k, v in self.get_opt_value(HEADER, preprocess=True).items():
			self.request_headers[k] = v

	@staticmethod
	def on_json_loaded(self, item):
		url = item['url']
		parsed_url = urlparse(url)
		url_without_param = urlunparse(parsed_url._replace(query=''))

		if url not in self.urls:
			self.urls.append(url)
			yield Url(
				url=url,
				host=parsed_url.hostname,
				method=item['method'],
				status_code=item['status'],
				content_length=item['size'],
				request_headers=self.request_headers,
			)

		for param in item.get('found_params', []):
			extra_data = {k: v for k, v in param.items() if k != 'name'}
			extra_data['value'] = param['value']
			extra_data['url'] = url
			yield Tag(
				category='info',
				name='url_param',
				match=url_without_param,
				value=param['name'],
				extra_data=extra_data
			)

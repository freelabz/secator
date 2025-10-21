from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT, URL, HOST)
from secator.output_types.url import Url
from secator.output_types.subdomain import Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler


@task()
class gau(HttpCrawler):
	"""Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan."""
	cmd = 'gau'
	input_types = [URL, HOST]
	output_types = [Url, Subdomain]
	tags = ['pattern', 'scan']
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	opts = {
		'providers': {'type': str, 'default': None, 'help': 'List of providers to use (wayback,commoncrawl,otx,urlscan)'},
		'subdomains': {'is_flag': True, 'default': False, 'help': 'Fetch subdomains'}
	}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
		FILTER_CODES: 'fc',
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		MATCH_CODES: 'mc',
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		'subdomains': 'subs'
	}
	item_loaders = [JSONSerializer()]
	install_pre = {
		'apk': ['libc6-compat']
	}
	install_version = 'v2.2.4'
	install_cmd = 'go install -v github.com/lc/gau/v2/cmd/gau@[install_version]'
	install_github_handle = 'lc/gau'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_init(self):
		self.subdomains = []

	@staticmethod
	def on_json_loaded(self, item):
		if self.get_opt_value('subdomains'):
			subdomain = item['url'].split('://')[1].split('/')[0].split(':')[0]
			host = '.'.join(subdomain.split('.')[1:])
			subdomain = Subdomain(host=subdomain, domain=host)
			if subdomain not in self.subdomains:
				self.subdomains.append(subdomain)
				yield subdomain
		else:
			yield Url(url=item['url'])

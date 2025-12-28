import json
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, parse_qs

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT, URL, HOST)
from secator.output_types import Subdomain, Url, Warning
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler
from secator.utils import extract_domain_info


@task()
class gau(HttpCrawler):
	"""Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan."""
	cmd = 'gau --verbose'
	input_types = [URL, HOST]
	output_types = [Url, Subdomain]
	tags = ['url', 'crawl', 'passive']
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	encoding = 'ansi'
	opts = {
		'providers': {'type': str, 'default': None, 'help': 'List of providers to use (wayback,commoncrawl,otx,urlscan)'},
		'subs': {'is_flag': True, 'default': False, 'help': 'Output subdomains as well asURLs'},
		'max_param_occurrences': {'type': int, 'help': 'Max occurrences for the same parameter in the same URL before discarding next results', 'required': False, 'default': 10, 'internal': True},  # noqa: E501
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
	}
	item_loaders = [JSONSerializer()]
	install_pre = {'apk': ['libc6-compat']}
	install_version = 'v2.2.4'
	install_cmd = 'go install -v github.com/lc/gau/v2/cmd/gau@[install_version]'
	github_handle = 'lc/gau'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_init(self):
		self.max_param_occurrences = self.get_opt_value('max_param_occurrences')
		self.seen_params = defaultdict(lambda: defaultdict(int))
		self.subdomains = []

	@staticmethod
	def on_line(self, line):
		if 'level=warning' in line and 'error reading config' not in line:
			msg = line.split('msg=')[-1].rstrip('""').lstrip('"')
			if not msg.startswith('http'):
				msg = msg.capitalize()
			return json.dumps({'message': msg, '_type': 'warning'})
		return line

	@staticmethod
	def on_json_loaded(self, item):
		if item.get('message'):
			yield Warning(message=item['message'])
			return
		url = item['url']
		parsed_url = urlparse(url)
		base_url = urlunparse(parsed_url._replace(query="", fragment=""))  # Remove query & fragment
		query_params = parse_qs(parsed_url.query)
		current_params = set(query_params.keys())
		for param in current_params:
			self.seen_params[base_url][param] += 1
			if self.seen_params[base_url][param] > int(self.max_param_occurrences):
				return
		if self.get_opt_value('subs'):
			domain = extract_domain_info(parsed_url.hostname, domain_only=True)
			if domain:
				subdomain = Subdomain(host=parsed_url.hostname, domain=domain)
				if subdomain not in self.subdomains:
					self.subdomains.append(subdomain)
					yield subdomain
		else:
			yield Url(url=item['url'], host=parsed_url.hostname)

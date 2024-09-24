import os

from secator.decorators import task
from secator.definitions import (DEFAULT_HTTPX_FLAGS, DELAY, DEPTH,
								 FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
								 FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
								 MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PROXY,
								 RATE_LIMIT, RETRIES, THREADS,
								 TIMEOUT, URL, USER_AGENT)
from secator.config import CONFIG
from secator.output_types import Url, Subdomain
from secator.tasks._categories import Http
from secator.utils import (sanitize_url,
						   extract_root_domain_from_domain,
						   remove_first_subdomain)
import json


@task()
class httpx(Http):
	"""Fast and multi-purpose HTTP toolkit."""
	cmd = f'httpx {DEFAULT_HTTPX_FLAGS}'
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		# 'silent': {'is_flag': True, 'default': False, 'help': 'Silent mode'},
		# 'td': {'is_flag': True, 'default': True, 'help': 'Tech detection'},
		# 'irr': {'is_flag': True, 'default': False, 'help': 'Include http request / response'},
		'fep': {'is_flag': True, 'default': False, 'help': 'Error Page Classifier and Filtering'},
		'favicon': {'is_flag': True, 'default': False, 'help': 'Favicon hash'},
		'jarm': {'is_flag': True, 'default': False, 'help': 'Jarm fingerprint'},
		'asn': {'is_flag': True, 'default': False, 'help': 'ASN detection'},
		'cdn': {'is_flag': True, 'default': False, 'help': 'CDN detection'},
		'debug_resp': {'is_flag': True, 'default': False, 'help': 'Debug response'},
		'vhost': {'is_flag': True, 'default': False, 'help': 'Probe and display server supporting VHOST'},
		'store_responses': {'is_flag': True, 'short': 'sr', 'default': CONFIG.http.store_responses, 'help': 'Save HTTP responses'},  # noqa: E501
		'screenshot': {'is_flag': True, 'short': 'ss', 'default': False, 'help': 'Screenshot response'},
		'system_chrome': {'is_flag': True, 'default': False, 'help': 'Use local installed Chrome for screenshot'},
		'headless_options': {'is_flag': False, 'short': 'ho', 'default': None, 'help': 'Headless Chrome additional options'},
		'follow_host_redirects': {'is_flag': True, 'short': 'fhr', 'default': None, 'help': 'Follow redirects on the same host'},  # noqa: E501
		'tls_grab': {'is_flag': True, 'default': False, 'help': 'Grab some informations from the tls certificate'}
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		DEPTH: OPT_NOT_SUPPORTED,
		FILTER_CODES: 'filter-code',
		FILTER_REGEX: 'filter-regex',
		FILTER_SIZE: 'filter-length',
		FILTER_WORDS: 'filter-word-count',
		FOLLOW_REDIRECT: 'follow-redirects',
		MATCH_CODES: 'match-code',
		MATCH_REGEX: 'match-regex',
		MATCH_SIZE: 'match-length',
		MATCH_WORDS: 'match-word-count',
		METHOD: 'x',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		'store_responses': 'sr',
	}
	opt_value_map = {
		DELAY: lambda x: str(x) + 's' if x else None,
	}
	install_cmd = 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
	install_github_handle = 'projectdiscovery/httpx'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'cpu'
	output_types = [Url, Subdomain]
	founded_domain_in_certificates = []

	@staticmethod
	def on_init(self):
		debug_resp = self.get_opt_value('debug_resp')
		if debug_resp:
			self.cmd = self.cmd.replace('-silent', '')
		screenshot = self.get_opt_value('screenshot')
		store_responses = self.get_opt_value('store_responses')
		if store_responses or screenshot:
			self.cmd += f' -srd {self.reports_folder}/.outputs'
		if screenshot:
			self.cmd += ' -esb -ehb'

	@staticmethod
	def on_item_pre_convert(self, item):
		try:
			for k, v in item.items():
				if k == 'time':
					response_time = float(''.join(ch for ch in v if not ch.isalpha()))
					if v[-2:] == 'ms':
						response_time = response_time / 1000
					item[k] = response_time
				elif k == URL:
					item[k] = sanitize_url(v)
			item[URL] = item.get('final_url') or item[URL]
		# Because item can also be a domain
		except KeyError as e:
			if not ('url' in e.args):
				raise e
		return item

	def _create_subdomain_from_tls(self, domain_in_certificate):
		if domain_in_certificate.startswith('*'):
			domain_in_certificate = remove_first_subdomain(domain_in_certificate)
		if not (domain_in_certificate in self.founded_domain_in_certificates):
			self.founded_domain_in_certificates.append(domain_in_certificate)
			return {
				'host': domain_in_certificate,
				'domain': extract_root_domain_from_domain(domain_in_certificate),
			}

	@staticmethod
	def item_loader(self, line):
		try:
			item = json.loads(line)
		except json.JSONDecodeError:
			return
		for k, v in item.items():
			if k == 'tls':
				for tls_k, tls_v in v.items():
					if tls_k == 'subject_cn':
						domain = self._create_subdomain_from_tls(tls_v)
						yield domain
					if tls_k == 'subject_an':
						for alternative_name in tls_v:
							domain = self._create_subdomain_from_tls(alternative_name)
							yield domain

	@staticmethod
	def on_end(self):
		store_responses = self.get_opt_value('store_responses')
		response_dir = f'{self.reports_folder}/.outputs'
		if store_responses:
			index_rpath = f'{response_dir}/response/index.txt'
			index_spath = f'{response_dir}/screenshot/index_screenshot.txt'
			index_spath2 = f'{response_dir}/screenshot/screenshot.html'
			if os.path.exists(index_rpath):
				os.remove(index_rpath)
			if os.path.exists(index_spath):
				os.remove(index_spath)
			if os.path.exists(index_spath2):
				os.remove(index_spath2)

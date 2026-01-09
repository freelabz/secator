import os
import shlex

from datetime import datetime

from secator.decorators import task
from secator.definitions import (DATA, DELAY, DEPTH, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
							 	 FOLLOW_REDIRECT, HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS,
								 METHOD, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT,
								 URL, USER_AGENT, HOST, IP, HOST_PORT)
from secator.config import CONFIG
from secator.output_types import Url, Subdomain, Certificate
from secator.serializers import JSONSerializer
from secator.tasks._categories import Http
from secator.utils import (sanitize_url, extract_domain_info, extract_subdomains_from_fqdn)


@task()
class httpx(Http):
	"""Fast and multi-purpose HTTP toolkit."""
	cmd = 'httpx-toolkit -irh'
	input_types = [HOST, HOST_PORT, IP, URL]
	output_types = [Url, Subdomain]
	tags = ['url', 'probe']
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		# 'silent': {'is_flag': True, 'default': False, 'help': 'Silent mode'},
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
		'tech_detect': {'is_flag': True, 'short': 'td', 'default': False, 'help': 'Tech detection'},
		'tls_grab': {'is_flag': True, 'short': 'tlsg', 'default': False, 'help': 'Grab some informations from the tls certificate'},  # noqa: E501
		'rstr': {'type': int, 'default': CONFIG.http.response_max_size_bytes, 'help': 'Max body size to read (bytes)'},
		'rsts': {'type': int, 'default': CONFIG.http.response_max_size_bytes, 'help': 'Max body size to save (bytes)'},
		'filter_duplicates': {'is_flag': True, 'short': 'fd', 'default': False, 'help': 'Filter duplicates'},
	}
	opt_key_map = {
		DATA: 'body',
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
		'filter_duplicates': 'fd',
	}
	opt_value_map = {
		DELAY: lambda x: str(x) + 's' if x else None,
	}
	item_loaders = [JSONSerializer()]
	install_pre = {'apk': ['chromium']}
	install_version = 'v1.7.0'
	install_cmd = 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@[install_version]'
	github_handle = 'projectdiscovery/httpx'
	install_binary_name = 'httpx-toolkit'  # Rename to avoid conflict with Python httpx library
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = lambda opts: httpx.dynamic_profile(opts)  # noqa: E731

	@staticmethod
	def dynamic_profile(opts):
		screenshot = httpx._get_opt_value(
			opts,
			'screenshot',
			opts_conf=dict(httpx.opts, **httpx.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		return 'large' if screenshot is True else 'small'

	@staticmethod
	def on_init(self):
		debug_resp = self.get_opt_value('debug_resp')
		if debug_resp:
			self.cmd = self.cmd.replace('-silent', '')
		screenshot = self.get_opt_value('screenshot')
		store_responses = self.get_opt_value('store_responses')
		if store_responses or screenshot:
			reports_folder_outputs = f'{self.reports_folder}/.outputs'
			self.cmd += f' -srd {shlex.quote(reports_folder_outputs)}'
		if screenshot:
			self.cmd += ' -esb -ehb'
		self.domains = []

	@staticmethod
	def on_json_loaded(self, item):
		item = self._preprocess_url(item)
		yield item
		tls = item.get('tls', None)
		if tls:
			subject_cn = tls.get('subject_cn', None)
			subject_an = tls.get('subject_an', [])
			not_after = tls.get('not_after', None)
			if not_after:
				not_after = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%SZ')
			not_before = tls.get('not_before', None)
			if not_before:
				not_before = datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%SZ')
			cert = Certificate(
				host=tls['host'],
				subject_cn=subject_cn,
				subject_an=subject_an,
				issuer_dn=tls.get('issuer_dn', None),
				issuer_cn=tls.get('issuer_cn', None),
				issuer=tls.get('issuer_org', [None])[0],
				fingerprint_sha256=tls.get('fingerprint_hash', {}).get('sha256', None),
				not_before=not_before,
				not_after=not_after,
				serial_number=tls.get('serial_number', None),
				keysize=tls.get('keysize', None),
				status=tls.get('status'),
			)
			yield cert

			# Create subdomains from certificate CN and ANs.
			yield from self._create_subdomain_from_tls_cert(subject_cn, item['url'], cert)
			for an in subject_an:
				yield from self._create_subdomain_from_tls_cert(an, item['url'], cert)

	@staticmethod
	def on_end(self):
		store_responses = self.get_opt_value('store_responses') or CONFIG.http.store_responses
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

	def _preprocess_url(self, item):
		"""Replace time string by float, sanitize URL, get final redirect URL."""
		for k, v in item.items():
			if k == 'time':
				response_time = float(''.join(ch for ch in v if not ch.isalpha()))
				if v[-2:] == 'ms':
					response_time = response_time / 1000
				item[k] = response_time
			elif k == URL:
				item[k] = sanitize_url(v)
		item[URL] = item.get('final_url') or item[URL]
		item['request_headers'] = self.get_opt_value('header', preprocess=True)
		item['response_headers'] = item.get('header', {})
		item.pop('host', None)
		return item

	def _create_subdomain_from_tls_cert(self, host, url, cert):
		"""Extract subdomains from TLS certificate."""
		if host.startswith('*.'):
			host = host.lstrip('*.')
		if host in self.domains:
			return None
		url_domain = extract_domain_info(url)
		url_domains = extract_subdomains_from_fqdn(url_domain.fqdn, url_domain.domain, url_domain.suffix)
		if not url_domain or host not in url_domains:
			return None
		self.domains.append(host)
		yield Subdomain(
			host=host,
			domain=extract_domain_info(host, domain_only=True),
			verified=True,
			extra_data={
				'tls_cert_state': 'EXPIRED' if cert.is_expired() else 'EXPIRES_SOON' if cert.is_expired(months=2) else 'VALID',  # noqa: E501
				'tls_cert_expiration_date': cert.format_date(cert.not_after),
			},
			sources=['tls', 'certificate'],
		)

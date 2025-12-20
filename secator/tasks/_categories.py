import os

from functools import cache

from cpe import CPE

from secator.definitions import (CIDR_RANGE, DATA, DELAY, DEPTH, FILTER_CODES,
								 FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT, HEADER, HOST, IP,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, PATH, PORTS, PROXY,
								 RATE_LIMIT, RAW, RETRIES, THREADS, TIMEOUT, TOP_PORTS, URL, USER_AGENT,
								 USERNAME, WORDLIST)
from secator.output_types import Ip, Port, Subdomain, Tag, Url, UserAccount, Vulnerability
from secator.config import CONFIG
from secator.providers._base import CVEProvider
from secator.runners import Command
from secator.utils import debug, process_wordlist, headers_to_dict, parse_raw_http_request


def process_headers(headers_dict):
	headers = []
	for key, value in headers_dict.items():
		headers.append(f'{key}:{value}')
	return headers


def process_raw_request(file_path):
	"""Process raw HTTP request file and return parsed request data.

	Args:
		file_path (str): Path to file containing raw HTTP request.

	Returns:
		dict: Parsed request data with method, url, headers, and data.
	"""
	if not file_path:
		return None
	if not os.path.exists(file_path):
		raise ValueError(f"Raw request file not found: {file_path}")
	with open(file_path, 'r') as f:
		raw_request = f.read()
	return parse_raw_http_request(raw_request)


def apply_raw_request_options(self):
	"""Apply raw HTTP request options to task if raw option is provided.

	This function is shared across Http, HttpCrawler, and HttpFuzzer classes.

	Args:
		self: Task instance.
	"""
	raw_request_data = self.get_opt_value(RAW, preprocess=True)
	if raw_request_data:
		# Set method from raw request
		if raw_request_data.get('method') and not self.get_opt_value(METHOD):
			self.run_opts[METHOD] = raw_request_data['method']

		# Set URL from raw request if not already provided
		if raw_request_data.get('url') and (not self.inputs or len(self.inputs) == 0):
			self.inputs = [raw_request_data['url']]

		# Merge headers from raw request with existing headers
		if raw_request_data.get('headers'):
			existing_headers = self.get_opt_value(HEADER, preprocess=True) or {}
			# Raw request headers take precedence
			merged_headers = {**existing_headers, **raw_request_data['headers']}
			self.run_opts[HEADER] = merged_headers

		# Set data from raw request
		if raw_request_data.get('data') and not self.get_opt_value(DATA):
			self.run_opts[DATA] = raw_request_data['data']


OPTS = {
	HEADER: {'type': str, 'short': 'H', 'help': 'Custom header to add to each request in the form "KEY1:VALUE1;; KEY2:VALUE2"', 'pre_process': headers_to_dict, 'process': process_headers, 'default': CONFIG.http.default_header},  # noqa: E501
	DATA: {'type': str, 'help': 'Data to send in the request body'},
	DELAY: {'type': float, 'short': 'd', 'help': 'Delay to add between each requests'},
	DEPTH: {'type': int, 'help': 'Scan depth'},
	FILTER_CODES: {'type': str, 'short': 'fc', 'help': 'Filter out responses with HTTP codes'},
	FILTER_REGEX: {'type': str, 'short': 'fr', 'help': 'Filter out responses with regular expression'},
	FILTER_SIZE: {'type': int, 'short': 'fs', 'help': 'Filter out responses with size'},
	FILTER_WORDS: {'type': int, 'short': 'fw', 'help': 'Filter out responses with word count'},
	FOLLOW_REDIRECT: {'is_flag': True, 'short': 'frd', 'help': 'Follow HTTP redirects'},
	MATCH_CODES: {'type': str, 'short': 'mc', 'help': 'Match HTTP status codes e.g "201,300,301"'},
	MATCH_REGEX: {'type': str, 'short': 'mr', 'help': 'Match responses with regular expression'},
	MATCH_SIZE: {'type': int, 'short': 'ms', 'help': 'Match responses with size'},
	MATCH_WORDS: {'type': int, 'short': 'mw', 'help': 'Match responses with word count'},
	METHOD: {'type': str, 'short': 'X', 'help': 'HTTP method to use for requests'},
	PROXY: {'type': str, 'help': 'HTTP(s) / SOCKS5 proxy'},
	RATE_LIMIT: {'type':  int, 'short': 'rl', 'help': 'Rate limit, i.e max number of requests per second'},
	RAW: {'type': str, 'help': 'Path to file containing raw HTTP request (Burp-style format)', 'pre_process': process_raw_request, 'internal': True},  # noqa: E501
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': CONFIG.runners.threads},
	TIMEOUT: {'type': int, 'short': 'to', 'help': 'Request timeout'},
	USER_AGENT: {'type': str, 'short': 'ua', 'help': 'User agent, e.g "Mozilla Firefox 1.0"'},
	WORDLIST: {'type': str, 'short': 'w', 'default': 'http', 'process': process_wordlist, 'help': 'Wordlist to use for HTTP requests'},  # noqa: E501
	PORTS: {'type': str, 'short': 'p', 'help': 'Only scan specific ports (comma separated list, "-" for all ports)'},  # noqa: E501
	TOP_PORTS: {'type': str, 'short': 'tp', 'help': 'Scan <number> most common ports'},
}

WORDLIST_PARAMS = {
	WORDLIST: {'type': str, 'short': 'w', 'default': 'http_params', 'process': process_wordlist, 'help': 'Wordlist to use for HTTP requests'},  # noqa: E501
}

WORDLIST_DNS = {
	WORDLIST: {'type': str, 'short': 'w', 'default': 'dns', 'process': process_wordlist, 'help': 'Wordlist to use for DNS requests'},  # noqa: E501
}

OPTS_HTTP_BASE = [
	HEADER, DELAY, FOLLOW_REDIRECT, METHOD, PROXY, RATE_LIMIT, RAW, RETRIES, THREADS, TIMEOUT, USER_AGENT, DATA
]
OPTS_HTTP_FILTERS = [
	DEPTH, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, FILTER_REGEX, FILTER_CODES, FILTER_SIZE, FILTER_WORDS, MATCH_CODES
]

OPTS_HTTP = OPTS_HTTP_BASE + OPTS_HTTP_FILTERS

OPTS_HTTP_FUZZERS = OPTS_HTTP + [WORDLIST, DATA]

OPTS_HTTP_CRAWLERS = OPTS_HTTP_FUZZERS.copy()
OPTS_HTTP_CRAWLERS.remove(DATA)
OPTS_HTTP_CRAWLERS.remove(METHOD)
OPTS_HTTP_CRAWLERS.remove(WORDLIST)

OPTS_RECON = [
	DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT
]

OPTS_RECON_PORT = [
	PORTS, TOP_PORTS, DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT
]

OPTS_VULN = [
	HEADER, DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT
]


#---------------#
# HTTP category #
#---------------#

class HttpBase(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_BASE}
	input_types = [URL]
	output_types = [Url]

	@staticmethod
	def before_init(self):
		"""Process raw HTTP request if provided and set appropriate options."""
		apply_raw_request_options(self)


class Http(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP}
	input_types = [URL]
	output_types = [Url]

	@staticmethod
	def before_init(self):
		"""Process raw HTTP request if provided and set appropriate options."""
		apply_raw_request_options(self)


class HttpCrawler(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_CRAWLERS}
	input_types = [URL]
	output_types = [Url]

	@staticmethod
	def before_init(self):
		"""Process raw HTTP request if provided and set appropriate options."""
		apply_raw_request_options(self)


class HttpFuzzer(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_FUZZERS}
	input_types = [URL]
	output_types = [Url]
	enable_duplicate_check = False
	profile = lambda opts: HttpFuzzer.dynamic_profile(opts)  # noqa: E731

	@staticmethod
	def before_init(self):
		"""Process raw HTTP request if provided and set appropriate options."""
		apply_raw_request_options(self)

	@staticmethod
	def dynamic_profile(opts):
		wordlist = HttpFuzzer._get_opt_value(
			opts,
			'wordlist',
			opts_conf=dict(HttpFuzzer.opts, **HttpFuzzer.meta_opts),
			opt_aliases=opts.get('aliases', []),
			preprocess=True,
			process=True,
		)
		wordlist_size_mb = os.path.getsize(wordlist) / (1024 * 1024)
		return 'cpu' if wordlist_size_mb > 5 else 'io'


class HttpParamsFuzzer(HttpFuzzer):
	meta_opts = {**{k: OPTS[k] for k in OPTS_HTTP_FUZZERS}, **WORDLIST_PARAMS}


#----------------#
# Recon category #
#----------------#

class Recon(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_RECON}
	output_types = [Subdomain, UserAccount, Ip, Port]


class ReconDns(Recon):
	input_types = [HOST]
	output_types = [Subdomain]


class ReconUser(Recon):
	input_types = [USERNAME]
	output_types = [UserAccount]


class ReconIp(Recon):
	input_types = [CIDR_RANGE]
	output_types = [Ip]


class ReconPort(Recon):
	meta_opts = {k: OPTS[k] for k in OPTS_RECON_PORT}
	input_types = [IP]
	output_types = [Port]


#---------------#
# Vuln category #
#---------------#

class Vuln(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_VULN}
	output_types = [Vulnerability]

	@staticmethod
	def create_cpe_string(product_name, version):
		"""
		Generate a CPE string for a given product and version.

		Args:
			product_name (str): The name of the product.
			version (str): The version of the product.

		Returns:
			str: A CPE string formatted according to the CPE 2.3 specification.
		"""
		cpe_version = "2.3"  # CPE Specification version
		part = "a"           # 'a' for application
		vendor = product_name.lower()  # Vendor name, using product name
		product = product_name.lower()  # Product name
		version = version  # Product version
		cpe_string = f"cpe:{cpe_version}:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
		return cpe_string

	@staticmethod
	def match_cpes(fs1, fs2):
		"""Check if two CPEs match. Partial matches consisting of <vendor>:<product>:<version> are considered a match.

		Args:
			fs1 (str): Format string 1.
			fs2 (str): Format string 2.

		Returns:
			bool: True if the two CPEs match, False otherwise.
		"""
		if fs1 == fs2:
			return True
		split_fs1 = fs1.split(':')
		split_fs2 = fs2.split(':')
		tup1 = split_fs1[3], split_fs1[4], split_fs1[5]
		tup2 = split_fs2[3], split_fs2[4], split_fs2[5]
		return tup1 == tup2

	@staticmethod
	def get_cpe_fs(cpe):
		""""Return formatted string for given CPE.

		Args:
			cpe (string): Input CPE

		Returns:
			string: CPE formatted string.
		"""
		try:
			return CPE(cpe).as_fs()
		except NotImplementedError:
			return None

	@cache
	@staticmethod
	def lookup_cve(cve_id, *cpes):
		"""Search for a CVE info and return vulnerability data.

		Args:
			cve_id (str): CVE ID in the form CVE-*
			cpes (tuple[str], Optional): CPEs to match for.

		Returns:
			Vulnerability: Vulnerability object.
		"""
		# Lookup CVE data
		vuln = CVEProvider.lookup_local_cve(cve_id)
		if not vuln:
			vuln = CVEProvider.lookup_external_cve(cve_id)
			if not vuln:
				return None

		# Match the CPE string against the affected products CPE FS strings from the CVE data if a CPE was passed.
		# This allow to limit the number of False positives (high) that we get from nmap NSE vuln scripts like vulscan
		# and ensure we keep only right matches.
		# The check is not executed if no CPE was passed (sometimes nmap cannot properly detect a CPE) or if the CPE
		# version cannot be determined.
		cpes_affected = vuln.extra_data.get('cpes', [])
		cpe_match = False
		if cpes and cpes_affected:
			for cpe in cpes:
				cpe_fs = Vuln.get_cpe_fs(cpe)
				if not cpe_fs:
					debug(f'{cve_id}: Failed to parse CPE {cpe} with CPE parser', sub='cve.match', verbose=True)
					vuln.tags.append('cpe-invalid')
					continue
				for cpe_affected in cpes_affected:
					cpe_affected_fs = Vuln.get_cpe_fs(cpe_affected)
					if not cpe_affected_fs:
						debug(f'{cve_id}: Failed to parse CPE {cpe} (from online data) with CPE parser', sub='cve.match', verbose=True)
						continue
					debug(f'{cve_id}: Testing {cpe_fs} against {cpe_affected_fs}', sub='cve.match', verbose=True)
					cpe_match = Vuln.match_cpes(cpe_fs, cpe_affected_fs)
					if cpe_match:
						debug(f'{cve_id}: CPE match found for {cpe}.', sub='cve.match')
						vuln.tags.append('cpe-match')
						break

				if not cpe_match:
					debug(f'{cve_id}: no CPE match found for {cpe}.', sub='cve.match')

		return vuln


class VulnHttp(Vuln):
	input_types = [HOST]


class VulnCode(Vuln):
	input_types = [PATH]


class VulnMulti(Vuln):
	input_types = [HOST]
	output_types = [Vulnerability]


#--------------#
# Tag category #
#--------------#

class Tagger(Command):
	input_types = [URL]
	output_types = [Tag]

#----------------#
# osint category #
#----------------#


class OSInt(Command):
	output_types = [UserAccount]

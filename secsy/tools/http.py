"""HTTP tools. Includes HTTP probers and URL finders / fuzzers."""

import logging
import shlex
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import yaml
from furl import furl

from secsy.cmd import CommandRunner
from secsy.definitions import *
from secsy.utils import sanitize_url

logger = logging.getLogger(__name__)

HTTP_META_OPTS = {
	HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
	DELAY: {'type': float, 'help': 'Delay to add between each requests'},
	DEPTH: {'type': int, 'help': 'Scan / crawl depth'},
	FOLLOW_REDIRECT: {'is_flag': True, 'default': True, 'help': 'Follow HTTP redirects'},
	MATCH_CODES: {'type': str, 'default': '200,204,301,302,307,401,405', 'help': 'Match HTTP status codes e.g "201,300,301"'},
	METHOD: {'type': str, 'help': 'HTTP method to use for requests'},
	PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
	RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
	TIMEOUT: {'type': int, 'help': 'Request timeout'},
	USER_AGENT: {'type': str, 'help': 'User agent, e.g "Mozilla Firefox 1.0"'},
}

# TODO: add redirect URL for all tools
HTTP_OUTPUT = [
	URL,
	METHOD,
	STATUS_CODE,
	WORDS,
	LINES,
	CONTENT_TYPE,
	CONTENT_LENGTH,
	HOST,
	TIME
]


class HTTPCommand(CommandRunner):
	meta_opts = HTTP_META_OPTS
	output_schema = HTTP_OUTPUT
	output_field = URL
	output_type = URL
	output_table_fields = [URL, STATUS_CODE, CONTENT_TYPE, TIME]
	input_type = URL


class cariddi(HTTPCommand):
	"""Crawl endpoints, secrets, api keys, extensions, tokens..."""
	cmd = 'cariddi -plain'
	opt_key_map = {
		HEADER: 'headers',
		DELAY: 'd',
		DEPTH: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'c',
		TIMEOUT: 't',
		USER_AGENT: 'ua'
	}
	file_flag = OPT_PIPE_INPUT
	input_flag = OPT_PIPE_INPUT
	install_cmd = 'go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest'

	def item_loader(self, line):
		if not 'protocol error' in line and self._json_output:
			return {URL: line}


class dirsearch(HTTPCommand):
	"""Advanced web path brute-forcer."""
	cmd = 'dirsearch -q'
	input_flag = '-u'
	file_flag = '-l'
	json_flag = '--format json'
	opt_prefix = '--'
	encoding = 'ansi'
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		DEPTH: 'max-recursion-depth',
		FOLLOW_REDIRECT: 'follow-redirects',
		MATCH_CODES: 'include-status',
		METHOD: 'http-method',
		PROXY: 'proxy',
		RATE_LIMIT: 'max-rate',
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
	}
	output_map = {
		CONTENT_LENGTH: 'content-length',
		CONTENT_TYPE: 'content-type',
		STATUS_CODE: 'status'
	}

	def __iter__(self):
		prev = self._print_item_count
		self._print_item_count = False
		list(super().__iter__())
		if self.return_code != 0:
			return
		self.results = []
		if not self._json_output:
			return
		note = f'dirsearch JSON results saved to {self.output_path}'
		if self._print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				results = yaml.safe_load(f.read()).get('results', [])
			for item in results:
				item = self._process_item(item)
				if not item:
					continue
				yield item
		self._print_item_count = prev
		self._process_results()

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value('output_path')
		if not self.output_path:
			timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
			self.output_path = f'{TEMP_FOLDER}/dirsearch_{timestr}.json'
		self.cmd += f' -o {self.output_path}'


class feroxbuster(HTTPCommand):
	"""Simple, fast, recursive content discovery tool written in Rust"""
	cmd = 'feroxbuster'
	input_flag = '--url'
	file_flag = None
	json_flag = '--json'
	opt_prefix = '--'
	opts = {
		'wordlist': {'type': str, 'help': 'Wordlist'},
		'auto_tune': {'is_flag': True, 'help': 'Automatically lower scan rate when an excessive amount of errors are encountered'},
		'extract_links': {'is_flag': True, 'default': True, 'help': 'Extract links from response body (html, javascript, etc...); make new requests based on findings'},
		'collect_backups': {'is_flag': True, 'help': 'Automatically request likely backup extensions for "found" urls'},
		'collect_extensions': {'is_flag': True, 'help': 'Automatically discover extensions ad add them to --extensions'},
		'collect_words': {'is_flag': True, 'help': 'Automatically discover important words from within responses and add them to the wordlist'},
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: 'depth',
		FOLLOW_REDIRECT: 'redirects',
		MATCH_CODES: 'status-codes',
		METHOD: 'methods',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
	}
	output_map = {
		STATUS_CODE: 'status',
		CONTENT_TYPE: lambda x: x['headers'].get('content-type'),
		LINES: 'line_count',
		WORDS: 'word_count'
	}

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value('output_path')
		if not self.output_path:
			timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
			self.output_path = f'{TEMP_FOLDER}/feroxbuster_{timestr}.json'
		Path(self.output_path).touch()
		self.cmd += f' --output {self.output_path}'
		if os.path.exists(self.input):
			self.cmd += ' --stdin'

	@staticmethod
	def on_start(self):
		self.cmd += f' & tail --pid $! -f {shlex.quote(self.output_path)}'
		self.shell = True

	@staticmethod
	def validate_item(self, item):
		return item['type'] == 'response'


class ffuf(HTTPCommand):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive -recursion'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		AUTO_CALIBRATION: {'is_flag': True, 'default': True, 'help': 'Filter out HTTP responses based on status codes, content length, etc.'},
		WORDLIST: {'type': str, 'default': FFUF_DEFAULT_WORDLIST, 'help': 'Wordlist to fuzz from.'},
	}
	opt_key_map = {
		HEADER: 'H',
		DELAY: 'p',
		DEPTH: 'recursion-depth',
		FOLLOW_REDIRECT: 'r',
		MATCH_CODES: 'mc',
		METHOD: 'X',
		PROXY: 'x',
		RATE_LIMIT: 'rate',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 't',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		
		# ffuf opts
		WORDLIST: 'w',
		AUTO_CALIBRATION: 'ac'
	}
	output_map = {
		STATUS_CODE: 'status',
		CONTENT_LENGTH: 'length',
		CONTENT_TYPE: 'content-type',
		TIME: lambda x: x['duration'] * 10**-9
	}
	encoding = 'ansi'
	install_cmd = 'go install -v github.com/ffuf/ffuf@latest'

	@staticmethod
	def on_init(self):
		# Remove query params for URL fuzzing
		self.input = urlunparse(urlparse(self.input)._replace(query="")).rstrip('/')

		# Add /FUZZ keyword
		self.input = f'{self.input}/FUZZ'

	@staticmethod
	def on_item_convert(self, item):
		item[METHOD] = self.cmd_opts.get(METHOD, 'GET')
		return item


class gau(HTTPCommand):
	"""Fetches known URLs from AlienVault's Open Threat Exchange, the Wayback
	Machine, Common Crawl, and URLScan.
	"""
	cmd = 'gau'
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: 'mc',
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	install_cmd = 'go install -v github.com/lc/gau/v2/cmd/gau@latest'

	# @staticmethod
	# def validate_item(self, item):
	# 	return item['url'] == 'response'


class gospider(HTTPCommand):
	"""Fast web spider written in Go."""
	cmd = 'gospider --js'
	file_flag = '-S'
	input_flag = '-s'
	json_flag = '--json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		DEPTH: 'depth',
		FOLLOW_REDIRECT: 'no-redirect',
		MATCH_CODES: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
	}
	opt_value_map = {
		FOLLOW_REDIRECT: lambda x: not x,
		DELAY: lambda x: round(x) if isinstance(x, float) else x
	}
	output_map = {
		URL: 'output',
		STATUS_CODE: 'status',
		CONTENT_LENGTH: 'length',
	}
	install_cmd = 'go install -v github.com/jaeles-project/gospider@latest'

	@staticmethod
	def validate_item(self, item):
		"""Keep only items that match the same host."""
		try:
			netloc_in = furl(item['input']).netloc
			netloc_out = furl(item['output']).netloc
			if netloc_in != netloc_out:
				return False
		except ValueError: # gospider returns invalid URLs for output sometimes
			return False

		match_codess = self.cmd_opts.get(MATCH_CODES, '')
		if match_codess:
			http_statuses = match_codess.split(',')
			if not str(item['status']) in http_statuses:
				return False
			
		if item['status'] == 0:
			return False

		return True


class httpx(HTTPCommand):
	"""Fast and multi-purpose HTTP toolkit."""
	cmd = 'httpx'
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		'silent': {'is_flag': True, 'default': False},
		'td': {'is_flag': True, 'default': True},
		'asn': {'is_flag': True, 'default': False},
		'cdn': {'is_flag': True, 'default': True},
		'filter_code': {'type': str},
		'filter_length': {'type': str},
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		DEPTH: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirects',
		MATCH_CODES: 'match-code',
		METHOD: 'x',
		PROXY: OPT_NOT_SUPPORTED, # TODO: httpx supports only HTTP -proxy for now https://github.com/yt-dlp/yt-dlp/pull/3668
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	opt_value_map = {
		DELAY: lambda x: str(x) + 's' if x else None,
	}
	install_cmd = 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'

	@staticmethod
	def on_item(self, item):
		for k, v in item.items():
			if k == 'time':
				response_time = float(''.join(ch for ch in v if not ch.isalpha()))
				if v[-2:] == 'ms':
					response_time = response_time / 1000
				item[k] = response_time
			elif k == URL:
				item[k] = sanitize_url(v)
		item[URL] = item.get('final_url') or item[URL]
		return item


class katana(HTTPCommand):
	"""Next-generation crawling and spidering framework."""
	cmd = 'katana -silent -jc -js-crawl -known-files all'
	file_flag = '-list'
	input_flag = '-u'
	json_flag = '-json'
	opt_key_map = {
		HEADER: 'headers',
		DELAY: 'delay',
		DEPTH: 'depth',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'concurrency',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		DELAY: lambda x: int(x) if isinstance(x, float) else x
	}
	output_map = {
		URL: 'endpoint',
		HOST: lambda x: urlparse(x['endpoint']).netloc
	}
	install_cmd = 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest'
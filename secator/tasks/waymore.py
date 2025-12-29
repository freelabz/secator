import json
import validators
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, parse_qs

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT, URL, HOST)
from secator.output_types import Url
from secator.tasks._categories import HttpCrawler


@task()
class waymore(HttpCrawler):
	"""Find way more from the Wayback Machine, Common Crawl, AlienVault OTX, URLScan, VirusTotal and Intelligence X."""
	cmd = 'waymore -mode U --stream'
	input_types = [URL, HOST]
	output_types = [Url]
	tags = ['url', 'crawl', 'passive']
	file_flag = OPT_PIPE_INPUT
	input_flag = '-i'
	opt_prefix = '-'
	encoding = 'utf-8'
	opts = {
		'no_subs': {'is_flag': True, 'short': 'n',
			'help': 'Don\'t include subdomains of the target domain'},
		'limit': {'type': int, 'short': 'l', 'default': 5000,
			'help': 'How many responses will be saved (positive=first N, negative=last N, 0=all)'},
		'from_date': {'type': str, 'default': None,
			'help': 'What date to get responses from (yyyyMMddhhmmss or partial)'},
		'to_date': {'type': str, 'default': None,
			'help': 'What date to get responses to (yyyyMMddhhmmss or partial)'},
		'capture_interval': {'type': str, 'short': 'ci', 'default': 'd',
			'help': 'Capture interval filter (h=hour, d=day, m=month, none)'},
		'regex_after': {'type': str, 'short': 'ra', 'default': None,
			'help': 'RegEx for filtering links and responses (only positive matches)'},
		'providers': {'type': str, 'default': None,
			'help': 'Comma separated list (wayback,commoncrawl,otx,urlscan,virustotal,intelx)'},
		'limit_requests': {'type': int, 'short': 'lr', 'default': 0,
			'help': 'Limit number of requests per source (0=no limit)'},
		'keywords_only': {'type': str, 'short': 'ko', 'default': None,
			'help': 'Only return links containing specific keywords or regex'},
		'limit_cc': {'type': int, 'short': 'lcc', 'default': 1,
			'help': 'Limit Common Crawl index collections searched (0=all, default=1)'},
		'exclude_wayback': {'is_flag': True, 'short': 'xwm', 'help': 'Exclude Wayback Machine', 'default': False},
		'exclude_commoncrawl': {'is_flag': True, 'short': 'xcc', 'help': 'Exclude Common Crawl', 'default': False},
		'exclude_alienvault': {'is_flag': True, 'short': 'xav', 'help': 'Exclude AlienVault', 'default': False},
		'exclude_urlscan': {'is_flag': True, 'short': 'xus', 'help': 'Exclude URLScan', 'default': False},
		'exclude_virustotal': {'is_flag': True, 'short': 'xvt', 'help': 'Exclude VirusTotal', 'default': False},
		'exclude_intelx': {'is_flag': True, 'short': 'xix', 'help': 'Exclude Intelligence X', 'default': False},
		'max_param_occurrences': {'type': int, 'required': False, 'default': 10, 'internal': True,
			'help': 'Max occurrences for same parameter in same URL before discarding'},
		'stream': {'is_flag': True, 'help': 'Output URLs to STDOUT as soon as found', 'default': False},
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
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		THREADS: 'processes',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	install_cmd = 'pip install waymore'
	github_handle = 'xnl-h4ck3r/waymore'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def before_init(self):
		# Call parent's before_init to process raw HTTP request
		HttpCrawler.before_init(self)

		# Convert URLs to hostnames if needed
		for idx, input_val in enumerate(self.inputs):
			if validators.url(input_val):
				parsed = urlparse(input_val)
				if not parsed.path or parsed.path == '/':
					self.inputs[idx] = parsed.netloc
				else:
					self.inputs[idx] = f"{parsed.netloc}{parsed.path}"

	@staticmethod
	def on_init(self):
		self.max_param_occurrences = self.get_opt_value('max_param_occurrences')
		self.seen_params = defaultdict(lambda: defaultdict(int))

	@staticmethod
	def on_line(self, line):
		# waymore outputs URLs one per line in -mode U with --stream
		line = line.strip()
		if not line or line.startswith('[') or 'INFO' in line or 'ERROR' in line or 'WARNING' in line:
			return None
		# Try to parse as URL
		try:
			parsed_url = urlparse(line)
			if parsed_url.scheme and parsed_url.netloc:
				return json.dumps({'url': line})
		except Exception:
			pass
		return None

	@staticmethod
	def on_json_loaded(self, item):
		url = item.get('url')
		if not url:
			return

		parsed_url = urlparse(url)
		base_url = urlunparse(parsed_url._replace(query="", fragment=""))  # Remove query & fragment
		query_params = parse_qs(parsed_url.query)
		current_params = set(query_params.keys())

		# Check parameter occurrence limit
		for param in current_params:
			self.seen_params[base_url][param] += 1
			if self.seen_params[base_url][param] > int(self.max_param_occurrences):
				return

		yield Url(url=url, host=parsed_url.hostname)

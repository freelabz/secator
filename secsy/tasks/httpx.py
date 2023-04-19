from secsy.decorators import task
from secsy.definitions import (DEFAULT_HTTPX_FLAGS, DEPTH, DELAY, FILTER_CODES,
							   FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
							   FOLLOW_REDIRECT, HEADER, MATCH_CODES,
							   MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, URL, USER_AGENT)
from secsy.tasks._categories import Http
from secsy.utils import sanitize_url


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
		# 'asn': {'is_flag': True, 'default': False, 'help': 'ASN detection'},
		# 'cdn': {'is_flag': True, 'default': True, 'help': 'CDN detection'},
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
		MATCH_SIZE: 'm,atch-length',
		MATCH_WORDS: 'match-word-count',
		METHOD: 'x',
		PROXY: OPT_NOT_SUPPORTED,  # TODO: httpx supports only HTTP -proxy https://github.com/yt-dlp/yt-dlp/pull/3668
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
	def on_item_pre_convert(self, item):
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

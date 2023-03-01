from secsy.definitions import *
from secsy.tasks._categories import HTTPCommand
from secsy.utils import sanitize_url


class httpx(HTTPCommand):
	"""Fast and multi-purpose HTTP toolkit."""
	cmd = 'httpx'
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		'silent': {'is_flag': True, 'default': False, 'help': 'Silent mode'},
		'td': {'is_flag': True, 'default': True, 'help': 'Tech detection'},
		'asn': {'is_flag': True, 'default': False, 'help': 'ASN detection'},
		'cdn': {'is_flag': True, 'default': True, 'help': 'CDN detection'},
		'filter_code': {'type': str, 'help': 'Filter HTTP codes'},
		'filter_length': {'type': str, 'help': 'Filter length'},
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

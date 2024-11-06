from secator.decorators import task
from secator.definitions import (AUTO_CALIBRATION, CONTENT_LENGTH,
								 CONTENT_TYPE, DELAY, DEPTH, EXTRA_DATA,
								 FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
								 FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
								 MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
								 PERCENT, PROXY, RATE_LIMIT, RETRIES,
								 STATUS_CODE, THREADS, TIME, TIMEOUT,
								 USER_AGENT, WORDLIST)
from secator.output_types import Progress, Url
from secator.serializers import JSONSerializer, RegexSerializer
from secator.tasks._categories import HttpFuzzer

FFUF_PROGRESS_REGEX = r':: Progress: \[(?P<count>\d+)/(?P<total>\d+)\] :: Job \[\d/\d\] :: (?P<rps>\d+) req/sec :: Duration: \[(?P<duration>[\d:]+)\] :: Errors: (?P<errors>\d+) ::'  # noqa: E501


@task()
class ffuf(HttpFuzzer):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive -recursion'
	input_flag = '-u'
	input_chunk_size = 1
	file_flag = None
	json_flag = '-json'
	version_flag = '-V'
	item_loaders = [
		JSONSerializer(strict=True),
		RegexSerializer(FFUF_PROGRESS_REGEX, fields=['count', 'total', 'rps', 'duration', 'errors'])
	]
	opts = {
		AUTO_CALIBRATION: {'is_flag': True, 'short': 'ac', 'help': 'Auto-calibration'},
	}
	opt_key_map = {
		HEADER: 'H',
		DELAY: 'p',
		DEPTH: 'recursion-depth',
		FILTER_CODES: 'fc',
		FILTER_REGEX: 'fr',
		FILTER_SIZE: 'fs',
		FILTER_WORDS: 'fw',
		FOLLOW_REDIRECT: 'r',
		MATCH_CODES: 'mc',
		MATCH_REGEX: 'mr',
		MATCH_SIZE: 'ms',
		MATCH_WORDS: 'mw',
		METHOD: 'X',
		PROXY: 'x',
		RATE_LIMIT: 'rate',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 't',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,

		# ffuf opts
		WORDLIST: 'w',
		AUTO_CALIBRATION: 'ac',
	}
	output_types = [Url, Progress]
	output_map = {
		Url: {
			STATUS_CODE: 'status',
			CONTENT_LENGTH: 'length',
			CONTENT_TYPE: 'content-type',
			TIME: lambda x: x['duration'] * 10**-9
		},
		Progress: {
			PERCENT: lambda x: int(int(x['count']) * 100 / int(x['total'])),
			EXTRA_DATA: lambda x: {k: v for k, v in x.items() if k not in ['count', 'total', 'errors']}
		},
	}
	encoding = 'ansi'
	install_cmd = 'go install -v github.com/ffuf/ffuf@latest'
	install_github_handle = 'ffuf/ffuf'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_item(self, item):
		if isinstance(item, Url):
			item.method = self.get_opt_value(METHOD) or 'GET'
		return item

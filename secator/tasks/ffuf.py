from secator.decorators import task
from secator.definitions import (AUTO_CALIBRATION, CONTENT_LENGTH,
								 CONTENT_TYPE, DELAY, DEPTH, EXTRA_DATA,
								 FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
								 FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
								 MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
								 PERCENT, PROXY, RATE_LIMIT, RETRIES,
								 STATUS_CODE, THREADS, TIME, TIMEOUT,
								 USER_AGENT, WORDLIST, URL)
from secator.output_types import Progress, Url
from secator.serializers import JSONSerializer, RegexSerializer
from secator.tasks._categories import HttpFuzzer
from secator.utils import headers_to_dict


FFUF_PROGRESS_REGEX = r':: Progress: \[(?P<count>\d+)/(?P<total>\d+)\] :: Job \[\d/\d\] :: (?P<rps>\d+) req/sec :: Duration: \[(?P<duration>[\d:]+)\] :: Errors: (?P<errors>\d+) ::'  # noqa: E501


@task()
class ffuf(HttpFuzzer):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive'
	tags = ['url', 'fuzz']
	input_types = [URL]
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
		'recursion': {'is_flag': True, 'default': False, 'short': 'recursion', 'help': 'Recursion'},
		'fuzz_host_header': {'is_flag': True, 'default': False, 'internal': True, 'short': 'fhh', 'help': 'Fuzz host header'},
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
	install_version = 'v2.1.0'
	install_cmd = 'go install -v github.com/ffuf/ffuf/v2@[install_version]'
	install_github_handle = 'ffuf/ffuf'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def before_init(self):
		header_opt = self.get_opt_value('header')
		headers = headers_to_dict(header_opt)

		if self.get_opt_value('fuzz_host_header'):
			header = self.get_opt_value('header') or ''
			if header:
				header += ';; '
			if len(self.inputs) > 0:  # for dry-run
				host = self.inputs[0].split('://')[1].split('/')[0]
				headers['Host'] = f'FUZZ.{host}'

		self.headers = headers

	@staticmethod
	def on_cmd(self):
		for k, v in self.headers.items():
			header_str = f" -H '{k}: {v}'"
			if f'{k}:{v}'.replace(' ', '') not in self.cmd.replace(' ', ''):
				self.cmd += header_str

	@staticmethod
	def on_item_pre_convert(self, item):
		if 'host' in item:
			self.current_host = item['host']
		return item

	@staticmethod
	def on_item(self, item):
		if isinstance(item, Url):
			item.method = self.get_opt_value(METHOD) or 'GET'
			item.headers = self.headers.copy()
			if 'FUZZ' in self.headers.get('Host', ''):
				item.headers['Host'] = self.current_host
		return item

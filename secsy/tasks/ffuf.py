from secsy.decorators import task
from secsy.definitions import (AUTO_CALIBRATION, CONTENT_LENGTH, CONTENT_TYPE,
							   DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, STATUS_CODE, THREADS, TIME,
							   TIMEOUT, USER_AGENT, WORDLIST)
from secsy.output_types import Url
from secsy.tasks._categories import HttpFuzzer


@task()
class ffuf(HttpFuzzer):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive -recursion'
	input_flag = '-u'
	input_chunk_size = 1
	file_flag = None
	json_flag = '-json'
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
	output_map = {
		Url: {
			STATUS_CODE: 'status',
			CONTENT_LENGTH: 'length',
			CONTENT_TYPE: 'content-type',
			TIME: lambda x: x['duration'] * 10**-9
		}
	}
	encoding = 'ansi'
	install_cmd = (
		'go install -v github.com/ffuf/ffuf@latest && '
		'sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists'
	)

	@staticmethod
	def validate_input(self, input):
		"""No list input supported for this command. Pass a single input instead."""
		if isinstance(input, list):
			return False
		return True

	@staticmethod
	def on_item(self, item):
		item.method = self.cmd_opts.get(METHOD, 'GET')
		return item

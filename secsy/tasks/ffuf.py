from secsy.definitions import (AUTO_CALIBRATION, CONTENT_LENGTH, CONTENT_TYPE,
							   DEFAULT_FFUF_WORDLIST, DELAY, DEPTH,
							   FOLLOW_REDIRECT, HEADER, MATCH_CODES, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   STATUS_CODE, THREADS, TIME, TIMEOUT, USER_AGENT,
							   WORDLIST)
from secsy.output_types import Url
from secsy.tasks._categories import HTTPCommand


class ffuf(HTTPCommand):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive -recursion'
	input_flag = '-u'
	input_chunk_size = 1
	file_flag = None
	json_flag = '-json'
	opts = {
		AUTO_CALIBRATION: {'is_flag': True, 'short': 'ac', 'help': 'Auto-calibration'},
		WORDLIST: {'type': str, 'short': 'w', 'default': DEFAULT_FFUF_WORDLIST, 'help': 'Wordlist to fuzz from.'},
		'mw': {'type': str, 'help': 'Match responses with word count'},
		'mr': {'type': str, 'help': 'Match responses with regular expression'},
		'ms': {'type': str, 'help': 'Match respones with size'},
		'fc': {'type': str, 'help': 'Filter out responses with HTTP codes'},
		'fw': {'type': str, 'help': 'Filter out responses with word count'},
		'fr': {'type': str, 'help': 'Filter out responses with regular expression'},
		'fs': {'type': str, 'help': 'Filter out responses with size'},
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
	def on_item_converted(self, item):
		item.method = self.cmd_opts.get(METHOD, 'GET')
		return item

from urllib.parse import urlparse, urlunparse

from secsy.definitions import *
from secsy.tasks._categories import HTTPCommand


class ffuf(HTTPCommand):
	"""Fast web fuzzer written in Go."""
	cmd = 'ffuf -noninteractive -recursion'
	input_flag = '-u'
	input_chunk_size = 1
	file_flag = None
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
	def validate_input(self, input):
		"""No list input supported for this command. Pass a single input instead."""
		if isinstance(input, list):
			return False

		# Remove query path and add /FUZZ keyword
		self.input = urlunparse(urlparse(self.input)._replace(query="")).rstrip('/')
		self.input = f'{self.input}/FUZZ'
		return True

	@staticmethod
	def on_item_converted(self, item):
		item[METHOD] = self.cmd_opts.get(METHOD, 'GET')
		return item
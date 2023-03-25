from furl import furl

from secsy.definitions import *
from secsy.output_types import Url
from secsy.tasks._categories import HTTPCommand


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
		Url: {
			URL: 'output',
			STATUS_CODE: 'status',
			CONTENT_LENGTH: 'length',
		}
	}
	install_cmd = 'go install -v github.com/jaeles-project/gospider@latest'
	ignore_return_code = True

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
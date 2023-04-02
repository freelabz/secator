from secsy.definitions import (DELAY, DEPTH, FOLLOW_REDIRECT, HEADER,
							   MATCH_CODES, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, URL, USER_AGENT)
from secsy.tasks._categories import HTTPCommand


class cariddi(HTTPCommand):
	"""Crawl endpoints, secrets, api keys, extensions, tokens..."""
	cmd = 'cariddi -err -e -ext 1'
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
		if 'protocol error' not in line and self._json_output:
			return {URL: line}

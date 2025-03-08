from furl import furl

from secator.decorators import task
from secator.definitions import (CONTENT_LENGTH, DELAY, DEPTH, FILTER_CODES,
							   FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
							   FOLLOW_REDIRECT, HEADER, MATCH_CODES,
							   MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   STATUS_CODE, THREADS, TIMEOUT, URL, USER_AGENT)
from secator.output_types import Url
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler


@task()
class gospider(HttpCrawler):
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
		FILTER_CODES: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'no-redirect',
		MATCH_CODES: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
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
	item_loaders = [JSONSerializer()]
	output_map = {
		Url: {
			URL: 'output',
			STATUS_CODE: 'status',
			CONTENT_LENGTH: 'length',
		}
	}
	install_cmd = 'go install -v github.com/jaeles-project/gospider@latest'
	install_github_handle = 'jaeles-project/gospider'
	proxychains = False
	proxy_socks5 = True  # with leaks... https://github.com/jaeles-project/gospider/issues/61
	proxy_http = True  # with leaks... https://github.com/jaeles-project/gospider/issues/61
	profile = 'io'

	@staticmethod
	def validate_item(self, item):
		"""Keep only items that match the same host."""
		if not isinstance(item, dict):
			return False
		try:
			netloc_in = furl(item['input']).netloc
			netloc_out = furl(item['output']).netloc
			if netloc_in != netloc_out:
				return False
		except ValueError:  # gospider returns invalid URLs for output sometimes
			return False
		return True

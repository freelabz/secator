from urllib.parse import urlparse

from secsy.decorators import task
from secsy.definitions import (CONTENT_TYPE, DELAY, DEPTH, FILTER_CODES,
							   FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
							   FOLLOW_REDIRECT, HEADER, HOST, MATCH_CODES,
							   MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   STATUS_CODE, TECH, THREADS, TIME, TIMEOUT, URL,
							   USER_AGENT)
from secsy.output_types import Url
from secsy.tasks._categories import HttpCrawler


@task()
class katana(HttpCrawler):
	"""Next-generation crawling and spidering framework."""
	cmd = 'katana -silent -jc -js-crawl -known-files all'
	file_flag = '-list'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		'headless': {'is_flag': True, 'short': 'hl', 'help': 'Headless mode'},
		'system-chrome': {'is_flag': True, 'short': 'sc', 'help': 'Use local installed chrome browser'}
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: 'delay',
		DEPTH: 'depth',
		FILTER_CODES: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'concurrency',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		DELAY: lambda x: int(x) if isinstance(x, float) else x
	}
	output_map = {
		Url: {
			URL: lambda x: x['request']['endpoint'],
			HOST: lambda x: urlparse(x['request']['endpoint']).netloc,
			TIME: 'timestamp',
			METHOD: lambda x: x['request']['method'],
			STATUS_CODE: lambda x: x['response'].get('status_code'),
			CONTENT_TYPE: lambda x: x['response'].get('content_type', ';').split(';')[0],
			TECH: lambda x: x['response'].get('technologies', []),
			# TAGS: lambda x: x['response'].get('server')
		}
	}
	install_cmd = 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest'

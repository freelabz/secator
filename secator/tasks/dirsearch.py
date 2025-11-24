import yaml

from secator.decorators import task
from secator.definitions import (CONTENT_LENGTH, CONTENT_TYPE, DATA, DELAY, DEPTH,
							   FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
							   FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
							   MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, STATUS_CODE,
							   PERCENT, EXTRA_DATA, THREADS, TIMEOUT, USER_AGENT, WORDLIST, URL)
from secator.output_types import Url, Progress
from secator.tasks._categories import HttpFuzzer
from secator.serializers import RegexSerializer, FileSerializer

DIRSEARCH_PROGRESS_REGEX = r'\s+(?P<percent>\d+)%\s+(?P<reqs_current>\d+)/(?P<req_total>\d+)\s+(?P<rps>\d+)/s\s+job:(?P<job_current>\d+)/(?P<job_total>\d+)\s+errors:(?P<errors>\d+)'  # noqa: E501
DIRSEARCH_PROGRESS_FIELDS = ['percent', 'reqs_current', 'req_total', 'rps', 'job_current', 'job_total', 'errors']


@task()
class dirsearch(HttpFuzzer):
	"""Advanced web path brute-forcer."""
	cmd = 'dirsearch'
	input_types = [URL]
	output_types = [Url]
	tags = ['url', 'fuzz']
	input_flag = '-u'
	file_flag = '-l'
	json_flag = '-O json'
	opt_prefix = '--'
	encoding = 'ansi'
	opt_key_map = {
		HEADER: 'header',
		DATA: 'data',
		DELAY: 'delay',
		DEPTH: 'max-recursion-depth',
		FILTER_CODES: 'exclude-status',
		FILTER_REGEX: 'exclude-regex',
		FILTER_SIZE: 'exclude-sizes',
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirects',
		MATCH_CODES: 'include-status',
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		METHOD: 'http-method',
		PROXY: 'proxy',
		RATE_LIMIT: 'max-rate',
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
		WORDLIST: 'wordlists',
	}
	item_loaders = [
		RegexSerializer(DIRSEARCH_PROGRESS_REGEX, fields=DIRSEARCH_PROGRESS_FIELDS, findall=True),
		FileSerializer(output_flag='-o')
	]
	output_map = {
		Url: {
			CONTENT_LENGTH: 'content-length',
			CONTENT_TYPE: 'content-type',
			STATUS_CODE: 'status',
			'request_headers': 'request_headers'
		},
		Progress: {
			PERCENT: lambda x: int(x['percent']),
			EXTRA_DATA: lambda x: {k: v for k, v in x.items() if k != 'percent'}
		}
	}
	install_cmd = 'pipx install git+https://github.com/maurosoria/dirsearch.git --force'
	install_version = '0.4.3'
	proxychains = True
	proxy_socks5 = True
	proxy_http = True

	@staticmethod
	def on_file_loaded(self, content):
		results = yaml.safe_load(content).get('results', [])
		for result in results:
			result['request_headers'] = self.get_opt_value(HEADER, preprocess=True)
			yield result

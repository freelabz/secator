import json
import re

from secator.decorators import task
from secator.output_types import Url, Progress
from secator.definitions import (
	HEADER, DELAY, FOLLOW_REDIRECT, METHOD, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT,
	DEPTH, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, FILTER_REGEX, FILTER_CODES, FILTER_SIZE, FILTER_WORDS,
	MATCH_CODES, OPT_NOT_SUPPORTED, URL
)
from secator.serializers import JSONSerializer
from secator.tasks._categories import Http


@task()
class bup(Http):
	"""40X bypasser."""
	cmd = 'bup'
	input_flag = '-u'
	input_type = URL
	json_flag = '--jsonl'
	opt_prefix = '--'
	opts = {
		'spoofport': {'type': int, 'short': 'sp', 'help': 'Port(s) to inject in port-specific headers'},
		'spoofip': {'type': str, 'short': 'si', 'help': 'IP(s) to inject in ip-specific headers'},
		'mode': {'type': str, 'help': 'Bypass modes.'},
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_CODES: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
	}
	item_loaders = [JSONSerializer()]
	output_types = [Url, Progress]
	output_map = {
		Url: {
			'url': 'request_url',
			'method': lambda x: bup.method_extractor(x),
			'headers': lambda x: bup.headers_extractor(x),
			'status_code': 'response_status_code',
			'content_type': 'response_content_type',
			'content_length': 'response_content_length',
			'title': 'response_title',
			'server': 'response_server_type',
			'lines': 'response_lines_count',
			'words': 'response_words_count',
			'stored_response_path': 'response_html_filename',
		}
	}
	install_cmd = 'pipx install bypass-url-parser && pipx upgrade bypass-url-parser'

	@staticmethod
	def on_init(self):
		self.cmd += f' -o {self.reports_folder}/.outputs/response'

	@staticmethod
	def on_line(self, line):
		if 'Doing' in line:
			progress_indicator = line.split(':')[-1]
			current, total = tuple([int(c.strip()) for c in progress_indicator.split('/')])
			return json.dumps({"duration": "unknown", "percent": int((current / total) * 100)})
		elif 'batcat' in line:  # ignore batcat lines as they're loaded as JSON
			return None
		return line

	@staticmethod
	def method_extractor(item):
		payload = item['request_curl_payload']
		match = re.match(r'-X\s+(\w+)', payload)
		if match:
			return match.group(1)
		return 'GET'

	@staticmethod
	def headers_extractor(item):
		headers_list = item['response_headers'].split('\n')[1:]
		headers = {}
		for header in headers_list:
			split_headers = header.split(':')
			key = split_headers[0]
			value = ':'.join(split_headers[1:])
			headers[key] = value
		return headers

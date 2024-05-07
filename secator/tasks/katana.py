import os
import json
from urllib.parse import urlparse

from secator.decorators import task
from secator.definitions import (CONTENT_TYPE, DEFAULT_KATANA_FLAGS,
								 DELAY, DEPTH,
								 FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
								 FILTER_WORDS, FOLLOW_REDIRECT, HEADER, HOST,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
								 MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PROXY,
								 RATE_LIMIT, RETRIES, STATUS_CODE,
								 STORED_RESPONSE_PATH, TECH,
								 THREADS, TIME, TIMEOUT, URL, USER_AGENT, WEBSERVER, CONTENT_LENGTH)
from secator.config import CONFIG
from secator.output_types import Url, Tag
from secator.tasks._categories import HttpCrawler


@task()
class katana(HttpCrawler):
	"""Next-generation crawling and spidering framework."""
	# TODO: add -fx for form detection and extract 'forms' from the output with custom item_loader
	# TODO: add -jsluice for JS parsing
	cmd = f'katana {DEFAULT_KATANA_FLAGS}'
	file_flag = '-list'
	input_flag = '-u'
	json_flag = '-jsonl'
	opts = {
		'headless': {'is_flag': True, 'short': 'hl', 'help': 'Headless mode'},
		'system_chrome': {'is_flag': True, 'short': 'sc', 'help': 'Use local installed chrome browser'},
		'form_extraction': {'is_flag': True, 'short': 'fx', 'help': 'Detect forms'},
		'store_responses': {'is_flag': True, 'short': 'sr', 'default': CONFIG.http.store_responses, 'help': 'Store responses'}
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
		USER_AGENT: OPT_NOT_SUPPORTED,
		'store_responses': 'sr'
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
			CONTENT_TYPE: lambda x: x['response'].get('headers', {}).get('content_type', ';').split(';')[0],
			CONTENT_LENGTH: lambda x: x['response'].get('headers', {}).get('content_length', 0),
			WEBSERVER: lambda x: x['response'].get('headers', {}).get('server', ''),
			TECH: lambda x: x['response'].get('technologies', []),
			STORED_RESPONSE_PATH: lambda x: x['response'].get('stored_response_path', '')
			# TAGS: lambda x: x['response'].get('server')
		}
	}
	item_loaders = []
	install_cmd = 'sudo apt install build-essential && go install -v github.com/projectdiscovery/katana/cmd/katana@latest'
	install_github_handle = 'projectdiscovery/katana'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def item_loader(self, item):
		try:
			item = json.loads(item)
		except json.JSONDecodeError:
			return None

		# form detection
		forms = item.get('response', {}).get('forms', [])
		if forms:
			for form in forms:
				method = form['method']
				yield Url(form['action'], host=urlparse(item['request']['endpoint']).netloc, method=method)
				yield Tag(
					name='form',
					match=form['action'],
					extra_data={
						'method': form['method'],
						'enctype': form.get('enctype', ''),
						'parameters': ','.join(form.get('parameters', []))
					}
				)
		yield item

	@staticmethod
	def on_init(self):
		debug_resp = self.get_opt_value('debug_resp')
		if debug_resp:
			self.cmd = self.cmd.replace('-silent', '')
		store_responses = self.get_opt_value('store_responses')
		if store_responses:
			self.cmd += f' -srd {self.reports_folder}/.outputs'

	@staticmethod
	def on_item(self, item):
		if not isinstance(item, Url):
			return item
		store_responses = self.get_opt_value('store_responses')
		if store_responses and os.path.exists(item.stored_response_path):
			with open(item.stored_response_path, 'r', encoding='latin-1') as fin:
				data = fin.read().splitlines(True)
				first_line = data[0]
			with open(item.stored_response_path, 'w', encoding='latin-1') as fout:
				fout.writelines(data[1:])
				fout.writelines('\n')
				fout.writelines(first_line)
		return item

	@staticmethod
	def on_end(self):
		store_responses = self.get_opt_value('store_responses')
		index_rpath = f'{self.reports_folder}/.outputs/index.txt'
		if store_responses and os.path.exists(index_rpath):
			os.remove(index_rpath)

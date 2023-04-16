import os

import yaml

from secsy.decorators import task
from secsy.definitions import (CONTENT_LENGTH, CONTENT_TYPE, DELAY, DEPTH,
							   FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
							   FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
							   MATCH_CODES, MATCH_REGEX,
							   MATCH_SIZE, MATCH_WORDS, METHOD,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   STATUS_CODE, TEMP_FOLDER, THREADS, TIMEOUT,
							   USER_AGENT, WORDLIST)
from secsy.output_types import Url
from secsy.tasks._categories import HttpFuzzer
from secsy.utils import get_file_timestamp


@task()
class dirsearch(HttpFuzzer):
	"""Advanced web path brute-forcer."""
	cmd = 'dirsearch -q'
	input_flag = '-u'
	file_flag = '-l'
	json_flag = '--format json'
	opt_prefix = '--'
	encoding = 'ansi'
	opt_key_map = {
		HEADER: 'header',
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
	output_map = {
		Url: {
			CONTENT_LENGTH: 'content-length',
			CONTENT_TYPE: 'content-type',
			STATUS_CODE: 'status'
		}
	}
	install_cmd = 'pip3 install dirsearch'

	def __iter__(self):
		prev = self._print_item_count
		self._print_item_count = False
		list(super().__iter__())
		if self.return_code != 0:
			return
		self.results = []
		if not self._json_output:
			return
		note = f'dirsearch JSON results saved to {self.output_path}'
		if self._print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				results = yaml.safe_load(f.read()).get('results', [])
			for item in results:
				item = self._process_item(item)
				if not item:
					continue
				yield item
		self._print_item_count = prev
		self._process_results()

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value('output_path')
		if not self.output_path:
			timestr = get_file_timestamp()
			self.output_path = f'{TEMP_FOLDER}/dirsearch_{timestr}.json'
		self.cmd += f' -o {self.output_path}'

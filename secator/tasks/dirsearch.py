import os

import yaml

from secator.decorators import task
from secator.definitions import (CONTENT_LENGTH, CONTENT_TYPE, DELAY, DEPTH,
							   FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
							   FILTER_WORDS, FOLLOW_REDIRECT, HEADER,
							   MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
							   RATE_LIMIT, RETRIES, STATUS_CODE,
							   THREADS, TIMEOUT, USER_AGENT, WORDLIST)
from secator.output_types import Url, Info, Error
from secator.tasks._categories import HttpFuzzer


@task()
class dirsearch(HttpFuzzer):
	"""Advanced web path brute-forcer."""
	cmd = 'dirsearch'
	input_flag = '-u'
	file_flag = '-l'
	json_flag = '-O json'
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
	install_cmd = 'pipx install --force git+https://github.com/maurosoria/dirsearch'
	proxychains = True
	proxy_socks5 = True
	proxy_http = True
	profile = 'io'

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.cmd += f' -o {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read()).get('results', [])
		yield from results

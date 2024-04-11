import shlex
from pathlib import Path

from secator.decorators import task
from secator.definitions import (CONTENT_TYPE, DELAY, DEPTH, FILTER_CODES,
							   FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
							   FOLLOW_REDIRECT, HEADER, LINES, MATCH_CODES,
							   MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD,
							   OPT_NOT_SUPPORTED, OPT_PIPE_INPUT, OUTPUT_PATH, PROXY,
							   RATE_LIMIT, RETRIES, STATUS_CODE,
							   THREADS, TIMEOUT, USER_AGENT, WORDLIST, WORDS, DEFAULT_FEROXBUSTER_FLAGS)
from secator.output_types import Url
from secator.tasks._categories import HttpFuzzer


@task()
class feroxbuster(HttpFuzzer):
	"""Simple, fast, recursive content discovery tool written in Rust"""
	cmd = f'feroxbuster {DEFAULT_FEROXBUSTER_FLAGS}'
	input_flag = '--url'
	input_chunk_size = 1
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	opts = {
		# 'auto_tune': {'is_flag': True, 'default': False, 'help': 'Automatically lower scan rate when too many errors'},
		'extract_links': {'is_flag': True, 'default': False, 'help': 'Extract links from response body'},
		'collect_backups': {'is_flag': True, 'default': False, 'help': 'Request likely backup exts for urls'},
		'collect_extensions': {'is_flag': True, 'default': False, 'help': 'Discover exts and add to --extensions'},
		'collect_words': {'is_flag': True, 'default': False, 'help': 'Discover important words and add to wordlist'},
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: 'depth',
		FILTER_CODES: 'filter-status',
		FILTER_REGEX: 'filter-regex',
		FILTER_SIZE: 'filter-size',
		FILTER_WORDS: 'filter-words',
		FOLLOW_REDIRECT: 'redirects',
		MATCH_CODES: 'status-codes',
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		METHOD: 'methods',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
		WORDLIST: 'wordlist'
	}
	output_map = {
		Url: {
			STATUS_CODE: 'status',
			CONTENT_TYPE: lambda x: x['headers'].get('content-type'),
			LINES: 'line_count',
			WORDS: 'word_count'
		}
	}
	install_cmd = (
		'sudo apt install -y unzip curl && '
		'curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | '
		'bash && sudo mv feroxbuster /usr/local/bin'
	)
	install_github_handle = 'epi052/feroxbuster'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = 'cpu'

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		Path(self.output_path).touch()
		self.cmd += f' --output {self.output_path}'

	@staticmethod
	def on_start(self):
		if self.input_path:
			self.cmd += ' --stdin'
		self.cmd += f' & tail --pid=$! -f {shlex.quote(self.output_path)}'
		self.shell = True

	@staticmethod
	def validate_item(self, item):
		return item['type'] == 'response'

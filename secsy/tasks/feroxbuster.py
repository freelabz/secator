import shlex
from pathlib import Path

from secsy.definitions import (CONTENT_TYPE, DELAY, DEPTH, FOLLOW_REDIRECT,
							   HEADER, LINES, MATCH_CODES, METHOD,
							   OPT_NOT_SUPPORTED, OPT_PIPE_INPUT, PROXY,
							   RATE_LIMIT, RETRIES, STATUS_CODE, TEMP_FOLDER,
							   THREADS, TIMEOUT, USER_AGENT, WORDS)
from secsy.output_types import Url
from secsy.tasks._categories import HTTPCommand
from secsy.utils import get_file_timestamp


class feroxbuster(HTTPCommand):
	"""Simple, fast, recursive content discovery tool written in Rust"""
	cmd = 'feroxbuster'
	input_flag = '--url'
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	opts = {
		'wordlist': {'type': str, 'help': 'Wordlist'},
		'auto_tune': {'is_flag': True, 'help': 'Automatically lower scan rate when too many errors are encountered'},
		'extract_links': {'is_flag': True, 'default': True, 'help': 'Extract links from response body'},
		'collect_backups': {'is_flag': True, 'help': 'Request likely backup extensions for found urls'},
		'collect_extensions': {'is_flag': True, 'help': 'Discover extensions and add them to --extensions'},
		'collect_words': {'is_flag': True, 'help': 'Discover important words and add them to the wordlist'},
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: 'depth',
		FOLLOW_REDIRECT: 'redirects',
		MATCH_CODES: 'status-codes',
		METHOD: 'methods',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
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
		'sudo apt install -y unzip && '
		'curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | '
		'bash && sudo mv feroxbuster /usr/local/bin'
	)

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value('output_path')
		if not self.output_path:
			timestr = get_file_timestamp()
			self.output_path = f'{TEMP_FOLDER}/feroxbuster_{timestr}.json'
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

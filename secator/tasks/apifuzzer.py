import glob
import json
import os
import uuid

from secator.decorators import task
from secator.definitions import (AUTO_CALIBRATION, DELAY, DEPTH, FILTER_CODES,
								 FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
								 FOLLOW_REDIRECT, HEADER, MATCH_CODES,
								 MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD,
								 OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
								 STATUS_CODE, TASKS_FOLDER, THREADS, TIMEOUT,
								 URL, USER_AGENT, WORDLIST)
from secator.output_types import Url
from secator.tasks._categories import HttpFuzzer


@task()
class apifuzzer(HttpFuzzer):
	"""Reads API description (swagger / openapi) and fuzzes the fields to validate if you application can cope with the
	fuzzed parameters"""
	cmd = 'APIFuzzer --basic_output=True'
	input_flag = '-u'
	file_flag = None
	opt_prefix = '-'
	input_chunk_size = 1
	json_flag = None
	output_map = {
		Url: {
			URL: 'request_url',
			STATUS_CODE: 'parsed_status_code',
			METHOD: 'request_method',
		}
	}
	opts = {
		's': {'type': str, 'short': 's', 'help': 'API definition file path (JSON / YAML).', 'required': True}
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
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
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
		WORDLIST: OPT_NOT_SUPPORTED,
		AUTO_CALIBRATION: OPT_NOT_SUPPORTED,
	}
	install_cmd = (
		'pip install APIFuzzer'
	)
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	def yielder(self):
		for _ in super().yielder():
			files = self.get_files()
			new_files = [f for f in files if f not in self.file_cache]
			self.file_cache.extend(new_files)
			if new_files:
				for fpath in new_files:
					with open(fpath, 'r') as f:
						try:
							content = json.loads(f.read())
							yield content
						except Exception:
							pass

	def get_files(self):
		return glob.glob(f'{self.output_path}/*.json')

	# @staticmethod
	# def before_init(self):
		# print(self.input)
		# print(self.input)
		# if os.path.exists(self.input):
		# else:  # url
		# 	resp = requests.get(self.input).json()
		# 	with open('')

	@staticmethod
	def on_init(self):
		_id = uuid.uuid4()
		self.file_cache = []
		self.output_path = f'{TASKS_FOLDER}/{_id}'
		os.makedirs(self.output_path, exist_ok=True)
		self.cmd += f' -r {self.output_path}'

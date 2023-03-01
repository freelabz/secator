from datetime import datetime

import yaml

from secsy.definitions import *
from secsy.tasks._categories import HTTPCommand


class dirsearch(HTTPCommand):
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
		FOLLOW_REDIRECT: 'follow-redirects',
		MATCH_CODES: 'include-status',
		METHOD: 'http-method',
		PROXY: 'proxy',
		RATE_LIMIT: 'max-rate',
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
	}
	output_map = {
		CONTENT_LENGTH: 'content-length',
		CONTENT_TYPE: 'content-type',
		STATUS_CODE: 'status'
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
			timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
			self.output_path = f'{TEMP_FOLDER}/dirsearch_{timestr}.json'
		self.cmd += f' -o {self.output_path}'
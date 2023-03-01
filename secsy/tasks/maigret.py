import json
import logging
import re

from secsy.definitions import *
from secsy.tasks._categories import ReconCommand

logger = logging.getLogger(__name__)


class maigret(ReconCommand):
	"""Collects a dossier on a person by username."""
	cmd = 'maigret'
	file_flag = None
	input_flag = None
	json_flag = '--json ndjson'
	opt_prefix = '--'
	opts = {
		'site': {'type': str, 'help': 'Sites to check'},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED
	}
	input_type = USERNAME
	output_schema = ['sitename', 'username', 'url_user']
	output_type = USER_ACCOUNT
	install_cmd = 'pip3 install maigret'

	def __iter__(self):
		prev = self._print_item_count
		self._print_item_count = False
		list(super().__iter__())
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_path:
			match = re.search('JSON ndjson report for ocervell saved in (.*)', self.output)
			if match is None:
				logger.warning('JSON output file not found in command output.')
				return
			self.output_path = match.group(1)
		note = f'maigret JSON results saved to {self.output_path}'
		if self._print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				data = [json.loads(line) for line in f.read().splitlines()]
			for item in data:
				item = self._process_item(item)
				if not item:
					continue
				yield item
		self._print_item_count = prev
		self._process_results()

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value('output_path')
		self.output_path = output_path

	@staticmethod
	def validate_item(self, item):
		return item['http_status'] == 200
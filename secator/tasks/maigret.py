import json
import logging
import os
import re

from secator.decorators import task
from secator.definitions import (DELAY, EXTRA_DATA, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
								 RATE_LIMIT, RETRIES, SITE_NAME, THREADS,
								 TIMEOUT, URL, USERNAME)
from secator.output_types import UserAccount
from secator.tasks._categories import ReconUser

logger = logging.getLogger(__name__)


@task()
class maigret(ReconUser):
	"""Collect a dossier on a person by username."""
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
	output_types = [UserAccount]
	output_map = {
		UserAccount: {
			SITE_NAME: 'sitename',
			URL: lambda x: x['status']['url'],
			EXTRA_DATA: lambda x: x['status'].get('ids', {})
		}
	}
	install_cmd = 'pipx install git+https://github.com/soxoj/maigret@6be2f409e58056b1ca8571a8151e53bef107dedc'
	socks5_proxy = True
	profile = 'io'

	def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		yield from super().yielder()
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_path:
			match = re.search('JSON ndjson report for .* saved in (.*)', self.output)
			if match is None:
				logger.warning('JSON output file not found in command output.')
				return
			self.output_path = match.group(1)
		note = f'maigret JSON results saved to {self.output_path}'
		if self.print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				data = [json.loads(line) for line in f.read().splitlines()]
			for item in data:
				yield item
		self.print_item_count = prev

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		self.output_path = output_path

	@staticmethod
	def validate_item(self, item):
		return item['http_status'] == 200

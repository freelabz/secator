import json
import logging
import os
import re

from secator.decorators import task
from secator.definitions import (DELAY, EXTRA_DATA, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
								 RATE_LIMIT, RETRIES, SITE_NAME, THREADS,
								 TIMEOUT, URL, USERNAME)
from secator.output_types import UserAccount, Info, Error
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

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		self.output_path = output_path

	@staticmethod
	def on_cmd_done(self):
		# Search output path in cmd output
		if not self.output_path:
			match = re.search('JSON ndjson report for .* saved in (.*)', self.output)
			if match is None:
				yield Error(message='JSON output file not found in command output.')
				return
			self.output_path = match.group(1)

		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			data = [json.loads(line) for line in f.read().splitlines()]
		for item in data:
			yield item

	@staticmethod
	def validate_item(self, item):
		if isinstance(item, dict):
			return item['http_status'] == 200
		return True

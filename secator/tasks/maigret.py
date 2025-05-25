import json
import logging

from secator.decorators import task
from secator.definitions import (DELAY, EXTRA_DATA, OPT_NOT_SUPPORTED, PROXY,
								 RATE_LIMIT, RETRIES, SITE_NAME, THREADS,
								 TIMEOUT, URL, USERNAME, STRING)
from secator.output_types import UserAccount
from secator.tasks._categories import ReconUser
from secator.serializers.file import FileSerializer
logger = logging.getLogger(__name__)


MAIGRET_OUTPUT_FILE_REGEX = r'JSON ndjson report for .* saved in (.*)'


@task()
class maigret(ReconUser):
	"""Collect a dossier on a person by username."""
	cmd = 'maigret'
	input_types = [STRING]
	output_types = [UserAccount]
	tags = ['user', 'recon', 'username']
	file_flag = None
	input_flag = None
	json_flag = '--json ndjson'
	item_loaders = [FileSerializer(output_path_regex=MAIGRET_OUTPUT_FILE_REGEX)]
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
	output_map = {
		UserAccount: {
			SITE_NAME: 'sitename',
			URL: lambda x: x['status']['url'],
			EXTRA_DATA: lambda x: x['status'].get('ids', {})
		}
	}
	install_version = '0.5.0a'
	install_cmd = 'pipx install git+https://github.com/soxoj/maigret --force'
	socks5_proxy = True
	profile = 'io'

	@staticmethod
	def on_file_loaded(self, content):
		data = [json.loads(line) for line in content.splitlines()]
		for item in data:
			yield item

	@staticmethod
	def validate_item(self, item):
		if isinstance(item, dict):
			return item['http_status'] == 200
		return True

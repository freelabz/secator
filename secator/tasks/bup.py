import re

from secator.decorators import task
from secator.tasks._categories import Http
from secator.definitions import OPT_NOT_SUPPORTED
from secator.output_types import Url, Vulnerability
from urllib.parse import urlparse


@task()
class bup(Http):
	"""Tool that tests MANY url bypasses to reach a 40X protected page."""
	cmd = 'bup -S 2'
	json_flag = '--jsonl'
	input_flag = '--url'
	install_cmd = 'pipx install bypass-url-parser==0.4.2b0'
	opt_key_map = {
		'threads': '--threads',
		'depth': OPT_NOT_SUPPORTED,
	}
	output_types = [Url, Vulnerability]
	output_map = {
		Url: {
			'url': 'request_url',
			'host': lambda x: urlparse(x['request_url']).netloc,
			'method': lambda x: bup.method_extractor(x),
			'status_code': 'response_status_code',
			'title': 'response_title',
			'lines': 'response_lines_count',
			'words': 'response_words_count',
			'webserver': 'response_server_type',
			'content_type': 'response_content_type',
			'content_length': 'response_content_length',
			'stored_response_path': 'response_html_filename'
		}
	}

	@staticmethod
	def on_item_pre_convert(self, item):
		if self.orig:
			return item
		if item.get('response_status_code', 0) == 200:
			payload = item['request_curl_payload']
			return Vulnerability(
				name='Bypassed 4xx',
				matched_at=self.input,
				confidence='high',
				severity='medium',
				tags=['bypass-4xx'],
				extra_data={'payload': payload}
			)
		return item

	@staticmethod
	def method_extractor(item):
		payload = item['request_curl_payload']
		match = re.match(r'-X\s+(\w+)', payload)
		if match:
			return match.group(0)
		else:
			return 'GET'

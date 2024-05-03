import os
import re
import yaml

from secator.decorators import task
from secator.tasks._categories import Http
from secator.definitions import OPT_NOT_SUPPORTED
from pathlib import Path
from secator.output_types import Url, Vulnerability
from urllib.parse import urlparse


@task()
class bup(Http):
	"""Tool that tests MANY url bypasses to reach a 40X protected page."""
	cmd = 'bup'
	input_flag = '--url'
	install_cmd = 'pipx install bypass-url-parser'
	opts = {
		'output_dir': {'type': str, 'help': 'NSE scripts'},
	}
	opt_key_map = {
		'output_dir': '--outdir',
		'threads': '--threads',
		'depth': OPT_NOT_SUPPORTED,
	}
	output_types = [Url, Vulnerability]
	output_map = {
		Url: {
			'url': 'url',
			'host': lambda x: urlparse(x['url']).netloc,
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

	def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		list(super().yielder())
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_json:
			return
		self.output_path = self.output_path or list(Path(self.output_dir).glob('*.json'))[0]
		note = f'bup JSON results saved to {self.output_path}'
		print(self.output_path)
		if self.print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				results = yaml.safe_load(f.read()).get('results', [])
			for item in results:
				init_item = item
				item['url'] = self.input
				item = self._process_item(item)
				if not item:
					continue
				yield item
				if item.status_code == 200:  # successfully bypassed
					payload = init_item['request_curl_payload']
					yield Vulnerability(
						name='Bypassed 4xx',
						matched_at=self.input,
						confidence='high',
						severity='medium',
						tags=['bypass-4xx'],
						extra_data={'payload': payload}
					)
		self.print_item_count = prev

	@staticmethod
	def on_init(self):
		self.output_path = self.get_opt_value('output_path')
		self.output_dir = self.get_opt_value('output_dir')
		if not self.output_dir:
			self.output_dir = f'{self.reports_folder}/.outputs/report'
		self.cmd += f' -o {self.output_dir}'

	@staticmethod
	def method_extractor(item):
		payload = item['request_curl_payload']
		match = re.match(r'-X\s+(\w+)', payload)
		if match:
			return match.group(0)
		else:
			return 'GET'

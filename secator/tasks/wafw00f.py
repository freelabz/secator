import os
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, HEADER, PROXY, URL, TIMEOUT)
from secator.output_types import Tag, Info, Error
from secator.tasks._categories import OPTS


@task()
class wafw00f(Command):
	"""Web Application Firewall Fingerprinting tool."""
	cmd = 'wafw00f'
	tags = ['waf', 'scan']
	input_types = [URL]
	input_flag = None
	file_flag = '-i'
	json_flag = '-f json'
	encoding = 'ansi'
	opt_prefix = '--'
	meta_opts = {
		PROXY: OPTS[PROXY],
		HEADER: OPTS[HEADER],
		TIMEOUT: OPTS[TIMEOUT]
	}
	opts = {
		'list': {'is_flag': True, 'default': False, 'help': 'List all WAFs that WAFW00F is able to detect'},
		'waf_type': {'type': str, 'short': 'wt', 'help': 'Test for one specific WAF'},
		'find_all': {'is_flag': True, 'short': 'ta', 'default': False, 'help': 'Find all WAFs which match the signatures, do not stop testing on the first one'},  # noqa: E501
		'no_follow_redirects': {'is_flag': True, 'short': 'nfr', 'default': False, 'help': 'Do not follow redirections given by 3xx responses'},  # noqa: E501
	}
	opt_key_map = {
		HEADER: 'headers',
		PROXY: 'proxy',
		'waf_type': 'test',
		'find_all': 'findall',
		'no_follow_redirects': 'noredirect',
	}
	output_types = [Tag]
	install_version = 'v2.3.1'
	install_cmd = 'pipx install git+https://github.com/EnableSecurity/wafw00f.git@[install_version] --force'
	install_github_handle = 'EnableSecurity/wafw00f'
	proxy_http = True

	@staticmethod
	def on_cmd(self):
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.cmd += f' -o {self.output_path}'

		self.headers = self.get_opt_value(HEADER)
		if self.headers:
			header_file = f'{self.reports_folder}/.inputs/headers.txt'
			with open(header_file, 'w') as f:
				for header in self.headers.split(';;'):
					f.write(f'{header}\n')
			self.cmd = self.cmd.replace(self.headers, header_file)

	@staticmethod
	def on_cmd_done(self):
		# Skip parsing if list mode
		list_mode = self.get_opt_value('list')
		if list_mode:
			return

		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())

		if len(results) > 0 and results[0]['detected']:
			waf_name = results[0]['firewall']
			url = results[0]['url']
			match = results[0]['trigger_url']
			manufacter = results[0]['manufacturer']
			yield Tag(
				name=waf_name + ' WAF',
				match=url,
				extra_data={'waf_name': waf_name, 'manufacter': manufacter, 'trigger_url': match}
			)

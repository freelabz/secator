import tempfile
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import HEADER, PROXY, URL, TIMEOUT
from secator.output_types import Tag
from secator.serializers.file import FileSerializer
from secator.tasks._categories import OPTS


@task()
class wafw00f(Command):
	"""Web Application Firewall Fingerprinting tool."""
	cmd = 'wafw00f'
	input_types = [URL]
	output_types = [Tag]
	tags = ['waf', 'scan']
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
	opt_value_map = {
		HEADER: lambda x: wafw00f.headers_to_file(x)
	}
	opt_key_map = {
		HEADER: 'headers',
		PROXY: 'proxy',
		'waf_type': 'test',
		'find_all': 'findall',
		'no_follow_redirects': 'noredirect',
	}
	item_loaders = [FileSerializer(output_flag='-o')]
	install_version = 'v2.3.1'
	install_cmd = 'pipx install git+https://github.com/EnableSecurity/wafw00f.git@[install_version] --force'
	install_github_bin = False
	github_handle = 'EnableSecurity/wafw00f'
	proxy_http = True

	@staticmethod
	def on_cmd(self):
		self.headers = self.get_opt_value(HEADER)
		if self.headers:
			header_file = f'{self.reports_folder}/.inputs/headers.txt'
			with open(header_file, 'w') as f:
				for header in self.headers.split(';;'):
					f.write(f'{header}\n')
			self.cmd = self.cmd.replace(self.headers, header_file)

	@staticmethod
	def on_file_loaded(self, content):
		# Skip parsing if list mode
		list_mode = self.get_opt_value('list')
		if list_mode:
			return

		results = yaml.safe_load(content)
		if len(results) > 0 and results[0]['detected']:
			waf_name = results[0]['firewall']
			url = results[0]['url']
			match = results[0]['trigger_url']
			manufacter = results[0]['manufacturer']
			yield Tag(
				category='info',
				name='waf',
				match=url,
				extra_data={
					'content': waf_name,
					'manufacter': manufacter,
					'trigger_url': match,
					'headers': self.get_opt_value('header', preprocess=True)
				}
			)

	@staticmethod
	def headers_to_file(headers):
		temp_dir = tempfile.gettempdir()
		header_file = f'{temp_dir}/headers.txt'
		with open(header_file, 'w') as f:
			for header in headers.split(';;'):
				f.write(f'{header}\n')
		return header_file

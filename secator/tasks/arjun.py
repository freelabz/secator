import os
import yaml

from secator.decorators import task
from secator.definitions import (OUTPUT_PATH, RATE_LIMIT, THREADS, DELAY, TIMEOUT, METHOD, WORDLIST,
								 HEADER, URL, FOLLOW_REDIRECT)
from secator.output_types import Info, Url, Warning, Error
from secator.runners import Command
from secator.tasks._categories import OPTS
from secator.utils import process_wordlist


@task()
class arjun(Command):
	"""HTTP Parameter Discovery Suite."""
	cmd = 'arjun'
	tags = ['url', 'fuzz', 'params']
	input_flag = '-u'
	input_types = [URL]
	version_flag = ' '
	opts = {
		'chunk_size': {'type': int, 'help': 'Control query/chunk size'},
		'stable': {'is_flag': True, 'default': False, 'help': 'Use stable mode'},
		'include': {'type': str, 'help': 'Include persistent data (e.g: "api_key=xxxxx" or {"api_key": "xxxx"})'},
		'passive': {'is_flag': True, 'default': False, 'help': 'Passive mode'},
		'casing': {'type': str, 'help': 'Casing style for params e.g. like_this, likeThis, LIKE_THIS, like_this'},  # noqa: E501
		WORDLIST: {'type': str, 'short': 'w', 'default': None, 'process': process_wordlist, 'help': 'Wordlist to use (default: arjun wordlist)'},  # noqa: E501
	}
	meta_opts = {
		THREADS: OPTS[THREADS],
		DELAY: OPTS[DELAY],
		TIMEOUT: OPTS[TIMEOUT],
		RATE_LIMIT: OPTS[RATE_LIMIT],
		METHOD: OPTS[METHOD],
		HEADER: OPTS[HEADER],
		FOLLOW_REDIRECT: OPTS[FOLLOW_REDIRECT],
	}
	opt_key_map = {
		THREADS: 't',
		DELAY: 'd',
		TIMEOUT: 'T',
		RATE_LIMIT: '--rate-limit',
		METHOD: 'm',
		WORDLIST: 'w',
		HEADER: '--headers',
		'chunk_size': 'c',
		'stable': '--stable',
		'passive': '--passive',
		'casing': '--casing',
		'follow_redirect': '--follow-redirect',
	}
	output_types = [Url]
	install_version = '2.2.7'
	install_cmd = 'pipx install arjun==[install_version] --force'
	install_github_handle = 's0md3v/Arjun'

	@staticmethod
	def on_line(self, line):
		if 'Processing chunks' in line:
			return ''
		return line

	@staticmethod
	def on_cmd(self):
		follow_redirect = self.get_opt_value(FOLLOW_REDIRECT)
		self.cmd = self.cmd.replace(' --follow-redirect', '')
		if not follow_redirect:
			self.cmd += ' --disable-redirects'

		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.cmd += f' -oJ {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())
			if not results:
				yield Warning(message='No results found !')
				return
		for url, values in results.items():
			for param in values['params']:
				yield Url(
					url=url + '?' + param + '=' + 'FUZZ',
					headers=values['headers'],
					method=values['method'],
				)

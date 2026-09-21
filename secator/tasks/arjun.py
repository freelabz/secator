import os
import shlex
from urllib.parse import urlparse, urlunparse

import yaml

from secator.decorators import task

# fmt: off
from secator.definitions import (
	DATA, DELAY, FOLLOW_REDIRECT, HEADER, METHOD, OPT_NOT_SUPPORTED, OUTPUT_PATH, RATE_LIMIT, RETRIES, THREADS, TIMEOUT,
	URL, USER_AGENT, WORDLIST
)
# fmt: on
from secator.output_types import Info, Tag, Url, Warning
from secator.tasks._categories import HttpBase
from secator.utils import process_wordlist


@task()
class arjun(HttpBase):
	"""HTTP Parameter Discovery Suite."""
	# Prod peaks ~284 MiB / ~566 mc, against the small pool's admitted
	# 500m / 512 MiB -- CPU is already over the request (throttled), and memory
	# is close enough that a heavier target OOMs the pod. That kills PID 1, so it
	# surfaces as an abandoned task with no error rather than an OOMKilled event.
	# Low sample (n=1); medium costs only +0.5 GiB billed at this pool's tiny
	# pod-hours, so the trade is heavily in favour of not OOMing.
	profile = 'medium'

	cmd = 'arjun'
	input_types = [URL]
	output_types = [Url, Tag]
	tags = ['url', 'fuzz', 'params']
	input_flag = '-u'
	file_flag = '-i'
	version_flag = ' '
	opts = {
		'chunk_size': {'type': int, 'help': 'Control query/chunk size'},
		'stable': {'is_flag': True, 'default': False, 'help': 'Use stable mode'},
		'include': {'type': str, 'help': 'Include persistent data (e.g: "api_key=xxxxx" or {"api_key": "xxxx"})'},
		'passive': {'is_flag': True, 'default': False, 'help': 'Passive mode'},
		'casing': {'type': str, 'help': 'Casing style for params e.g. like_this, likeThis, LIKE_THIS, like_this'},  # noqa: E501
		WORDLIST: {'type': str, 'short': 'w', 'default': 'burp-parameter-names', 'process': process_wordlist, 'help': 'Wordlist to use (default: arjun wordlist)'},  # noqa: E501
	}
	opt_key_map = {
		DATA: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 't',
		DELAY: 'd',
		TIMEOUT: 'T',
		RATE_LIMIT: '--rate-limit',
		METHOD: 'm',
		WORDLIST: 'w',
		HEADER: '--headers',
		FOLLOW_REDIRECT: '--follow-redirect',
		'chunk_size': 'c',
		'stable': '--stable',
		'passive': '--passive',
		'casing': '--casing',
	}
	opt_value_map = {HEADER: lambda headers: '\\n'.join(c.strip() for c in headers.split(';;'))}
	install_version = '2.2.7'
	install_cmd = 'pipx install arjun==[install_version] --force'
	install_github_bin = False
	github_handle = 's0md3v/Arjun'

	@staticmethod
	def on_cmd(self):
		follow_redirect = self.get_opt_value(FOLLOW_REDIRECT)
		self.cmd = self.cmd.replace(' --follow-redirect', '')
		if not follow_redirect:
			self.cmd += ' --disable-redirects'

		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.fqn}.json'
		self.cmd += f' -oJ {shlex.quote(self.output_path)}'

	@staticmethod
	def on_line(self, line):
		if 'Processing chunks' in line:
			yield ''
			return
		yield line

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			# yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())
			if not results:
				yield Warning(message='No results found !')
				return
		for url, values in results.items():
			parsed_url = urlparse(url)
			url_without_param = str(urlunparse(parsed_url._replace(query='')))
			yield Url(
				url=url,
				host=parsed_url.hostname,
				request_headers=values['headers'],
				method=values['method'],
				confidence='high',
				verified=True,
				tags=['fuzz'],
			)
			for param in values['params']:
				yield Tag(
					category='info',
					name='url_param',
					value=param,
					match=url_without_param,
				)
				yield Url(
					url=f'{url_without_param}?{param}=',
					host=parsed_url.hostname,
					request_headers=values['headers'],
					method=values['method'],
					confidence='high',
					verified=True,
					tags=['fuzz'],
				)

import click
import re

from secator.decorators import task
from secator.definitions import (
	IP, HOST, URL, TIMEOUT, PROXY, THREADS, OPT_NOT_SUPPORTED, HEADER, FOLLOW_REDIRECT,
	USER_AGENT, DELAY, RETRIES, RATE_LIMIT,
)
from secator.output_types import Port, Ip, Tag, Vulnerability, Technology, Progress, Url
from secator.serializers import JSONSerializer
from secator.tasks._categories import Vuln


PROGRESS_PATTERN_REGEX = re.compile(r'(?P<name>\w+)\s*.+?.+?.+?\s*(?P<current>\d+)/(?P<total>\d+)\s*\((?P<percent>\d+)')


@task()
class droopescan(Vuln):
	"""Scan Drupal/CMS sites for version, themes, plugins and interesting URLs."""
	cmd = 'droopescan scan'
	input_types = [IP, HOST, URL]
	output_types = [Progress, Port, Ip, Tag, Vulnerability, Technology, Url]
	opt_prefix = '--'
	input_flag = '-u'
	file_flag = '-U'
	json_flag = '--output json'
	# droopescan exits non-zero even on a successful scan when an individual
	# enumeration step (plugins/themes/version) can't fully complete or the
	# target is only partially reachable. The JSON report is still produced and
	# parsed, so a non-zero exit must not fail the task on its own.
	ignore_return_code = True
	opts = {
		# 'output_path': {'type': str, 'default': None, 'help': 'Output JSON file path', 'internal': True, 'display': False},
		'mode': {'type': click.Choice(['drupal', '']), 'default': 'drupal', 'help': 'Drupal scan mode', 'internal': True, 'display': True},  # noqa: E501
		'enumerate': {'type': str, 'default': 'a', 'help': 'What to enumerate, comma-separated (a=all, i=interesting URLs, v=version, t=themes, p=plugins)'},  # noqa: E501
	}
	item_loaders = [
		JSONSerializer(),
	]
	opt_key_map = {
		THREADS: 'threads',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent'
	}
	opt_value_map = {
		# TIMEOUT: lambda x: int(x * 1000),
		# DELAY: lambda x: int(x * 1000),
	}
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
	github_handle = 'SamJoan/droopescan'
	install_version = '1.45.1'
	install_cmd = 'pipx install droopescan==[install_version] --force && pipx inject droopescan cement==2.10.14 setuptools '  # noqa: E501
	install_github_bin = False
	profile = 'small'

	@staticmethod
	def before_init(self):
		mode = self.get_opt_value('mode')
		if mode:
			self.cmd = f'{self.cmd} {mode}'

	# @staticmethod
	# def on_cmd(self):
		# default_output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		# self.output_path = self.get_opt_value('output_path') or default_output_path
		# self.cmd = self.cmd.replace('--output', f'--output {shlex.quote(self.output_path)}')

	@staticmethod
	def on_line(self, line):
		m = PROGRESS_PATTERN_REGEX.match(line)
		if m:
			data = m.groupdict()
			yield Progress(
				percent=int(data.pop('percent')),
				extra_data=data
			)
			return
		yield line

	@staticmethod
	def on_json_loaded(self, item):
		versions = item.get('version', {}).get('finds', [])
		cms_name = item.get('cms_name')
		for version in versions:
			yield Technology(
				product=cms_name,
				version=version,
				match=item['host'],
			)

		themes = item.get('themes', {}).get('finds', [])
		for theme in themes:
			yield Tag(
				category='info',
				name='drupal_theme',
				value=theme['name'],
				match=theme['url'],
				extra_data=theme.get('imu', [])
			)
		plugins = item.get('plugins', {}).get('finds', [])
		for plugin in plugins:
			yield Tag(
				category='info',
				name='drupal_plugin',
				value=plugin['name'],
				match=plugin['url'],
				extra_data=plugin.get('imu', [])
			)
		interesting_urls = item.get('interesting urls', {}).get('finds', [])
		for url in interesting_urls:
			yield Url(
				url=url['url'],
				verified=False,
				extra_data={
					'description': url.get('description')
				},
			)

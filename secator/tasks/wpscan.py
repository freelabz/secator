import json
import os

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DELAY, DESCRIPTION,
							   EXTRA_DATA, FOLLOW_REDIRECT, HEADER, ID,
							   MATCHED_AT, NAME, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROVIDER,
							   PROXY, RATE_LIMIT, REFERENCES, RETRIES,
							   SEVERITY, TAGS, THREADS, TIMEOUT,
							   URL, USER_AGENT)
from secator.output_types import Tag, Vulnerability, Info, Error
from secator.tasks._categories import VulnHttp


@task()
class wpscan(VulnHttp):
	"""Wordpress security scanner."""
	cmd = 'wpscan --random-user-agent --force --verbose'
	file_flag = None
	input_flag = '--url'
	input_type = URL
	json_flag = '-f json'
	opt_prefix = '--'
	opts = {
		'cookie_string': {'type': str, 'short': 'cookie', 'help': 'Cookie string, format: cookie1=value1;...'},
		'api_token': {'type': str, 'short': 'token', 'help': 'WPScan API Token to display vulnerability data'},
		'wp_content_dir': {'type': str, 'short': 'wcd', 'help': 'wp-content directory if custom or not detected'},
		'wp_plugins_dir': {'type': str, 'short': 'wpd', 'help': 'wp-plugins directory if custom or not detected'},
		'passwords': {'type': str, 'help': 'List of passwords to use during the password attack.'},
		'usernames': {'type': str, 'help': 'List of usernames to use during the password attack.'},
		'login_uri': {'type': str, 'short': 'lu', 'help': 'URI of the login page if different from /wp-login.php'},
		'detection_mode': {'type': str, 'short': 'dm', 'help': 'Detection mode between mixed, passive, and aggressive'}
	}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'throttle',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'request-timeout',
		THREADS: 'max-threads',
		USER_AGENT: 'user-agent',
	}
	opt_value_map = {
		DELAY: lambda x: x * 1000
	}
	output_map = {
		Vulnerability: {
			ID: lambda x: '',
			NAME: lambda x: x['to_s'].split(':')[0],
			DESCRIPTION: lambda x: '',
			SEVERITY: lambda x: 'info',
			CONFIDENCE: lambda x: 'high' if x.get('confidence', 0) == 100 else 'low',
			CVSS_SCORE: lambda x: 0,
			MATCHED_AT: lambda x: x['url'],
			TAGS: lambda x: [x['type']],
			REFERENCES: lambda x: x.get('references', {}).get('url', []),
			EXTRA_DATA: lambda x: {
				'data': x.get('interesting_entries', []),
				'found_by': x.get('found_by', ''),
				'confirmed_by': x.get('confirmed_by', {}),
				'metasploit': x.get('references', {}).get('metasploit', [])
			},
			PROVIDER: 'wpscan',
		},
	}
	output_types = [Vulnerability, Tag]
	install_pre = {
		'apt': ['make', 'kali:libcurl4t64', 'libffi-dev'],
		'pacman': ['make', 'ruby-erb'],
		'*': ['make']
	}
	install_cmd = f'gem install wpscan --user-install -n {CONFIG.dirs.bin}'
	install_post = {
		'kali': (
			f'gem uninstall nokogiri --user-install -n {CONFIG.dirs.bin} --force --executables && '
			f'gem install nokogiri --user-install -n {CONFIG.dirs.bin} --platform=ruby'
		)
	}
	proxychains = False
	proxy_http = True
	proxy_socks5 = False
	profile = 'io'

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd += f' -o {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			data = json.load(f)

		# Get URL
		target = data.get('target_url', self.inputs[0])

		# Wordpress version
		version = data.get('version', {})
		if version:
			wp_version = version['number']
			wp_version_status = version['status']
			if wp_version_status == 'outdated':
				vuln = version
				vuln.update({
					'url': target,
					'to_s': 'Wordpress outdated version',
					'type': wp_version,
					'references': {},
				})
				yield vuln

		# Main theme
		main_theme = data.get('main_theme', {})
		if main_theme:
			version = main_theme.get('version', {})
			slug = main_theme['slug']
			location = main_theme['location']
			if version:
				number = version['number']
				latest_version = main_theme.get('latest_version')
				yield Tag(
					name=f'Wordpress theme - {slug} {number}',
					match=target,
					extra_data={
						'url': location,
						'latest_version': latest_version
					}
				)
				if (latest_version and number < latest_version):
					yield Vulnerability(
						matched_at=target,
						name=f'Wordpress theme - {slug} {number} outdated',
						confidence='high',
						severity='info'
					)

		# Interesting findings
		interesting_findings = data.get('interesting_findings', [])
		for item in interesting_findings:
			yield item

		# Plugins
		plugins = data.get('plugins', {})
		for _, data in plugins.items():
			version = data.get('version', {})
			slug = data['slug']
			location = data['location']
			if version:
				number = version['number']
				latest_version = data.get('latest_version')
				yield Tag(
					name=f'Wordpress plugin - {slug} {number}',
					match=target,
					extra_data={
						'url': location,
						'latest_version': latest_version
					}
				)
				if (latest_version and number < latest_version):
					yield Vulnerability(
						matched_at=target,
						name=f'Wordpress plugin - {slug} {number} outdated',
						confidence='high',
						severity='info'
					)

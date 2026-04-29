import os
import re
import click
import yaml
import shlex

from secator.decorators import task
from secator.runners import Command
from secator.definitions import OUTPUT_PATH, THREADS, URL
from secator.output_types import Vulnerability, Tag, Info, Warning, Error
from secator.tasks._categories import OPTS


@task()
class wpprobe(Command):
	"""Fast wordpress plugin enumeration tool."""
	cmd = 'wpprobe'
	input_types = [URL]
	output_types = [Vulnerability, Tag]
	tags = ['vuln', 'scan', 'wordpress']
	file_flag = '-f'
	input_flag = '-u'
	opt_prefix = '-'
	opts = {
		'mode': {'type': click.Choice(['scan', 'update', 'update-db']), 'default': 'scan', 'help': 'WPProbe mode', 'required': True, 'internal': True},  # noqa: E501
		'output_path': {'type': str, 'default': None, 'help': 'Output JSON file path', 'internal': True, 'display': False},  # noqa: E501
	}
	meta_opts = {
		THREADS: OPTS[THREADS]
	}
	opt_key_map = {
		THREADS: 't'
	}
	install_version = 'v0.11.1'
	install_cmd = 'go install github.com/Chocapikk/wpprobe@[install_version]'
	github_handle = 'Chocapikk/wpprobe'
	install_post = {
		'*': 'wpprobe update-db'
	}

	@staticmethod
	def on_cmd(self):
		mode = self.get_opt_value('mode')
		if mode == 'update' or mode == 'update-db':
			self.cmd = f'{wpprobe.cmd} {mode}'
			return
		self.cmd = re.sub(wpprobe.cmd, f'{wpprobe.cmd} {mode}', self.cmd, 1)
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.file_name}.json'
		self.output_path = output_path
		self.cmd += f' -o {shlex.quote(self.output_path)}'

	@staticmethod
	def on_cmd_done(self):
		if not self.get_opt_value('mode') == 'scan':
			return

		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())
			if not results or 'url' not in results:
				yield Warning(message='No results found !')
				return
			url = results['url']

			# Parse plugins
			for item in wpprobe._parse_software(results.get('plugins', {}), url, 'plugin'):
				yield item

			# Parse themes (v0.11.0+, absent in older versions)
			for item in wpprobe._parse_software(results.get('themes', {}), url, 'theme'):
				yield item

	@staticmethod
	def _parse_software(software_data, url, software_type):
		"""Parse plugin or theme entries from wpprobe JSON output."""
		tag_name = f'wordpress_{software_type}'
		for name, versions in software_data.items():
			for entry in versions:
				version = entry['version']
				yield Tag(
					category='info',
					name=tag_name,
					match=url,
					value=f'{name}:{version}',
					extra_data={'name': name, 'version': version, 'type': software_type}
				)
				for vuln in wpprobe._parse_vulns(entry, name, version, software_type, tag_name, url):
					yield vuln

	@staticmethod
	def _normalize_severities(raw):
		"""Normalize severities from list to dict format.

		Fix for https://github.com/Chocapikk/wpprobe/issues/17
		"""
		if not isinstance(raw, list):
			return raw
		merged = {}
		for entry in raw:
			for k, v in entry.items():
				if k != 'n/a':
					merged[k] = v
		return merged

	@staticmethod
	def _parse_vulns(entry, name, version, software_type, tag_name, url):
		"""Yield Vulnerability items from a version entry."""
		severities = wpprobe._normalize_severities(entry.get('severities', {}))
		for severity, auth_groups in severities.items():
			if severity.lower() == 'none':
				severity = 'unknown'
			for group in auth_groups:
				auth_type = group.get('auth_type')
				for vuln in group['vulnerabilities']:
					if not vuln['title']:
						continue
					extra_data = {
						f'{software_type}_name': name,
						f'{software_type}_version': version,
					}
					if auth_type:
						extra_data['auth_type'] = auth_type
					yield Vulnerability(
						name=vuln['title'],
						id=vuln['cve'],
						severity=severity,
						cvss_score=vuln['cvss_score'],
						tags=['wordpress', tag_name, name],
						reference=vuln['cve_link'],
						extra_data=extra_data,
						matched_at=url,
						confidence='high',
					)

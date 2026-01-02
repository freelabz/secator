import click
import os
import yaml
import shlex

from pathlib import Path

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (THREADS, OUTPUT_PATH, OPT_NOT_SUPPORTED, HEADER, DELAY, FOLLOW_REDIRECT,
								PATH, PROXY, RATE_LIMIT, RETRIES, TIMEOUT, USER_AGENT, STRING)
from secator.output_types import Vulnerability, Tag, Info, Error
from secator.tasks._categories import Vuln
from secator.utils import caml_to_snake
from secator.rich import console


TRIVY_MODES = ['image', 'fs', 'repo']


def convert_mode(mode):
	return 'fs' if mode == 'filesystem' else 'repo' if mode == 'git' else mode


@task()
class trivy(Vuln):
	"""Comprehensive and versatile security scanner."""
	cmd = 'trivy'
	input_types = [PATH, STRING]
	output_types = [Tag, Vulnerability]
	tags = ['vuln', 'scan']
	input_chunk_size = 1
	json_flag = '-f json'
	version_flag = '--version'
	opts = {
		"mode": {"type": click.Choice(TRIVY_MODES), 'help': f'Scan mode ({", ".join(TRIVY_MODES)})', 'internal': True, 'required': False}  # noqa: E501
	}
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED,
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		'mode': lambda x: convert_mode(x)
	}
	install_version = 'v0.61.1'
	install_cmd = (
		'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh |'
		f'sudo sh -s -- -b {CONFIG.dirs.bin} [install_version]'
	)
	github_handle = 'aquasecurity/trivy'

	@staticmethod
	def on_cmd(self):
		mode = self.cmd_options.get('mode', {}).get('value')
		if mode and mode not in TRIVY_MODES:
			raise Exception(f'Invalid mode: {mode}')
		if not mode and len(self.inputs) > 0:
			git_path = Path(self.inputs[0]) / '.git'
			if git_path.exists():
				mode = 'repo'
			elif Path(self.inputs[0]).exists():
				mode = 'fs'
			else:
				mode = 'image'
			console.print(Info(message=f'Auto mode detected: {mode} for input: {self.inputs[0]}'))

		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace(f' -mode {mode}', '').replace('trivy', f'trivy {mode}')
		self.cmd += f' -o {shlex.quote(self.output_path)}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read()).get('Results', [])
		for item in results:
			for vuln in item.get('Vulnerabilities', []):
				vuln_id = vuln['VulnerabilityID']
				extra_data = {}
				if 'PkgName' in vuln:
					extra_data['product'] = vuln['PkgName']
				if 'InstalledVersion' in vuln:
					extra_data['version'] = vuln['InstalledVersion']
				cvss = vuln.get('CVSS', {})
				cvss_score = -1
				for _, cvss_data in cvss.items():
					cvss_score = cvss_data.get('V3Score', -1) or cvss_data.get('V2Score', -1)
				data = {
					'name': vuln_id.replace('-', '_'),
					'id': vuln_id,
					'provider': vuln.get('DataSource', {}).get('ID', ''),
					'description': vuln.get('Description'),
					'matched_at': self.inputs[0],
					'confidence': 'high',
					'severity': vuln['Severity'].lower(),
					'cvss_score': cvss_score,
					'reference': vuln.get('PrimaryURL', ''),
					'references': vuln.get('References', []),
					'extra_data': extra_data
				}
				if vuln_id.startswith('CVE'):
					remote_data = Vuln.lookup_cve(vuln_id)
					if remote_data:
						data.update(remote_data)
				yield Vulnerability(**data)
			for secret in item.get('Secrets', []):
				code_context = '\n'.join([line['Content'] for line in secret.get('Code', {}).get('Lines') or []])
				extra_data = {'code_context': code_context}
				extra_data.update({caml_to_snake(k): v for k, v in secret.items() if k not in ['RuleID', 'Match', 'Code']})
				yield Tag(
					category='secret',
					name=secret['RuleID'].replace('-', '_'),
					value=secret['Match'],
					match=item['Target'],
					extra_data=extra_data
				)

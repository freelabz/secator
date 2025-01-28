import click
import os
import yaml

from secator.decorators import task
from secator.definitions import THREADS, OUTPUT_PATH, OPT_NOT_SUPPORTED
from secator.tasks._categories import VulnCode
from secator.output_types import Vulnerability, Tag, Info, Error


@task()
class trivy(VulnCode):
	"""Comprehensive and versatile security scanner."""
	cmd = 'trivy'
	input_flag = None
	json_flag = '-f json'
	opts = {
		"mode": {"type": click.Choice(['image', 'fs', 'repo']), 'default': 'image', 'help': 'Trivy mode', 'required': True}  # noqa: E501
	}
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED
	}
	output_types = [Tag, Vulnerability]
	install_cmd = "sudo apt install trivy"
	install_github_handle = 'aquasecurity/trivy'

	@staticmethod
	def on_cmd(self):
		mode = self.get_opt_value('mode')
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace(f' -mode {mode}', '').replace('trivy', f'trivy {mode}')
		self.cmd += f' -o {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())['Results']
		for item in results:
			for vuln in item.get('Vulnerabilities', []):
				vuln_id = vuln['VulnerabilityID']
				extra_data = {}
				if 'PkgName' in vuln:
					extra_data['product'] = vuln['PkgName']
				if 'InstalledVersion' in vuln:
					extra_data['version'] = vuln['InstalledVersion']
				cvss = vuln.get('CVSS', {})
				cvss_score = cvss.get('V3Score', -1) or cvss.get('V2Score', -1)
				data = {
					'name': vuln_id,
					'id': vuln_id,
					'description': vuln.get('Description'),
					'matched_at': self.inputs[0],
					'confidence': 'high',
					'severity': vuln['Severity'].lower(),
					'cvss_score': cvss_score,
					'references': vuln.get('References', []),
					'extra_data': extra_data
				}
				if vuln_id.startswith('CVE'):
					remote_data = VulnCode.lookup_cve(vuln_id)
					if remote_data:
						data.update(remote_data)
				yield Vulnerability(**data)
			for secret in item.get('Secrets', []):
				yield Tag(
					name=secret['RuleID'],
					match=secret['Match'],
					extra_data={k: v for k, v in secret.items() if k not in ['RuleID', 'Match']}
				)

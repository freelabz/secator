import os
import yaml

from pathlib import Path

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT, HEADER,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT, OUTPUT_PATH)
from secator.output_types import Vulnerability, Info, Error
from secator.tasks._categories import VulnCode
from secator.utils import debug


@task()
class grype(VulnCode):
	"""Vulnerability scanner for container images and filesystems."""
	cmd = 'grype --quiet'
	input_flag = ''
	file_flag = OPT_NOT_SUPPORTED
	json_flag = '-o json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	output_map = {
		Vulnerability: {
			'name': lambda x: x['vulnerability']['id'],
			'id': lambda x: x['vulnerability']['id'],
			'severity': lambda x: x['vulnerability']['severity'].lower(),
			'cvss_score': lambda x: x['vulnerability']['cvss_score'],
			'references': lambda x: x['vulnerability']['urls'],
			'description': lambda x: x['vulnerability']['description']
		}
	}
	output_types = [Vulnerability]
	install_cmd = f'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {str(Path.home())}/.local/bin'  # noqa: E501
	install_github_handle = 'anchore/grype'

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = f'{self.cmd} --file {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())
			if not results:
				return
			for item in results['matches']:
				vulns = [item['vulnerability']] + item['relatedVulnerabilities']
				details = item['matchDetails'][0]
				searchedBy = details['searchedBy']
				for vuln_data in vulns:
					vuln_id = vuln_data['id']
					cvss = None
					if len(vuln_data['cvss']) > 0:
						cvss = vuln_data['cvss'][0]['metrics']['baseScore']
					description = vuln_data['description']
					references = vuln_data['urls']
					severity = vuln_data['severity'].lower()
					match_type = details['type']
					if severity == 'negligible':
						severity = 'low'
					confidence_to_match = {
						'cpe-match': 'high',
						'exact-direct-match': 'medium',
						'exact-indirect-match': 'low'
					}
					confidence = confidence_to_match.get(match_type, 'low')
					if (CONFIG.runners.skip_cve_low_confidence and confidence == 'low'):
						debug(f'{vuln_id}: ignored (low confidence).', sub='cve')
						continue
					data = {
						'id': vuln_id,
						'name': vuln_id,
						'description': description,
						'matched_at': self.inputs[0],
						'confidence': confidence,
						'provider': 'grype',
						'severity': severity,
						'cvss_score': cvss,
						'tags': [details['type']],
						'references': references,
						'extra_data': {}
					}
					if 'language' in searchedBy:
						data['extra_data']['lang'] = searchedBy['language']
					if 'package' in searchedBy:
						data['extra_data']['product'] = searchedBy['package']['name']
						data['extra_data']['version'] = searchedBy['package']['version']
					if 'namespace' in searchedBy:
						data['extra_data']['namespace'] = searchedBy['namespace']
					is_ghsa = vuln_id.startswith('GHSA')
					if is_ghsa:
						data['tags'].append('ghsa')
					else:
						data['tags'].append('cve')
					yield Vulnerability(**data)

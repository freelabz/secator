from pathlib import Path

import click

from secator.config import CONFIG
from secator.decorators import task

# fmt: off
from secator.definitions import (
	DELAY, FOLLOW_REDIRECT, HEADER, OPT_NOT_SUPPORTED, PATH, PROXY, RATE_LIMIT, RETRIES, STRING, THREADS, TIMEOUT,
	USER_AGENT
)
# fmt: on
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnCode

GRYPE_MODES = [
	'git',
	'github',
	'gitlab',
	's3',
	'filesystem',
	'gcs',
	'docker',
	'postman',
	'jenkins',
	'elasticsearch',
	'huggingface',
	'syslog',
]


def convert_mode(mode):
	return 'fs' if mode == 'filesystem' else 'repo' if mode == 'git' else mode


@task()
class grype(VulnCode):
	"""Vulnerability scanner for container images and filesystems."""

	cmd = 'grype --quiet'
	input_types = [PATH, STRING]
	output_types = [Vulnerability]
	tags = ['vuln', 'scan']
	input_flag = ''
	input_chunk_size = 1
	file_flag = None
	json_flag = None
	opt_prefix = '--'
	opts = {'mode': {'type': click.Choice(GRYPE_MODES), 'help': f'Scan mode ({", ".join(GRYPE_MODES)})', 'internal': True}}
	opt_key_value = {'mode': lambda x: convert_mode(x)}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	install_version = 'v0.115.0'
	install_cmd_pre = {'*': ['curl']}
	install_cmd = f'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {CONFIG.dirs.bin} [install_version]'  # noqa: E501
	github_handle = 'anchore/grype'

	@staticmethod
	def item_loader(self, line):
		"""Load vulnerabilty dicts from grype line output."""
		split = [i for i in line.split('  ') if i]
		kev = split and split[-1].strip() == '(kev)'  # grype flags KEV vulns with a trailing marker in the RISK column
		if kev:
			split = split[:-1]
		if len(split) not in [7, 8] or split[0] == 'NAME':
			return
		versions_fixed = None
		if len(split) == 7:  # no version fixed
			product, version, product_type, vuln_id, severity, epss, risk = tuple(split)
		elif len(split) == 8:
			product, version, versions_fixed, product_type, vuln_id, severity, epss, risk = tuple(split)
		extra_data = {
			'lang': product_type.strip(),
			'product': product.strip(),
			'version': version.strip(),
			'risk': risk.strip(),
		}
		epss_score = 0.0
		if '%' in epss:  # e.g. '47.6% (98th)' -> 0.476
			try:
				epss_score = float(epss.split('%')[0].strip()) / 100
			except ValueError:
				pass
		wont_fix = versions_fixed is not None and versions_fixed.strip() == "(won't fix)"
		if wont_fix:
			extra_data['versions_fixed'] = []
		elif versions_fixed:
			extra_data['versions_fixed'] = [c.strip() for c in versions_fixed.split(', ')]
		tags = (['kev'] if kev else []) + (['wont_fix'] if wont_fix else [])
		vuln_id = vuln_id.strip()
		severity = severity.lower().strip()
		if severity == 'negligible':
			severity = 'low'
		matched_at = self.inputs[0]
		if Path(matched_at).exists():
			matched_at = str(Path(matched_at).resolve())
		data = {
			'id': vuln_id,
			'name': vuln_id,
			'matched_at': matched_at,
			'confidence': 'medium',
			'severity': severity,
			'provider': 'grype',
			'cvss_score': -1,
			'epss_score': epss_score,
			'tags': list(tags),
		}
		if vuln_id.startswith('GHSA'):
			data['provider'] = 'github.com'
			data['references'] = [f'https://github.com/advisories/{vuln_id}']
			vuln = VulnCode.lookup_cve_from_ghsa(vuln_id)
			if vuln:
				data.update(vuln)
				data['severity'] = data['severity'] if data['severity'] not in ('', 'unknown') else severity
				extra_data['ghsa_id'] = vuln_id
		elif vuln_id.startswith('CVE'):
			vuln = VulnCode.lookup_cve(vuln_id)
			if vuln:
				data.update(vuln.toDict())
				data['severity'] = data['severity'] if data['severity'] not in ('', 'unknown') else severity
		# grype's EPSS and tags are authoritative; re-assert them after the CVE/GHSA lookup which clobbers them
		data['epss_score'] = epss_score
		if tags:
			data['tags'] = list(dict.fromkeys(data.get('tags', []) + tags))
		data['extra_data'] = extra_data
		yield data

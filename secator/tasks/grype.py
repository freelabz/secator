
from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT, HEADER,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT)
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnCode


def grype_item_loader(self, line):
	"""Load vulnerabilty dicts from grype line output."""
	split = [i for i in line.split(' ') if i]
	if not len(split) == 6 or split[0] == 'NAME':
		return None
	product, version_vuln, version, product_type, vuln_id, severity = tuple(split)
	extra_data = {
		'product': product,
		'version': version,
		'product_type': product_type
	}
	data = {
		'id': vuln_id,
		'name': vuln_id,
		'matched_at': self.input,
		'confidence': 'medium',
		'severity': severity.lower(),
		'provider': 'grype',
		'cvss_score': -1,
		'tags': [],
	}
	if vuln_id.startswith('GHSA'):
		data['provider'] = 'github.com'
		data['references'] = [f'https://github.com/advisories/{vuln_id}']
		data['tags'].extend(['cve', 'ghsa'])
		vuln = VulnCode.lookup_ghsa(vuln_id)
		if vuln:
			data.update(vuln)
			extra_data['ghsa_id'] = vuln_id
	elif vuln_id.startswith('CVE'):
		vuln = VulnCode.lookup_cve(vuln_id)
		if vuln:
			vuln['tags'].append('cve')
			data.update(vuln)
	data['extra_data'] = extra_data
	return data


@task()
class grype(VulnCode):
	"""Vulnerability scanner for container images and filesystems."""
	cmd = 'grype --quiet'
	input_flag = ''
	file_flag = OPT_NOT_SUPPORTED
	json_flag = None
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
	output_types = [Vulnerability]
	install_cmd = (
		'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin'
	)
	item_loader = grype_item_loader

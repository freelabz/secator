
from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT, HEADER,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT)
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnCode


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
	install_github_handle = 'anchore/grype'

	@staticmethod
	def item_loader(self, line):
		"""Load vulnerabilty dicts from grype line output."""
		split = [i for i in line.split(' ') if i]
		if not len(split) in [5, 6] or split[0] == 'NAME':
			return None
		version_fixed = None
		if len(split) == 5:  # no version fixed
			product, version, product_type, vuln_id, severity = tuple(split)
		elif len(split) == 6:
			product, version, version_fixed, product_type, vuln_id, severity = tuple(split)
		extra_data = {
			'lang': product_type,
			'product': product,
			'version': version,
		}
		if version_fixed:
			extra_data['version_fixed'] = version_fixed
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
				data['severity'] = data['severity'] or severity.lower()
				extra_data['ghsa_id'] = vuln_id
		elif vuln_id.startswith('CVE'):
			vuln = VulnCode.lookup_cve(vuln_id)
			if vuln:
				vuln['tags'].append('cve')
				data.update(vuln)
				data['severity'] = data['severity'] or severity.lower()
		data['extra_data'] = extra_data
		return data

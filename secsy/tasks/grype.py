from furl import furl

from secsy.definitions import *
from secsy.tasks._categories import VulnCommand


def grype_item_loader(self, line):
	"""Load vulnerabilty dicts from grype line output."""
	split = [i for i in line.split(' ') if i]
	if not len(split) == 5:
		return None
	product, version, product_type, vuln_id, severity = tuple(split)
	extracted_results = {
		'product': product,
		'version': version,
		'product_type': product_type
	}
	data = {
		'id': vuln_id,
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
		vuln = VulnCommand.lookup_ghsa(vuln_id)
		data.update(vuln)
		extracted_results['ghsa_id'] = vuln_id
	elif vuln_id.startswith('CVE'):
		vuln = VulnCommand.lookup_cve(vuln_id)
		vuln['tags'].append('cve')
		data.update(vuln)
	data['extracted_results'] = extracted_results
	return data


class grype(VulnCommand):
	"""A vulnerability scanner for container images and filesystems. Easily install the binary to try it out. Works with Syft, the powerful SBOM (software bill of materials) tool for container images and filesystems."""
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
		TIMEOUT: OPT_NOT_SUPPORTED
	}
	install_cmd = 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin'
	item_loader = grype_item_loader
	
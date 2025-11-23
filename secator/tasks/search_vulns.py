from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DESCRIPTION, EXTRA_DATA,
								 ID, MATCHED_AT, NAME, PROVIDER, REFERENCES,
								 SEVERITY, STRING, TAGS)
from secator.output_types import Vulnerability
from secator.tasks._categories import Vuln


@task()
class search_vulns(Vuln):
	"""Search for known vulnerabilities in software by product name or CPE."""
	cmd = 'search_vulns'
	input_types = [STRING]
	output_types = [Vulnerability]
	tags = ['vuln', 'recon']
	input_flag = '-q'
	input_chunk_size = 1
	json_flag = '-f json'
	version_flag = '-V'
	opts = {
		'ignore_general_product_vulns': {
			'is_flag': True,
			'help': 'Ignore vulnerabilities that only affect a general product'
		},
		'include_single_version_vulns': {
			'is_flag': True,
			'help': 'Include vulnerabilities that only affect one specific version'
		},
		'include_patched': {
			'is_flag': True,
			'help': 'Include vulnerabilities reported as patched'
		},
	}
	opt_key_map = {
		'ignore_general_product_vulns': 'ignore-general-product-vulns',
		'include_single_version_vulns': 'include-single-version-vulns',
		'include_patched': 'include-patched',
	}
	output_map = {
		Vulnerability: {
			ID: lambda x: search_vulns.extract_id(x),
			NAME: lambda x: search_vulns.extract_id(x),
			DESCRIPTION: lambda x: x.get('description', ''),
			SEVERITY: lambda x: search_vulns.cvss_to_severity(x.get('cvss', 0)),
			CONFIDENCE: lambda x: 'high',
			CVSS_SCORE: lambda x: x.get('cvss', 0),
			MATCHED_AT: lambda x: x.get('matched_at', ''),
			TAGS: lambda x: search_vulns.extract_tags(x),
			REFERENCES: lambda x: search_vulns.extract_references(x),
			EXTRA_DATA: lambda x: search_vulns.extract_extra_data(x),
			PROVIDER: lambda x: 'search_vulns',
		}
	}
	install_version = 'v1.6.0'
	install_cmd = 'pip install search_vulns==[install_version]'
	github_handle = 'ra1nb0rn/search_vulns'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def extract_id(item):
		"""Extract vulnerability ID from the item."""
		return item.get('id', '')

	@staticmethod
	def extract_tags(item):
		"""Extract tags from vulnerability item."""
		tags = []
		if item.get('cwe_id'):
			tags.append(item['cwe_id'])
		if item.get('cisa_known_exploited'):
			tags.append('actively-exploited')
		return tags

	@staticmethod
	def extract_references(item):
		"""Extract references from vulnerability item."""
		refs = []
		aliases = item.get('aliases', {})
		vuln_id = item.get('id', '')
		if vuln_id and vuln_id in aliases:
			refs.append(aliases[vuln_id])

		# Add exploit references
		exploits = item.get('exploits', [])
		if exploits:
			refs.extend(exploits)

		return refs

	@staticmethod
	def extract_extra_data(item):
		"""Extract extra data from vulnerability item."""
		extra = {}

		# Add published date
		if item.get('published'):
			extra['published'] = item['published']

		# Add CVSS version
		if item.get('cvss_ver'):
			extra['cvss_version'] = item['cvss_ver']

		# Add CWE ID
		if item.get('cwe_id'):
			extra['cwe_id'] = item['cwe_id']

		# Add CISA known exploited flag
		if item.get('cisa_known_exploited'):
			extra['cisa_known_exploited'] = item['cisa_known_exploited']

		# Add product IDs
		if item.get('product_ids'):
			extra['product_ids'] = item['product_ids']

		return extra

	@staticmethod
	def cvss_to_severity(cvss):
		"""Convert CVSS score to severity level."""
		if not cvss or cvss < 0:
			return None
		if cvss < 4:
			return 'low'
		elif cvss < 7:
			return 'medium'
		elif cvss < 9:
			return 'high'
		else:
			return 'critical'

	@staticmethod
	def item_loader(self, line):
		"""Load vulnerability items from search_vulns JSON output."""
		import json

		try:
			data = json.loads(line)
		except json.JSONDecodeError:
			return

		# Get the matched_at value (the query string)
		matched_at = self.inputs[0] if self.inputs else ''

		# Extract product IDs from the result
		product_ids = data.get('product_ids', {})

		# Extract vulnerabilities
		vulns = data.get('vulns', {})

		if not vulns:
			return

		# Yield each vulnerability
		for vuln_id, vuln_data in vulns.items():
			vuln_dict = {
				'id': vuln_id,
				'description': vuln_data.get('description', ''),
				'cvss': vuln_data.get('cvss', 0),
				'cvss_ver': vuln_data.get('cvss_ver', ''),
				'cwe_id': vuln_data.get('cwe_id', ''),
				'published': vuln_data.get('published', ''),
				'exploits': list(vuln_data.get('exploits', [])),
				'aliases': vuln_data.get('aliases', {}),
				'cisa_known_exploited': vuln_data.get('cisa_known_exploited', False),
				'product_ids': list(product_ids.keys()),
				'matched_at': matched_at,
			}
			yield vuln_dict

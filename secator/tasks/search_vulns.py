from urllib.parse import urlparse

from secator.decorators import task

# fmt: off
from secator.definitions import (
	DELAY, FOLLOW_REDIRECT, HEADER, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT
)
# fmt: on
from secator.output_types import Exploit, Info, Vulnerability, Warning
from secator.serializers import JSONSerializer
from secator.tasks._categories import Vuln


@task()
class search_vulns(Vuln):
	"""Search for known vulnerabilities in software by product name or CPE."""

	cmd = 'search_vulns'
	output_types = [Vulnerability, Exploit]
	tags = ['vuln', 'recon']
	input_flag = '-q'
	input_chunk_size = 1
	item_loaders = [JSONSerializer()]
	json_flag = '-f json'
	version_flag = '-V'
	opts = {
		'ignore_general_product_vulns': {'is_flag': True, 'help': 'Ignore vulnerabilities that only affect a general product'},  # noqa: E501
		'include_single_version_vulns': {'is_flag': True, 'help': 'Include vulnerabilities that only affect one specific version'},  # noqa: E501
		'include_patched': {'is_flag': True, 'help': 'Include vulnerabilities reported as patched'},
	}
	opt_key_map = {
		'ignore_general_product_vulns': 'ignore-general-product-vulns',
		'include_single_version_vulns': 'include-single-version-vulns',
		'include_patched': 'include-patched',
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
	install_version = '1.0.9'
	install_cmd = 'pipx install --force search_vulns==[install_version]'
	install_post = {'*': 'search_vulns -u'}
	github_handle = 'ra1nb0rn/search_vulns'
	install_github_bin = False
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'medium'

	@staticmethod
	def before_init(self):
		self._targets_info_yielded = False
		if len(self.inputs) != 1:
			return
		_in = self.inputs[0]
		self.matched_at = None
		if '~' in _in:
			split = _in.split('~')
			self.matched_at = split[0]
			self.inputs[0] = split[1]
		self.inputs[0] = self.inputs[0].replace('/', ' ').rstrip()

	@staticmethod
	def on_json_loaded(self, item):
		"""Load vulnerability items from search_vulns JSON output."""
		if self.matched_at:
			matched_ats = self.matched_at.split(',')
		else:
			matched_ats = [self.inputs[0] if self.inputs else '']
		if not getattr(self, '_targets_info_yielded', False):
			targets_str = ', '.join(matched_ats)
			yield Info(message=f'Targets: {targets_str}')
			self._targets_info_yielded = True

		values = item.values()
		if not values:
			return None

		data = list(values)[0]
		if isinstance(data, str):
			yield Warning(message=data.replace('Warning: ', ''))
			return

		vulns = data.get('vulns', {})
		common_extra_data = {}
		# product_ids = data.get('product_ids', {})
		# cpes = product_ids.get('cpe', [])
		# if cpes:
		# 	common_extra_data.update({'cpes': cpes})

		# Yield each vulnerability
		for cve_id, vuln_data in vulns.items():
			match_reason = vuln_data.get('match_reason', '')
			confidence = 'high'
			tags = search_vulns.extract_tags(vuln_data)
			exploits = vuln_data.get('exploits', [])
			cvss_score = float(vuln_data.get('severity', {}).get('CVSS', {}).get('score', 0))
			extra_data = search_vulns.extract_extra_data(vuln_data)
			extra_data['service_name'] = self.inputs[0] if self.inputs else ''
			references = search_vulns.extract_references(vuln_data)
			data = {
				'id': cve_id,
				'name': cve_id,
				'description': vuln_data.get('description', ''),
				'confidence': confidence,
				'cvss_score': cvss_score,
				'epss_score': vuln_data.get('epss', ''),
				'cvss_vec': vuln_data.get('cvss_vec', ''),
				'references': references,
				'extra_data': extra_data,
				'provider': 'search_vulns',
				'tags': tags,
			}
			if int(cvss_score) == 0:
				vuln = Vuln.lookup_cve(cve_id)
				if vuln:
					data.update(vuln.toDict())
					data['confidence'] = confidence
					data['references'].extend(references)
					data['extra_data'].update(extra_data)

			# Add 'exploitable' and 'uncertain' tags
			if match_reason == 'general_product_uncertain':
				data['confidence'] = 'low'
				data['tags'].append('uncertain')
			if len(exploits) > 0:
				data['tags'].append('exploitable')
			for matched_at in matched_ats:
				yield Vulnerability(**{**data, 'matched_at': matched_at})

			# Exploits
			if len(exploits) > 2:
				yield Info(message=f'{len(exploits)} exploits found. Keeping max 3')
				exploits = exploits[:3]
			for exploit in exploits:
				extra_data = common_extra_data.copy()
				parts = exploit.replace('http://', '').replace('https://', '').replace('github.com', 'github').split('/')
				hostname = urlparse(exploit).hostname
				tags = [hostname]
				provider = hostname.split('.')[-2]
				is_github = 'github.com' in exploit
				if is_github:
					user = parts[1]
					repo = parts[2]
					name = 'Github'
					extra_data.update({'user': user, 'repo': repo})
				else:
					hostname = urlparse(exploit).hostname
					name = provider.capitalize()
				name = name + ' exploit'
				last_part = exploit.split('/')[-1]
				id = f'{cve_id}-exploit'
				if last_part.isnumeric():
					id = last_part
					name += f' {id}'
				for matched_at in matched_ats:
					yield Exploit(
						name=name,
						provider=provider,
						id=id,
						matched_at=matched_at,
						confidence=confidence,
						reference=exploit,
						cves=[cve_id],
						tags=tags,
						extra_data=extra_data,
					)

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

		# Add match reason
		if item.get('match_reason'):
			extra['match_reason'] = item['match_reason']

		return extra

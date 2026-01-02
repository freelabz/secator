from urllib.parse import urlparse


from secator.decorators import task
from secator.definitions import (OPT_NOT_SUPPORTED, HEADER,
								 DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES,
								 THREADS, TIMEOUT, USER_AGENT)
from secator.output_types import Vulnerability, Exploit, Warning
from secator.tasks._categories import Vuln
from secator.serializers import JSONSerializer


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
	install_version = '0.8.4'
	install_cmd = 'pipx install --force search_vulns==[install_version]'
	install_post = {'*': 'search_vulns -u'}
	github_handle = 'ra1nb0rn/search_vulns'
	install_github_bin = False
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def before_init(self):
		if len(self.inputs) == 0:
			return
		_in = self.inputs[0]
		self.matched_at = None
		if '~' in _in:
			split = _in.split('~')
			self.matched_at = split[0]
			self.inputs[0] = split[1]
		self.inputs[0] = self.inputs[0].replace('httpd', '').replace('/', ' ')

	@staticmethod
	def on_json_loaded(self, item):
		"""Load vulnerability items from search_vulns JSON output."""
		matched_at = self.matched_at if self.matched_at else self.inputs[0] if self.inputs else ''

		values = item.values()
		if not values:
			return None

		data = list(values)[0]
		if isinstance(data, str):
			yield Warning(message=data)
			return

		vulns = data.get('vulns', {})
		common_extra_data = {}
		# product_ids = data.get('product_ids', {})
		# cpes = product_ids.get('cpe', [])
		# if cpes:
		# 	common_extra_data.update({'cpes': cpes})

		# Yield each vulnerability
		for cve_id, vuln_data in vulns.items():
			yield Vulnerability(
				id=cve_id,
				name=cve_id,
				description=vuln_data.get('description', ''),
				confidence='high',
				cvss_score=float(vuln_data.get('cvss', 0)),
				epss_score=vuln_data.get('epss', ''),
				cvss_vec=vuln_data.get('cvss_vec', ''),
				matched_at=matched_at,
				references=search_vulns.extract_references(vuln_data),
				extra_data=search_vulns.extract_extra_data(vuln_data),
				provider='search_vulns',
				tags=search_vulns.extract_tags(vuln_data),
			)
			exploits = vuln_data.get('exploits', [])
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
					extra_data.update({
						'user': user,
						'repo': repo,
					})
				else:
					hostname = urlparse(exploit).hostname
					name = provider.capitalize()
				name = name + ' exploit'
				last_part = exploit.split('/')[-1]
				id = f'{cve_id}-exploit'
				if last_part.isnumeric():
					id = last_part
					name += f' {id}'
				yield Exploit(
					name=name,
					provider=provider,
					id=id,
					matched_at=matched_at,
					confidence='high',
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

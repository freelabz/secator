import validators

from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Ip, Subdomain
from secator.output_types.ip import IpProtocol
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconDns


@task()
class amass(ReconDns):
	"""Amass is a subdomain enumeration tool that can be used to find subdomains of a domain."""
	cmd = 'amass enum -nocolor -v'
	input_types = [HOST]
	output_types = [Subdomain, Ip]
	tags = ['subdomain', 'enum']
	file_flag = '-d'
	input_flag = '-d'
	json_flag = ''
	opts = {
		'active': {'is_flag': True, 'default': False, 'short': 'active', 'help': 'Attempt zone transfers and certificate name grabs'},  # noqa: E501
		'asn': {'type': str, 'short': 'asn', 'help': 'ASN'},
		'domain': {'type': str, 'short': 'domain', 'help': 'Domain'},
		'ip': {'type': str, 'short': 'ip', 'help': 'IP'},
		'iprange': {'type': str, 'short': 'iprange', 'help': 'IP range'},
		'ports': {'type': str, 'short': 'ports', 'help': 'Ports'},
		'brute': {'is_flag': True, 'default': False, 'short': 'brute', 'help': 'Execute brute forcing after searches'},  # noqa: E501
		'cidr': {'type': str, 'short': 'cidr', 'help': 'CIDRs separated by commas (can be used multiple times)'},  # noqa: E501
		'config': {'type': str, 'short': 'config', 'help': 'Path to the YAML configuration file. Additional details below'},  # noqa: E501
		'dns_qps': {'type': int, 'short': 'dns-qps', 'help': 'Maximum number of DNS queries per second across all resolvers'},  # noqa: E501
		'include_file': {'type': str, 'short': 'if', 'help': 'Path to a file providing data sources to include'},  # noqa: E501
		'interface': {'type': str, 'short': 'iface', 'help': 'Provide the network interface to send traffic through'},  # noqa: E501
		'include_data_sources': {'type': str, 'short': 'include', 'help': 'Data source names separated by commas to be included'},  # noqa: E501
		'max_depth': {'type': int, 'short': 'max-depth', 'help': 'Maximum number of subdomain labels for brute forcing'},
		'min_for_recursive': {'type': int, 'short': 'min-for-recursive', 'help': 'Subdomain labels seen before recursive brute forcing (Default: 1)'},  # noqa: E501
		'untrusted_resolvers': {'type': str, 'short': 'r', 'help': 'IP addresses of untrusted DNS resolvers (can be used multiple times)'},  # noqa: E501
		'untrusted_resolvers_qps': {'type': int, 'short': 'rqps', 'help': 'Maximum number of DNS queries per second for each untrusted resolver'},  # noqa: E501
		'scripts': {'type': str, 'short': 'scripts', 'help': 'Path to a directory containing ADS scripts'},  # noqa: E501
		'silent': {'is_flag': True, 'default': False, 'short': 'silent', 'help': 'Disable all output during execution'},  # noqa: E501
		'timeout': {'type': int, 'short': 'timeout', 'help': 'Number of minutes to let enumeration run before quitting'},  # noqa: E501
		'trusted_resolvers': {'type': str, 'short': 'tr', 'help': 'IP addresses of trusted DNS resolvers (can be used multiple times)'},  # noqa: E501
		'trusted_resolvers_file': {'type': str, 'short': 'trf', 'help': 'Path to a file providing trusted DNS resolvers'},  # noqa: E501
		'trusted_resolvers_qps': {'type': int, 'short': 'rate-limit', 'help': 'Maximum number of DNS queries per second for each trusted resolver'},  # noqa: E501
		'wordlist': {'type': str, 'short': 'w', 'help': 'Path to a different wordlist file for brute forcing'},  # noqa: E501
		'wordlist_mask': {'type': str, 'short': 'wm', 'help': '"hashcat-style" wordlist masks for DNS brute forcing'},  # noqa: E501
		'no_recursive': {'is_flag': True, 'default': False, 'short': 'norecursive', 'help': 'Turn off recursive brute forcing'},  # noqa: E501
	}
	opt_key_map = {
		'domain': 'd',
		'wordlist': 'w',
		'include_file': 'if',
		'include_data_sources': 'include',
		'wordlist_mask': 'wm',
		'trusted_resolvers_file': 'trf',
		'trusted_resolvers': 'tr',
		'interface': 'iface',
		'untrusted_resolvers': 'r',
		'untrusted_resolvers_qps': 'rqps',
		'trusted_resolvers_qps': 'rate-limit',
		'dns_qps': 'dns-qps',
		'ports': 'p',
		'max_depth': 'max-depth',
		'min_for_recursive': 'min-for-recursive',
		'no_recursive': 'norecursive',
	}
	item_loaders = [
		JSONSerializer(),
	]
	install_version = 'v5.0.1'
	install_cmd = 'go install -v github.com/owasp-amass/amass/v5/cmd/amass@[install_version]'
	install_github_handle = 'owasp-amass/amass'

	@staticmethod
	def on_json_loaded(self, item):
		"""Map amass enum JSON output to Subdomain and Ip output types.

		amass `enum -json` emits one JSON object per discovered name, e.g.:
			{"name": "www.example.com", "domain": "example.com",
			 "addresses": [{"ip": "93.184.216.34", "cidr": "93.184.216.0/24"}],
			 "tag": "dns", "sources": ["DNS"]}
		"""
		host = item.get('name')
		domain = item.get('domain')
		if not host:
			return
		sources = item.get('sources', [])
		yield Subdomain(
			host=host,
			domain=domain or host,
			sources=sources,
		)
		for address in item.get('addresses', []):
			ip = address.get('ip')
			if not ip:
				continue
			protocol = IpProtocol.IPv6 if validators.ipv6(ip) else IpProtocol.IPv4
			yield Ip(
				ip=ip,
				host=host,
				protocol=protocol,
			)

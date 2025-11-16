from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Tag
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconDns


@task()
class amass(ReconDns):
	"""Amass is a subdomain enumeration tool that can be used to find subdomains of a domain."""
	cmd = 'amass enum -nocolor -v'
	input_types = [HOST]
	output_types = [Tag]
	tags = ['subdomain', 'enum']
	file_flag = '-d'
	input_flag = '-d'
	json_flag = ''
	opts = {
        'active': {'is_flag': True, 'default': False, 'short': 'active', 'help': 'Attempt zone transfers and certificate name grabs'},
        'asn': {'type': str, 'short': 'asn', 'help': 'ASN'},
        'domain': {'type': str, 'short': 'domain', 'help': 'Domain'},
        'ip': {'type': str, 'short': 'ip', 'help': 'IP'},
        'iprange': {'type': str, 'short': 'iprange', 'help': 'IP range'},
        'ports': {'type': str, 'short': 'ports', 'help': 'Ports'},
        'brute': {'is_flag': True, 'default': False, 'short': 'brute', 'help': 'Execute brute forcing after searches'},
        'cidr': {'type': str, 'short': 'cidr', 'help': 'CIDRs separated by commas (can be used multiple times)'},
        'config': {'type': str, 'short': 'config', 'help': 'Path to the YAML configuration file. Additional details below'},
        'dns_qps': {'type': int, 'short': 'dns-qps', 'help': 'Maximum number of DNS queries per second across all resolvers'},
        'include_file': {'type': str, 'short': 'if', 'help': 'Path to a file providing data sources to include'},
        'interface': {'type': str, 'short': 'iface', 'help': 'Provide the network interface to send traffic through'},
        'include_data_sources': {'type': str, 'short': 'include', 'help': 'Data source names separated by commas to be included'},
        'max_depth': {'type': int, 'short': 'max-depth', 'help': 'Maximum number of subdomain labels for brute forcing'},
        'min_for_recursive': {'type': int, 'short': 'min-for-recursive', 'help': 'Subdomain labels seen before recursive brute forcing (Default: 1)'},
        'norecursive': {'is_flag': True, 'default': False, 'short': 'norecursive', 'help': 'Turn off recursive brute forcing'},
        'ports': {'type': str, 'short': 'p', 'help': 'Ports separated by commas (default: 80, 443)'},
        'untrusted_resolvers': {'type': str, 'short': 'r', 'help': 'IP addresses of untrusted DNS resolvers (can be used multiple times)'},
        'untrusted_resolvers_qps': {'type': int, 'short': 'rqps', 'help': 'Maximum number of DNS queries per second for each untrusted resolver'},
        'scripts': {'type': str, 'short': 'scripts', 'help': 'Path to a directory containing ADS scripts'},
        'silent': {'is_flag': True, 'default': False, 'short': 'silent', 'help': 'Disable all output during execution'},
        'timeout': {'type': int, 'short': 'timeout', 'help': 'Number of minutes to let enumeration run before quitting'},
        'trusted_resolvers': {'type': str, 'short': 'tr', 'help': 'IP addresses of trusted DNS resolvers (can be used multiple times)'},
        'trusted_resolvers_file': {'type': str, 'short': 'trf', 'help': 'Path to a file providing trusted DNS resolvers'},
        'trusted_resolvers_qps': {'type': int, 'short': 'rate-limit', 'help': 'Maximum number of DNS queries per second for each trusted resolver'},
        'wordlist': {'type': str, 'short': 'w', 'help': 'Path to a different wordlist file for brute forcing'},
        'wordlist_mask': {'type': str, 'short': 'wm', 'help': '"hashcat-style" wordlist masks for DNS brute forcing'},
        'norecursive': {'is_flag': True, 'default': False, 'short': 'norecursive', 'help': 'Turn off recursive brute forcing'},
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
	}
	item_loaders = [
		JSONSerializer(),
	]
	install_version = 'v5.0.1'
	install_cmd = 'go install -v github.com/owasp-amass/amass/v5/cmd/amass@[install_version]'
	install_github_handle = 'owasp-amass/amass'

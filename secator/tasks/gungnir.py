from secator.decorators import task
from secator.definitions import HOST, OPT_NOT_SUPPORTED, DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT
from secator.output_types import Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconDns
from secator.utils import extract_domain_info


@task()
class gungnir(ReconDns):
	"""Certificate Transparency log monitor for subdomain discovery."""
	cmd = 'gungnir'
	input_types = [HOST]
	output_types = [Subdomain]
	tags = ['dns', 'recon', 'passive', 'ct']
	file_flag = '-r'
	json_flag = '-j'
	opt_prefix = '-'
	opts = {
		'verbose': {'is_flag': True, 'default': False, 'help': 'Output go logs (500/429 errors) to command line'},
		'debug': {'is_flag': True, 'default': False, 'help': 'Debug CT logs to see if you are keeping up'},
		'watch_file': {'is_flag': True, 'default': False, 'help': 'Monitor the root domain file for updates and restart the scan (requires -r flag)'},
		'output_dir': {'type': str, 'default': None, 'help': 'Directory to store output files (one per hostname, requires -r flag)'},
		'nats_subject': {'type': str, 'default': None, 'help': 'NATs subject to publish domains to'},
		'nats_url': {'type': str, 'default': None, 'help': 'NATs URL to publish domains to'},
		'nats_cred': {'type': str, 'default': None, 'help': 'NATs credentials file to publish domains to'},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		'verbose': 'v',
		'watch_file': 'f',
		'output_dir': 'o',
		'nats_subject': 'ns',
		'nats_url': 'nu',
		'nats_cred': 'nc',
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.1.2'
	install_cmd = 'go install -v github.com/g0ldencybersec/gungnir/cmd/gungnir@[install_version]'
	github_handle = 'g0ldencybersec/gungnir'
	proxychains = False
	proxy_http = False
	proxy_socks5 = False
	profile = 'io'

	@staticmethod
	def on_json_loaded(self, item):
		"""Process JSON output from gungnir.
		
		gungnir outputs JSON in the format:
		{
			"commonName": "example.com",
			"org": ["Organization"],
			"san": ["example.com", "www.example.com"],
			"domains": ["example.com", "www.example.com"],
			"source": "rfc6962" or "static_ct"
		}
		"""
		# Extract domains from the certificate info
		domains = item.get('domains', [])
		
		# Yield Subdomain object for each unique domain
		for host in domains:
			if host:  # Skip empty domains
				domain = extract_domain_info(host, domain_only=True)
				if domain:
					yield Subdomain(host=host, domain=domain)

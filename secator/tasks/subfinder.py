from secator.decorators import task
from secator.definitions import (DELAY, DOMAIN, HOST, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secator.output_types import Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconDns


@task()
class subfinder(ReconDns):
	"""Fast passive subdomain enumeration tool."""
	cmd = 'subfinder -cs'
	input_types = [HOST]
	output_types = [Subdomain]
	tags = ['dns', 'recon']
	file_flag = '-dL'
	input_flag = '-d'
	json_flag = '-json'
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		THREADS: 't'
	}
	opt_value_map = {
		PROXY: lambda x: x.replace('http://', '').replace('https://', '') if x else None
	}
	item_loaders = [JSONSerializer()]
	output_map = {
		Subdomain: {
			DOMAIN: 'input',
		}
	}
	install_version = 'v2.7.0'
	install_cmd = 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@[install_version]'
	install_github_handle = 'projectdiscovery/subfinder'
	proxychains = False
	proxy_http = True
	proxy_socks5 = False
	profile = 'io'

	@staticmethod
	def validate_item(self, item):
		if isinstance(item, dict):
			return item['input'] != 'localhost'
		return True

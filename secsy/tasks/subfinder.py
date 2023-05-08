from secsy.decorators import task
from secsy.definitions import (DELAY, DOMAIN, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secsy.output_types import Subdomain
from secsy.tasks._categories import ReconDns


@task()
class subfinder(ReconDns):
	"""Fast passive subdomain enumeration tool."""
	cmd = 'subfinder -silent -cs'
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
	output_map = {
		Subdomain: {
			DOMAIN: 'input',
		}
	}
	output_types = [Subdomain]
	install_cmd = 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
	proxychains = False

	@staticmethod
	def validate_item(self, item):
		return item['input'] != 'localhost'

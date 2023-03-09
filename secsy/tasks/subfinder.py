from secsy.definitions import *
from secsy.tasks._categories import ReconCommand


class subfinder(ReconCommand):
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
		DOMAIN: 'input',
	}
	output_schema = [HOST, DOMAIN, SOURCES]
	output_type = SUBDOMAIN
	output_field = HOST
	output_table_sort_fields = (HOST,)
	install_cmd = 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'

	@staticmethod
	def validate_item(self, item):
		return item['input'] != 'localhost'
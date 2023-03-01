from secsy.definitions import *
from secsy.tasks._categories import ReconCommand


class naabu(ReconCommand):
	"""Port scanning tool written in Go."""
	cmd = 'naabu -silent -Pn'
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		PORTS: {'type': str},
		TOP_PORTS: {'type': int}
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate',
		RETRIES: 'retries',
		TIMEOUT: 'timeout',
		THREADS: 'c',

		# naabu opts
		PORTS: 'port',
		TOP_PORTS: '--top-ports'
	}
	opt_value_map = {
		TIMEOUT: lambda x: x*1000 if x and x > 0 else None, # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x
	}
	output_schema = [PORT, IP, HOST]
	output_field = PORT # TODO: lambda self, x: '{host}:{port}'.format(**x)
	output_table_sort_fields = (HOST, PORT)
	output_type = PORT
	install_cmd = 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'

	@staticmethod
	def on_item_converted(self, item):
		if item['host'] is None:
			item['host'] = item['ip']
		return item
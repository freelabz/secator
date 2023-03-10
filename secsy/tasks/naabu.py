from secsy.definitions import *
from secsy.tasks._categories import ReconCommand


class naabu(ReconCommand):
	"""Port scanning tool written in Go."""
	cmd = 'naabu -Pn -silent'
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		PORTS: {'type': str, 'short': 'p', 'help':'Ports'},
		TOP_PORTS: {'type': int, 'short': 'tp', 'help': 'Top ports'}
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
	}
	opt_value_map = {
		TIMEOUT: lambda x: x*1000 if x and x > 0 else None, # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x
	}
	output_map = {
		PORT: lambda x: x['port']['Port']
	}
	output_schema = [PORT, HOST, IP]
	output_field = PORT # TODO: lambda self, x: '{host}:{port}'.format(**x)
	output_table_sort_fields = (HOST, PORT)
	output_type = PORT
	install_cmd = 'sudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'

	@staticmethod
	def on_item_converted(self, item):
		if item['host'] is None:
			item['host'] = item['ip']
		return item
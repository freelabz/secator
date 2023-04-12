from secsy.definitions import (DELAY, HOST, OPT_NOT_SUPPORTED, PORT, PORTS,
							   PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT,
							   TOP_PORTS)
from secsy.output_types import Port
from secsy.tasks._categories import ReconPort


class naabu(ReconPort):
	"""Port scanning tool written in Go."""
	cmd = 'naabu -Pn -silent'
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		PORTS: {'type': str, 'short': 'p', 'help': 'Ports'},
		TOP_PORTS: {'type': str, 'short': 'tp', 'help': 'Top ports'}
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
		TIMEOUT: lambda x: x*1000 if x and x > 0 else None,  # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x
	}
	output_map = {
		Port: {
			PORT: lambda x: x['port']['Port'],
			HOST: lambda x: x['host'] if 'host' in x else x['ip']
		}
	}
	output_types = [Port]
	install_cmd = 'sudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'

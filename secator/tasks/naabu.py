from secator.decorators import task
from secator.definitions import (DELAY, HOST, OPT_NOT_SUPPORTED, PORT, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, STATE, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port
from secator.tasks._categories import ReconPort


@task()
class naabu(ReconPort):
	"""Port scanning tool written in Go."""
	cmd = 'naabu -Pn -silent'
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		PORTS: {'type': str, 'short': 'p', 'help': 'Ports'},
		TOP_PORTS: {'type': str, 'short': 'tp', 'help': 'Top ports'},
		'scan_type': {'type': str, 'help': 'Scan type (SYN (s)/CONNECT(c))'},
		# 'health_check': {'is_flag': True, 'short': 'hc', 'help': 'Health check'}
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
		'scan_type': 's',
		# 'health_check': 'hc'
	}
	opt_value_map = {
		TIMEOUT: lambda x: x*1000 if x and x > 0 else None,  # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x,
		PROXY: lambda x: x.replace('socks5://', '')
	}
	output_map = {
		Port: {
			PORT: lambda x: x['port'],
			HOST: lambda x: x['host'] if 'host' in x else x['ip'],
			STATE: lambda x: 'open'
		}
	}
	output_types = [Port]
	install_cmd = 'sudo apt install -y build-essential libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'  # noqa: E501
	install_github_handle = 'projectdiscovery/naabu'
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
	profile = 'io'

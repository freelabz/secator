from secator.decorators import task
from secator.definitions import (DELAY, HOST, OPT_NOT_SUPPORTED, PORT, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, STATE, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port
from secator.serializers import JSONSerializer
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
		'scan_type': {'type': str, 'short': 'st', 'help': 'Scan type (SYN (s)/CONNECT(c))'},
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
		TIMEOUT: lambda x: int(x*1000) if x and x > 0 else None,  # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x,
		PROXY: lambda x: x.replace('socks5://', '')
	}
	item_loaders = [JSONSerializer()]
	output_map = {
		Port: {
			PORT: lambda x: x['port'],
			HOST: lambda x: x['host'] if 'host' in x else x['ip'],
			STATE: lambda x: 'open'
		}
	}
	output_types = [Port]
	install_cmd = 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3'
	# install_github_handle = 'projectdiscovery/naabu'
	install_pre = {'apt': ['libpcap-dev'], 'apk': ['libpcap-dev', 'libc6-compat'], 'pacman|brew': ['libpcap']}
	install_post = {'arch|alpine': 'sudo ln -sf /usr/lib/libpcap.so /usr/lib/libpcap.so.0.8'}
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
	profile = 'io'

	@staticmethod
	def before_init(self):
		for ix, input in enumerate(self.inputs):
			if input == 'localhost':
				self.inputs[ix] = '127.0.0.1'

	@staticmethod
	def on_item(self, item):
		if item.host == '127.0.0.1':
			item.host = 'localhost'
		return item

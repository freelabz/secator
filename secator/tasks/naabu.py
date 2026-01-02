from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port, Ip
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconPort


@task()
class naabu(ReconPort):
	"""Port scanning tool written in Go."""
	cmd = 'naabu'
	input_types = [HOST, IP]
	output_types = [Port, Ip]
	tags = ['port', 'scan']
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		'scan_type': {'type': str, 'short': 'st', 'help': 'Scan type (SYN (s)/CONNECT(c))'},
		'skip_host_discovery': {'is_flag': True, 'short': 'Pn', 'default': False, 'help': 'Skip host discovery'},
		# 'health_check': {'is_flag': True, 'short': 'hc', 'help': 'Health check'}
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate',
		RETRIES: 'retries',
		TIMEOUT: 'timeout',
		THREADS: 'c',
		PORTS: 'port',
		TOP_PORTS: 'top-ports',

		# naabu opts
		'scan_type': 's',
		# 'health_check': 'hc'
	}
	opt_value_map = {
		TIMEOUT: lambda x: int(x)*1000 if x and int(x) > 0 else None,  # convert to milliseconds
		PROXY: lambda x: x.replace('socks5://', '')
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v2.3.7'
	install_cmd = 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@[install_version]'
	github_handle = 'projectdiscovery/naabu'
	install_pre = {'apt': ['libpcap-dev'], 'apk': ['libpcap-dev', 'libc6-compat'], 'pacman|brew': ['libpcap']}
	install_post = {'arch|alpine|cachyos': 'sudo ln -sf /usr/lib/libpcap.so /usr/lib/libpcap.so.0.8'}
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
	profile = 'io'

	@staticmethod
	def before_init(self):
		self.hosts = []
		for ix, input in enumerate(self.inputs):
			if input == 'localhost':
				self.inputs[ix] = '127.0.0.1'

	@staticmethod
	def on_cmd(self):
		scan_type = self.get_opt_value('scan_type')
		if scan_type == 's':
			self.requires_sudo = True

	@staticmethod
	def on_json_loaded(self, item):
		ip = item['ip']
		host = item['host'] if 'host' in item else ip
		if host == '127.0.0.1':
			host = 'localhost'
		if host not in self.hosts:
			yield Ip(
				ip=ip,
				host=host,
				alive=True
			)
			self.hosts.append(host)
		yield Port(
			ip=ip,
			port=item['port'],
			host=host,
			state='open'
		)

import json
import os
import shlex

from secator.decorators import task
from secator.definitions import (CIDR_RANGE, DELAY, HOST, IP, OPT_NOT_SUPPORTED,
								 OUTPUT_PATH, PORTS, PROXY, RATE_LIMIT, RETRIES,
								 THREADS, TIMEOUT, TOP_PORTS)
from secator.output_types import Port, Ip, Info, Error
from secator.tasks._categories import ReconPort


@task()
class masscan(ReconPort):
	"""Fast TCP port scanner that can scan the entire Internet in under 5 minutes."""
	cmd = 'masscan'
	input_types = [HOST, IP, CIDR_RANGE]
	output_types = [Port, Ip]
	tags = ['port', 'scan']
	input_flag = None
	file_flag = '-iL'
	opt_prefix = '--'
	requires_sudo = True
	opts = {
		'banners': {'is_flag': True, 'short': 'bn', 'default': False, 'help': 'Grab banners from services'},
		'connection_timeout': {'type': int, 'short': 'ct', 'default': None, 'help': 'TCP connection timeout in seconds for banner grabbing'},
		'source_port': {'type': int, 'short': 'sp', 'default': None, 'help': 'Spoof source port number'},
		'source_ip': {'type': str, 'short': 'si', 'default': None, 'help': 'Spoof source IP address'},
		'interface': {'type': str, 'short': 'iface', 'default': None, 'help': 'Network interface to use'},
		'output_path': {'type': str, 'short': 'oJ', 'default': None, 'help': 'Output JSON file path', 'internal': True, 'display': False},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: 'max-rate',
		RETRIES: 'retries',
		TIMEOUT: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		PORTS: 'ports',
		TOP_PORTS: OPT_NOT_SUPPORTED,

		# masscan opts
		'banners': 'banners',
		'connection_timeout': 'connection-timeout',
		'source_port': 'source-port',
		'source_ip': 'source-ip',
		'interface': 'interface',
		'output_path': '-oJ',
	}
	install_pre = {
		'apt': ['masscan'],
		'apk': ['masscan'],
		'pacman|brew': ['masscan'],
	}
	install_cmd = 'sudo apt install -y masscan || sudo pacman -S --noconfirm masscan || brew install masscan'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'small'

	@staticmethod
	def before_init(self):
		self.seen_ips = []

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd += f' -oJ {shlex.quote(self.output_path)}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			content = f.read()
		try:
			results = json.loads(content)
		except json.JSONDecodeError as e:
			yield Error(message=f'Cannot parse JSON output {self.output_path}: {e}')
			return
		if not isinstance(results, list):
			return
		for item in results:
			ip = item.get('ip', '')
			timestamp = item.get('timestamp', '')
			ports = item.get('ports', [])
			if not ip or not ports:
				continue
			if ip not in self.seen_ips:
				yield Ip(
					ip=ip,
					host=ip,
					alive=True,
					tags=['masscan']
				)
				self.seen_ips.append(ip)
			for port_data in ports:
				port_num = port_data.get('port')
				proto = port_data.get('proto', 'tcp')
				status = port_data.get('status', 'open')
				extra_data = {}
				service_name = ''
				service = port_data.get('service', {})
				if service:
					service_name = service.get('name', '')
					banner = service.get('banner', '')
					if banner:
						extra_data['banner'] = banner
				reason = port_data.get('reason', '')
				ttl = port_data.get('ttl', 0)
				if reason:
					extra_data['reason'] = reason
				if ttl:
					extra_data['ttl'] = ttl
				if timestamp:
					extra_data['timestamp'] = timestamp
				yield Port(
					ip=ip,
					port=port_num,
					host=ip,
					state=status,
					protocol=proto.upper(),
					service_name=service_name,
					extra_data=extra_data,
					confidence='low',
					tags=['syn']
				)

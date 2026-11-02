import json
import os
import re
import shlex
import shutil

from secator.decorators import task
from secator.definitions import (CIDR_RANGE, DELAY, HOST, IP, OPT_NOT_SUPPORTED,
								 OUTPUT_PATH, PORTS, PROXY, RATE_LIMIT, RETRIES,
								 THREADS, TIMEOUT, TOP_PORTS)
from secator.output_types import Port, Ip, Info, Warning, Error, Progress
from secator.rich import console
from secator.tasks._categories import ReconPort


MASSCAN_RESUME_REGEX = re.compile(r'output-filename\s*=\s*(.+)', flags=re.MULTILINE)
MASSCAN_NOCAPTURE_REGEX = re.compile(r'^#?nocapture\s*=.*$\n?', flags=re.MULTILINE)


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
		'exclude_ports': {'type': str, 'short': 'ep', 'default': None, 'help': 'Exclude ports from scan', 'internal': True, 'display': True},
		'resume_conf': {'type': str, 'default': None, 'help': 'Path to resume file', 'internal': False, 'display': True},
		'ttl': {'type': int, 'short': 'ttl', 'default': None, 'help': 'Set TTL', 'requires_sudo': True},
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
		'resume_conf': 'resume',
	}
	install_pre = {
		'*': ['masscan'],
	}
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'small'

	@staticmethod
	def before_init(self):
		self.seen_ips = []

	@staticmethod
	def on_cmd_opts(self, opts):
		resume_conf = opts.get('resume_conf', {}).get('value')
		self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		if resume_conf:
			with open(resume_conf, 'r') as f:
				content = f.read()
				match = MASSCAN_RESUME_REGEX.search(content)
				if match:
					old_json_path = match.group(1).strip()
					shutil.copy(old_json_path, self.output_path)
					content = content.replace(old_json_path, self.output_path)
			new_resume_conf = f'{self.reports_folder}/.inputs/masscan_paused.conf'
			with open(new_resume_conf, 'w') as f:
				f.write(MASSCAN_NOCAPTURE_REGEX.sub('', content))
			opts['resume_conf']['value'] = new_resume_conf
			console.print(Info(message=f'Moved resume file to {new_resume_conf}'))
		return opts

	@staticmethod
	def on_cmd(self):
		self.output_path = self.get_opt_value('output_path') or self.output_path
		self.resume_conf = self.get_opt_value('resume_conf')
		if self.resume_conf:
			self.cmd += ' --append-output'
		else:
			self.cmd += f' -oJ {shlex.quote(self.output_path)}'

	@staticmethod
	def on_line(self, line):
		if line.startswith('rate'):
			chunks = [c.strip() for c in line.split(',')]
			percent = int(float(chunks[1].replace(r'% done', '')))
			extra_data = {
				'rate': chunks[0].replace('rate:', '').strip(),
				'remaining_time': chunks[2].replace(' remaining', ''),
				'found': int(chunks[3].replace('found=', ''))
			}
			yield Progress(percent, extra_data=extra_data)
		if line.startswith('saving resume file to'):
			paused_conf_path = f'{self.reports_folder}/.outputs/{self.unique_name}_paused.conf'
			shutil.move('paused.conf', paused_conf_path)
			yield Info(message=f'Saved resume file to {paused_conf_path}')
		yield line

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')
		exclude_ports = self.get_opt_value('exclude_ports') or []
		if exclude_ports:
			exclude_ports = [int(p) for p in exclude_ports.split(',')]
			yield Info(message=f'Excluded ports: {exclude_ports}')
		port_count = 0
		with open(self.output_path, 'r') as f:
			for (ix, line) in enumerate(f):
				if not line.startswith('{'):
					continue
				item = json.loads(line.rstrip(','))
				ip = item.get('ip', '')
				timestamp = item.get('timestamp', '')
				ports = item.get('ports', [])
				ports = [p for p in ports if p['port'] not in exclude_ports]
				if not ip or not ports:
					continue
				if ip not in self.seen_ips:
					yield Ip(
						ip=ip,
						host=ip,
						alive=False,
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
					port_count += 1
		if port_count == 0:
			yield Warning(message='No open ports found during scan.')

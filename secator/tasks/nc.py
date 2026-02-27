import re
import validators

from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port, Tag
from secator.tasks._categories import ReconPort
from secator.click import CLICK_LIST


@task()
class nc(ReconPort):
	"""Netcat - TCP/IP swiss army knife for reading and writing data across network connections."""
	cmd = 'nc -v -z'
	input_types = [HOST, IP]
	output_types = [Port, Tag]
	input_chunk_size = 1
	tags = ['port', 'scan']
	input_flag = None
	file_flag = None
	opts = {
		# 'udp': {'is_flag': True, 'short': 'u', 'default': False, 'help': 'UDP mode'},
		'banner': {'is_flag': True, 'short': 'b', 'default': True, 'help': 'Grab banners (disables zero-I/O mode)'},
		'port': {'type': CLICK_LIST, 'required': False, 'help': 'Ports to scan', 'internal': True, 'display': True},
	}
	opt_key_map = {
		DELAY: 'i',
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'w',
		THREADS: OPT_NOT_SUPPORTED,
		PORTS: OPT_NOT_SUPPORTED,  # Handled manually in on_cmd
		TOP_PORTS: OPT_NOT_SUPPORTED,

		# nc opts
		# 'udp': '-u',
		'banner': OPT_NOT_SUPPORTED,  # Handled in on_cmd
	}
	install_pre = {
		'apt|apk|pacman': ['netcat-openbsd'],
		'brew': ['netcat'],
	}
	ignore_return_code = True
	profile = 'io'

	@staticmethod
	def on_cmd(self):
		"""Build command with ports."""
		port = self.get_opt_value('port')
		banner = self.get_opt_value('banner')
		if ',' in port:
			port = port.split(',')
		if not isinstance(port, list):
			port = [port]
		cmds = []
		for p in port:
			if banner:
				cmds.append(f'echo "hello" | nc -v -w 5 {self.inputs[0]} {p}')
				self.shell = True
			else:
				cmds.append(f'nc -v -w 5 -z {self.inputs[0]} {p}')
		self.cmd = ' ; '.join(cmds)

	@staticmethod
	def before_init(self):
		"""Initialize state for banner collection."""
		self.current_connection = None
		self.banner_buffer = []

	@staticmethod
	def item_loader(self, line):
		"""
		Parse nc output for port scan results and banners.

		New expected open port format:
		<HOST> [<IP>] <PORT> (<service>) open

		nc: connect to <ip> port <port> (tcp) failed: Connection refused
		"""
		protocol = 'UDP' if self.get_opt_value('udp') else 'TCP'
		# First, handle new successful open port:
		# Example: "localhost [127.0.0.1] 8080 (http-alt) open"
		pattern_bracket = r'^([^\s]+) \[([^\]]+)\] (\d+) \(([^)]+)\) open'
		m = re.match(pattern_bracket, line)
		if m:
			host = m.group(1)
			ip = m.group(2)
			port_num = int(m.group(3))
			service = m.group(4)
		else:
			# Try hostless: "[127.0.0.1] 8080 (http-alt) open"
			pattern_nobracket_host = r'^\[([^\]]+)\] (\d+) \(([^)]+)\) open'
			m = re.match(pattern_nobracket_host, line)
			if m:
				host = ''
				ip = m.group(1)
				port_num = int(m.group(2))
				service = m.group(3)
			else:
				# Try old OpenBSD nc success output (backward compatibility)
				pattern_with_host = r'Connection to ([^\s]+) \(([^\)]+)\) (\d+) port \[(\w+)/([^\]]*)\] succeeded!'
				m = re.match(pattern_with_host, line)
				if m:
					host = m.group(1)
					ip = m.group(2)
					port_num = int(m.group(3))
					protocol = m.group(4)
					service = m.group(5)
				else:
					pattern_ip_only = r'Connection to ([^\s]+) (\d+) port \[(\w+)/([^\]]*)\] succeeded!'
					m = re.match(pattern_ip_only, line)
					if m:
						ip_or_host = m.group(1)
						port_num = int(m.group(2))
						protocol = m.group(3)
						service = m.group(4)
						is_ip = validators.ipv4(ip_or_host) or validators.ipv6(ip_or_host)
						if is_ip:
							host = ''
							ip = ip_or_host
						else:
							host = ip_or_host
							ip = ''
					else:
						# Check for banner data (line not a connection message)
						if self.current_connection and line.strip() and not line.startswith('nc:'):
							self.banner_buffer.append(line.strip())
						return

		# If we have a match, yield the previous connection's banner if any
		if self.current_connection and self.banner_buffer:
			banner = '\n'.join(self.banner_buffer)
			conn = self.current_connection
			match_target = f"{conn['host'] or conn['ip']}:{conn['port']}"
			service = conn['service']
			name = 'generic_banner' if not service else f'{service}_banner'
			yield Tag(
				name=name,
				value=banner,
				match=match_target,
				category='banner',
				extra_data={
					'ip': conn['ip'],
					'port': conn['port'],
					'host': conn['host'],
					'protocol': conn['protocol'],
					'service': conn['service'],
				}
			)
			self.banner_buffer = []

		yield Port(
			ip=ip,
			port=port_num,
			host=host,
			state='open',
			protocol=protocol,
			service_name=service if service else '',
		)

		self.current_connection = {
			'ip': ip,
			'port': port_num,
			'host': host,
			'protocol': protocol,
			'service': service if service else '',
		}

	@staticmethod
	def on_cmd_done(self):
		"""Yield any remaining banner from the last connection."""
		if self.current_connection and self.banner_buffer:
			banner = '\n'.join(self.banner_buffer)
			conn = self.current_connection
			match_target = f"{conn['host'] or conn['ip']}:{conn['port']}"
			service = conn['service']
			name = 'generic_banner' if not service else f'{service}_banner'
			yield Tag(
				name=name,
				value=banner,
				match=match_target,
				category='banner',
				extra_data={
					'ip': conn['ip'],
					'port': conn['port'],
					'host': conn['host'],
					'protocol': conn['protocol'],
					'service': conn['service'],
				}
			)

	@staticmethod
	def on_line(self, line):
		"""Filter out failed connection messages to reduce noise."""
		if 'failed:' in line or 'refused' in line:
			return ''  # discard failed connection lines
		return line

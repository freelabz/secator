import re

from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port
from secator.tasks._categories import ReconPort


@task()
class nc(ReconPort):
	"""Netcat - TCP/IP swiss army knife for reading and writing data across network connections."""
	cmd = 'nc -zv'
	input_types = [HOST, IP]
	output_types = [Port]
	tags = ['port', 'scan']
	input_flag = None
	file_flag = None
	opts = {
		'udp': {'is_flag': True, 'short': 'u', 'default': False, 'help': 'UDP mode'},
		'verbose': {'is_flag': True, 'short': 'vv', 'default': False, 'help': 'Very verbose'},
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
		'udp': '-u',
		'verbose': '-vv',
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
		ports = self.get_opt_value(PORTS)
		if ports:
			# Parse ports (can be single port, range, or comma-separated)
			port_list = []
			if isinstance(ports, str):
				for part in ports.split(','):
					if '-' in part:
						start, end = part.split('-', 1)
						port_list.extend(range(int(start), int(end) + 1))
					else:
						port_list.append(int(part))
			elif isinstance(ports, list):
				port_list = [int(p) for p in ports]
			else:
				port_list = [int(ports)]

			# Append ports to command
			self.cmd += ' ' + ' '.join(str(p) for p in port_list)

	@staticmethod
	def item_loader(self, line):
		"""Parse nc output for port scan results.

		Expected format:
		Connection to <ip> <port> port [tcp/<service>] succeeded!
		Connection to <hostname> (<ip>) <port> port [tcp/<service>] succeeded!
		nc: connect to <ip> port <port> (tcp) failed: Connection refused
		"""
		# Parse successful connections
		# Format: "Connection to 127.0.0.1 22 port [tcp/ssh] succeeded!"
		# Format: "Connection to localhost (::1) 22 port [tcp/ssh] succeeded!"

		# Try pattern with hostname and IP
		pattern_with_host = r'Connection to ([^\s]+) \(([^\)]+)\) (\d+) port \[(\w+)/([^\]]*)\] succeeded!'
		match = re.match(pattern_with_host, line)
		if match:
			host = match.group(1)
			ip = match.group(2)
			port_num = int(match.group(3))
			protocol = match.group(4)
			service = match.group(5)

			yield Port(
				ip=ip,
				port=port_num,
				host=host,
				state='open',
				protocol=protocol,
				service_name=service if service else '',
			)
			return

		# Try pattern with just IP
		pattern_ip_only = r'Connection to ([^\s]+) (\d+) port \[(\w+)/([^\]]*)\] succeeded!'
		match = re.match(pattern_ip_only, line)
		if match:
			ip_or_host = match.group(1)
			port_num = int(match.group(2))
			protocol = match.group(3)
			service = match.group(4)

			# Determine if it's an IP or hostname
			is_ipv4 = re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_or_host)
			is_ipv6 = '::' in ip_or_host or ip_or_host.count(':') > 1

			if is_ipv4 or is_ipv6:
				host = ''
				ip = ip_or_host
			else:
				host = ip_or_host
				ip = ''

			yield Port(
				ip=ip,
				port=port_num,
				host=host,
				state='open',
				protocol=protocol,
				service_name=service if service else '',
			)

	@staticmethod
	def on_line(self, line):
		"""Filter out failed connection messages to reduce noise."""
		if 'failed:' in line or 'refused' in line:
			return ''  # discard failed connection lines
		return line

import re
import validators

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
						start_str, end_str = part.split('-', 1)
						try:
							start = int(start_str)
							end = int(end_str)
							if not (1 <= start <= 65535 and 1 <= end <= 65535):
								self._print(f'Invalid port range: {part}. Ports must be between 1-65535.', 'red')
								continue
							port_list.extend(range(start, end + 1))
						except ValueError:
							self._print(f'Invalid port range: {part}. Must be numeric.', 'red')
							continue
					else:
						try:
							port = int(part)
							if not (1 <= port <= 65535):
								self._print(f'Invalid port: {port}. Port must be between 1-65535.', 'red')
								continue
							port_list.append(port)
						except ValueError:
							self._print(f'Invalid port: {part}. Must be numeric.', 'red')
							continue
			elif isinstance(ports, list):
				for p in ports:
					try:
						port = int(p)
						if 1 <= port <= 65535:
							port_list.append(port)
					except ValueError:
						continue
			else:
				try:
					port = int(ports)
					if 1 <= port <= 65535:
						port_list = [port]
				except ValueError:
					pass

			# Append ports to command
			if port_list:
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

			# Determine if it's an IP or hostname using validators
			is_ip = validators.ipv4(ip_or_host) or validators.ipv6(ip_or_host)

			if is_ip:
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

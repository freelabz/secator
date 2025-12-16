import re
import validators

from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, PORTS,
								 PROXY, RATE_LIMIT, RETRIES, THREADS,
								 TIMEOUT, TOP_PORTS)
from secator.output_types import Port, Tag
from secator.tasks._categories import ReconPort


@task()
class nc(ReconPort):
	"""Netcat - TCP/IP swiss army knife for reading and writing data across network connections."""
	cmd = 'nc -v -z'
	input_types = [HOST, IP]
	output_types = [Port, Tag]
	tags = ['port', 'scan']
	input_flag = None
	file_flag = None
	opts = {
		'udp': {'is_flag': True, 'short': 'u', 'default': False, 'help': 'UDP mode'},
		'verbose': {'is_flag': True, 'short': 'vv', 'default': False, 'help': 'Very verbose'},
		'banner': {'is_flag': True, 'short': 'b', 'default': False, 'help': 'Grab banners (disables zero-I/O mode)'},
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
		ports = self.get_opt_value(PORTS)
		banner = self.get_opt_value('banner')

		# If banner grabbing is enabled, remove -z flag
		if banner:
			self.cmd = self.cmd.replace(' -z', '')

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
				# For banner grabbing, we need to connect to each port individually
				# and send empty input to trigger banner responses
				if banner and len(port_list) == 1:
					# Single port banner grab - pipe empty input to trigger banner
					# Wrap in bash to ensure stderr is properly redirected
					self.cmd = f"bash -c \"echo '' | {self.cmd} {port_list[0]} 2>&1\""
				else:
					# Multiple ports or scan-only mode - use standard port list
					self.cmd += ' ' + ' '.join(str(p) for p in port_list)

	@staticmethod
	def before_init(self):
		"""Initialize state for banner collection."""
		self.current_connection = None
		self.banner_buffer = []

	@staticmethod
	def item_loader(self, line):
		"""Parse nc output for port scan results and banners.

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
		else:
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
			else:
				# Check if this is banner data (not a connection message)
				if self.current_connection and line.strip() and not line.startswith('nc:'):
					self.banner_buffer.append(line.strip())
				return

		# If we have a match, yield the previous connection's banner if any
		if self.current_connection and self.banner_buffer:
			banner = '\n'.join(self.banner_buffer)
			conn = self.current_connection
			match_target = f"{conn['host'] or conn['ip']}:{conn['port']}"
			yield Tag(
				name='banner',
				value=banner,
				match=match_target,
				category='banner',
				extra_data={
					'ip': self.current_connection['ip'],
					'port': self.current_connection['port'],
					'host': self.current_connection['host'],
					'protocol': self.current_connection['protocol'],
					'service': self.current_connection['service'],
				}
			)
			self.banner_buffer = []

		# Yield Port object (reduced duplication)
		yield Port(
			ip=ip,
			port=port_num,
			host=host,
			state='open',
			protocol=protocol,
			service_name=service if service else '',
		)

		# Store connection info for potential banner collection
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
			yield Tag(
				name='banner',
				value=banner,
				match=match_target,
				category='banner',
				extra_data={
					'ip': self.current_connection['ip'],
					'port': self.current_connection['port'],
					'host': self.current_connection['host'],
					'protocol': self.current_connection['protocol'],
					'service': self.current_connection['service'],
				}
			)

	@staticmethod
	def on_line(self, line):
		"""Filter out failed connection messages to reduce noise."""
		if 'failed:' in line or 'refused' in line:
			return ''  # discard failed connection lines
		return line

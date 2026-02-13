import re
import validators

from secator.decorators import task
from secator.definitions import HOST, IP, OPT_NOT_SUPPORTED, DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT
from secator.output_types import Record, Ip
from secator.output_types.ip import IpProtocol
from secator.tasks._categories import ReconDns


@task()
class nslookup(ReconDns):
	"""DNS lookup utility for querying DNS records."""
	cmd = 'nslookup'
	input_types = [HOST, IP]
	output_types = [Record, Ip]
	tags = ['dns', 'recon']
	file_flag = None
	input_flag = None
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}
	opts = {
		'type': {'type': str, 'short': 'type', 'default': None, 'help': 'Query type (A, AAAA, MX, NS, TXT, etc.)'},
		'server': {'type': str, 'default': None, 'help': 'DNS server to query'},
	}
	install_github_bin = False
	ignore_return_code = True
	profile = 'io'

	@staticmethod
	def before_init(self):
		"""Prepare command based on options."""
		query_type = self.get_opt_value('type')
		server = self.get_opt_value('server')

		# Build command with type option if specified
		if query_type:
			self.cmd = f'nslookup -type={query_type}'

		# Add server if specified
		if server:
			self.cmd = f'{self.cmd} {{input}} {server}'
		else:
			self.cmd = f'{self.cmd} {{input}}'

	@staticmethod
	def item_loader(self, line):
		"""Parse nslookup output line by line."""
		# Skip empty lines
		if not line:
			return

		# Skip error messages
		if '** server can\'t find' in line or 'NXDOMAIN' in line or 'SERVFAIL' in line:
			return

		# Skip header lines
		if 'Non-authoritative answer:' in line or 'Authoritative answers' in line:
			return

		# Skip DNS server information (header lines with #port)
		if line.startswith('Server:') or (line.startswith('Address:') and '#' in line):
			return

		# Parse Name: and Address: lines (A/AAAA records)
		name_match = re.match(r'^Name:[\s\t]+(.+)$', line.strip())
		if name_match:
			self._current_name = name_match.group(1)
			return

		address_match = re.match(r'^Address:[\s\t]+(.+)$', line.strip())
		if address_match and hasattr(self, '_current_name'):
			ip = address_match.group(1)
			host = self._current_name

			# Determine if IPv4 or IPv6
			if validators.ipv4(ip):
				protocol = IpProtocol.IPv4
				record_type = 'A'
			elif validators.ipv6(ip):
				protocol = IpProtocol.IPv6
				record_type = 'AAAA'
			else:
				return

			# Yield Ip output
			yield {
				'ip': ip,
				'host': host,
				'protocol': protocol,
				'alive': False
			}

			# Yield Record output
			yield {
				'host': host,
				'name': ip,
				'type': record_type,
				'extra_data': {}
			}
			return

		# Parse MX records
		mx_match = re.match(r'^(.+?)\s+mail exchanger\s+=\s+(\d+)\s+(.+?)\.?\s*$', line.strip())
		if mx_match:
			host = mx_match.group(1)
			priority = mx_match.group(2)
			mx_server = mx_match.group(3)
			yield {
				'host': host,
				'name': mx_server,
				'type': 'MX',
				'extra_data': {'priority': priority}
			}
			return

		# Parse NS records
		ns_match = re.match(r'^(.+?)\s+nameserver\s+=\s+(.+?)\.?\s*$', line.strip())
		if ns_match:
			host = ns_match.group(1)
			nameserver = ns_match.group(2)
			yield {
				'host': host,
				'name': nameserver,
				'type': 'NS',
				'extra_data': {}
			}
			return

		# Parse TXT records
		txt_match = re.match(r'^(.+?)\s+text\s+=\s+"(.+)"$', line.strip())
		if txt_match:
			host = txt_match.group(1)
			text_value = txt_match.group(2)
			yield {
				'host': host,
				'name': text_value,
				'type': 'TXT',
				'extra_data': {}
			}
			return

		# Parse CNAME records
		cname_match = re.match(r'^(.+?)\s+canonical name\s+=\s+(.+?)\.?\s*$', line.strip())
		if cname_match:
			host = cname_match.group(1)
			cname = cname_match.group(2)
			yield {
				'host': host,
				'name': cname,
				'type': 'CNAME',
				'extra_data': {}
			}
			return

	@staticmethod
	def on_item_pre_convert(self, item):
		"""Convert parsed items to output types."""
		if 'ip' in item:
			# This is an Ip output
			return Ip(**item)
		else:
			# This is a Record output
			return Record(**item)

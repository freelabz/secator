import validators

from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, PROXY,
								 RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secator.output_types import Record, Ip, Subdomain
from secator.output_types.ip import IpProtocol
from secator.tasks._categories import ReconDns
from secator.utils import extract_domain_info


@task()
class dig(ReconDns):
	"""DNS lookup utility for querying DNS name servers and performing zone transfers."""
	cmd = 'dig'
	tags = ['dns', 'recon']
	input_types = [HOST, IP]
	output_types = [Record, Ip, Subdomain]
	input_flag = None
	file_flag = None
	input_chunk_size = 1
	opts = {
		'record_type': {
			'type': str, 'short': 'rt', 'default': 'A', 'internal': True,
			'help': 'DNS record type to query (A, AAAA, MX, NS, TXT, CNAME, SOA, AXFR, etc.)'
		},
		'resolver': {
			'type': str, 'short': 'r', 'internal': True,
			'help': 'DNS resolver to use (e.g., 8.8.8.8, 1.1.1.1)'
		},
		'short': {
			'is_flag': True, 'default': False, 'internal': True,
			'help': 'Display short form answer'
		},
		'trace': {
			'is_flag': True, 'default': False, 'internal': True,
			'help': 'Trace delegation path from root name servers'
		},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}
	install_cmd_pre = {
		'apt': ['dnsutils'],
		'pacman': ['bind-tools'],
		'apk': ['bind-tools'],
		'brew': ['bind'],
	}
	github_handle = 'isc-projects/bind9'
	profile = 'io'

	@staticmethod
	def on_cmd(self):
		"""Build the dig command with appropriate flags."""
		record_type = self.get_opt_value('record_type', 'A').upper()
		resolver = self.get_opt_value('resolver')
		use_short = self.get_opt_value('short')
		use_trace = self.get_opt_value('trace')

		# Build command: dig [options] [record_type] <domain> [@resolver]
		# Use +short for brief output or +trace for full delegation path
		# Otherwise, use +noall +answer to show only the answer section
		if use_short:
			self.cmd += ' +short'
		elif use_trace:
			self.cmd += ' +trace'
		else:
			self.cmd += ' +noall +answer'

		# Add record type
		self.cmd += f' {record_type}'

		# Input will be added automatically by the framework

		# Add resolver if specified
		if resolver:
			self.cmd += f' @{resolver}'

	@staticmethod
	def item_loader(self, line):
		"""Parse dig output line by line."""
		# Skip empty lines and comment lines
		line = line.strip()
		if not line or line.startswith(';'):
			return

		# Parse the dig output format
		# Standard format: <name> <ttl> <class> <type> <rdata>
		# Some formats may have fewer fields, so we need at least 4 parts
		parts = line.split()
		if len(parts) < 4:
			return

		# Try to parse as standard dig output
		# If parts[1] is not a digit (TTL), try alternative parsing
		name = parts[0].rstrip('.')
		if len(parts) >= 5 and parts[1].isdigit():
			# Standard format with TTL
			ttl = parts[1]
			record_class = parts[2]
			record_type = parts[3]
			rdata = ' '.join(parts[4:])
		elif len(parts) >= 4:
			# Alternative format without TTL or simplified format
			ttl = '0'
			record_class = parts[1] if parts[1] in ['IN', 'CH', 'HS'] else 'IN'
			record_type = parts[2] if len(parts) > 2 else 'A'
			rdata_start = 3 if parts[1] in ['IN', 'CH', 'HS'] else 2
			rdata = ' '.join(parts[rdata_start:])
		else:
			return

		# Clean up rdata (remove trailing dot from domain names in certain records)
		if record_type in ['NS', 'CNAME', 'PTR']:
			rdata = rdata.rstrip('.')

		# For MX records, the rdata already contains "priority server"
		# Just clean up the server part
		if record_type == 'MX':
			mx_parts = rdata.split(None, 1)
			if len(mx_parts) == 2:
				rdata = f'{mx_parts[0]} {mx_parts[1].rstrip(".")}'

		# For TXT records, remove surrounding quotes
		if record_type == 'TXT':
			rdata = rdata.strip('"')

		# Check if the name is a valid domain/subdomain or IP
		is_ip = validators.ipv4(name) or validators.ipv6(name)
		is_valid_host = validators.domain(name) or is_ip
		input_record_type = self.get_opt_value('record_type')

		# Create appropriate output objects
		results = []

		# If it's a valid subdomain and not an IP
		if is_valid_host and not is_ip and record_type in ['A', 'AAAA', 'AXFR', 'CNAME', 'MX', 'NS', 'TXT']:
			domain = extract_domain_info(name, domain_only=False)
			if domain:
				extra_data = {}
				if input_record_type == "AXFR":
					extra_data = {'vhost': True}
				subdomain = {
					'_type': 'subdomain',
					'host': name,
					'domain': str(domain),
					'verified': True if input_record_type != "AXFR" else False,
					'extra_data': extra_data,
					'sources': ['dns']
				}
				results.append(subdomain)

		# For A and AAAA records, also yield IP objects
		if record_type == 'A':
			ip_addr = rdata.strip()
			if validators.ipv4(ip_addr):
				ip_obj = {
					'_type': 'ip',
					'host': name,
					'ip': ip_addr,
					'protocol': 'ipv4',
					'alive': False
				}
				results.append(ip_obj)
		elif record_type == 'AAAA':
			ip_addr = rdata.strip()
			if validators.ipv6(ip_addr):
				ip_obj = {
					'_type': 'ip',
					'host': name,
					'ip': ip_addr,
					'protocol': 'ipv6',
					'alive': False
				}
				results.append(ip_obj)

		# Always create a Record object
		record = {
			'_type': 'record',
			'host': name,
			'name': rdata,
			'type': record_type,
			'extra_data': {
				'ttl': ttl,
				'class': record_class
			}
		}
		results.append(record)

		# Yield all results
		for result in results:
			yield result

	@staticmethod
	def on_item_pre_convert(self, item):
		"""Convert dict items to proper output types."""
		item_type = item.get('_type')

		if item_type == 'subdomain':
			return Subdomain(
				host=item['host'],
				domain=item['domain'],
				verified=item['verified'],
				extra_data=item['extra_data'],
				sources=item['sources']
			)
		elif item_type == 'ip':
			protocol = IpProtocol.IPv4 if item['protocol'] == 'ipv4' else IpProtocol.IPv6
			return Ip(
				host=item['host'],
				ip=item['ip'],
				protocol=protocol,
				alive=item['alive']
			)
		elif item_type == 'record':
			return Record(
				host=item['host'],
				name=item['name'],
				type=item['type'],
				extra_data=item['extra_data'],
				_source=self.unique_name
			)

		return item

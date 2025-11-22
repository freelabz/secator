import re
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
		'record_type': {'type': str, 'short': 'rt', 'default': 'A', 'internal': True, 'help': 'DNS record type to query (A, AAAA, MX, NS, TXT, CNAME, SOA, AXFR, etc.)'},
		'resolver': {'type': str, 'short': 'r', 'internal': True, 'help': 'DNS resolver to use (e.g., 8.8.8.8, 1.1.1.1)'},
		'short': {'is_flag': True, 'default': False, 'internal': True, 'help': 'Display short form answer'},
		'trace': {'is_flag': True, 'default': False, 'internal': True, 'help': 'Trace delegation path from root name servers'},
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
		# Add short flag if needed, otherwise show only answer section
		if use_short:
			self.cmd += ' +short'
		elif not use_trace:
			# Only add +noall +answer if not using trace (trace needs full output)
			self.cmd += ' +noall +answer'
		
		# Add trace flag if needed
		if use_trace:
			self.cmd += ' +trace'
		
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
		# Format: <name> <ttl> <class> <type> <rdata>
		parts = line.split()
		if len(parts) < 5:
			return
		
		name = parts[0].rstrip('.')
		ttl = parts[1]
		record_class = parts[2]
		record_type = parts[3]
		rdata = ' '.join(parts[4:])
		
		# Clean up rdata (remove trailing dot from domain names in certain records)
		if record_type in ['NS', 'CNAME', 'PTR', 'MX']:
			rdata = rdata.rstrip('.')
		
		# For MX records, split priority and server
		if record_type == 'MX' and len(parts) >= 6:
			priority = parts[4]
			server = parts[5].rstrip('.')
			rdata = f'{priority} {server}'
		
		# Check if the name is a valid domain/subdomain or IP
		is_ip = validators.ipv4(name) or validators.ipv6(name)
		is_valid_host = validators.domain(name) or is_ip
		
		# Create appropriate output objects
		results = []
		
		# If it's a valid subdomain and not an IP
		if is_valid_host and not is_ip and record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
			domain = extract_domain_info(name, domain_only=True)
			if domain:
				subdomain = {
					'_type': 'subdomain',
					'host': name,
					'domain': domain,
					'verified': True,
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

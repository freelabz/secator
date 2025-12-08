import validators

from secator.decorators import task
from secator.definitions import (DELAY, IP, HOST, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
							   RETRIES, THREADS, TIMEOUT, CIDR_RANGE)
from secator.output_types import Ip
from secator.tasks._categories import ReconIp
from secator.utils import validate_cidr_range


@task()
class fping(ReconIp):
	"""Send ICMP echo probes to network hosts, similar to ping, but much better."""
	cmd = 'fping -a -A'
	input_types = [IP, HOST, CIDR_RANGE]
	output_types = [Ip]
	tags = ['ip', 'recon']
	file_flag = '-f'
	input_flag = None
	opts = {
		'count': {'type': int, 'default': None, 'help': 'Number of request packets to send to each target'},
		'show_name': {'is_flag': True, 'default': False, 'help': 'Show network addresses as well as hostnames'},
		'use_dns': {'is_flag': True, 'default': False, 'help': 'Use DNS to lookup address of return packet (same as -n but will force reverse-DNS lookup for hostnames)'},  # noqa: E501
		'summary': {'is_flag': True, 'default': False, 'help': 'Print cumulative statistics upon exit'},
	}
	opt_prefix = '--'
	opt_key_map = {
		DELAY: 'period',
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED,
		'count': '-c',
		'show_name': '-n',
		'use_dns': '-d',
		'summary': '-s',
	}
	opt_value_map = {
		DELAY: lambda x: int(x) * 1000,  # convert s to ms
		TIMEOUT: lambda x: int(x) * 1000  # convert s to ms
	}
	github_handle = 'schweikert/fping'
	install_github_bin = False
	install_version = 'v5.1'
	install_pre = {'*': ['fping']}
	ignore_return_code = True

	@staticmethod
	def before_init(self):
		for input in self.inputs:
			if validate_cidr_range(input):
				self.file_flag = None
				self.input_chunk_size = 1
				self.input_flag = '-g'

	@staticmethod
	def item_loader(self, line):
		if '(' in line:

			line_part = line.split(' : ')[0] if ' : ' in line else line    # Removing the stat parts that appears when using -c

			start_paren = line_part.find('(')
			end_paren = line_part.find(')', start_paren)

			if start_paren != -1 and end_paren != -1:
				host = line_part[:start_paren].strip()
				ip = line_part[start_paren+1:end_paren].strip()

				if (validators.ipv4(host) or validators.ipv6(host)):
					host = ''
			else:
				return
		else:
			ip = line.strip()
			host = ''
		if not (validators.ipv4(ip) or validators.ipv6(ip)):
			return
		yield Ip(ip=ip, alive=True, host=host, extra_data={'protocol': 'icmp'})

	@staticmethod
	def on_line(self, line):
		if 'Unreachable' in line:
			return ''  # discard line as it pollutes output
		return line

import validators

from secator.decorators import task
from secator.definitions import (DELAY, IP, HOST, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
							   RETRIES, THREADS, TIMEOUT)
from secator.output_types import Ip
from secator.tasks._categories import ReconIp


@task()
class fping(ReconIp):
	"""Send ICMP echo probes to network hosts, similar to ping, but much better."""
	cmd = 'fping -a -A'
	input_types = [IP, HOST]
	output_types = [Ip]
	tags = ['ip', 'recon']
	file_flag = '-f'
	input_flag = None
	opts = {
		'reverse_dns': {'is_flag': True, 'default': False, 'short': 'r', 'help': 'Reverse DNS lookup (slower)'}
	}
	opt_prefix = '--'
	opt_key_map = {
		DELAY: 'period',
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED,
		'reverse_dns': 'r'
	}
	opt_value_map = {
		DELAY: lambda x: x * 1000,  # convert s to ms
		TIMEOUT: lambda x: x * 1000  # convert s to ms
	}
	install_github_handle = 'schweikert/fping'
	install_version = 'v5.1'
	install_pre = {'*': ['fping']}
	ignore_return_code = True

	@staticmethod
	def item_loader(self, line):
		if '(' in line:
			host, ip = tuple(t.strip() for t in line.rstrip(')').split('('))
			if (validators.ipv4(host) or validators.ipv6(host)):
				host = ''
		else:
			ip = line.strip()
			host = ''
		if not (validators.ipv4(ip) or validators.ipv6(ip)):
			return
		yield {'ip': ip, 'alive': True, 'host': host}

	@staticmethod
	def on_line(self, line):
		if 'Unreachable' in line:
			return ''  # discard line as it pollutes output
		return line

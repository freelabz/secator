import validators

from secator.decorators import task
from secator.definitions import (DELAY, IP, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT,
							   RETRIES, THREADS, TIMEOUT)
from secator.output_types import Ip
from secator.tasks._categories import ReconIp


@task()
class fping(ReconIp):
	"""Send ICMP echo probes to network hosts, similar to ping, but much better."""
	cmd = 'fping -a'
	file_flag = '-f'
	input_flag = None
	opt_prefix = '--'
	opt_key_map = {
		DELAY: 'period',
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		DELAY: lambda x: x * 1000,  # convert s to ms
		TIMEOUT: lambda x: x * 1000  # convert s to ms
	}
	input_type = IP
	output_types = [Ip]
	install_pre = {'*': ['fping']}

	@staticmethod
	def item_loader(self, line):
		if not (validators.ipv4(line) or validators.ipv6(line)):
			return
		yield {'ip': line, 'alive': True}

	@staticmethod
	def on_line(self, line):
		if 'Unreachable' in line:
			return ''  # discard line as it pollutes output
		return line

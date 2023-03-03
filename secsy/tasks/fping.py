import validators

from secsy.definitions import *
from secsy.tasks._categories import ReconCommand


class fping(ReconCommand):
	cmd = 'fping -a'
	file_flag = '-f'
	input_flag = None
	install_cmd = 'apt install fping'
	ignore_return_code = True
	opt_prefix = '--'
	opt_key_map = {
		DELAY: 'period',
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		DELAY: lambda x: x * 1000,  # convert s to ms
		TIMEOUT: lambda x: x * 1000 # convert s to ms
	}
	input_type = IP
	output_schema = [IP, 'alive']
	output_type = IP
	output_field = IP

	def item_loader(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			return {'ip': line, 'alive': True}
		return None

	@staticmethod
	def on_line(self, line):
		if 'Unreachable' in line:
			return '' # discard line as it pollutes output
		return line
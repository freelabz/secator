import validators

from secator.decorators import task
from secator.definitions import (CIDR_RANGE, IP, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, THREADS, TIMEOUT, SLUG)
from secator.output_types import Ip
from secator.tasks._categories import ReconIp


@task()
class mapcidr(ReconIp):
	"""Utility program to perform multiple operations for a given subnet/cidr ranges."""
	cmd = 'mapcidr'
	input_types = [CIDR_RANGE, IP, SLUG]
	output_types = [Ip]
	tags = ['ip', 'recon']
	input_flag = '-cidr'
	file_flag = '-cl'
	install_version = 'v1.1.34'
	install_pre = {'apk': ['libc6-compat']}
	install_cmd = 'go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@[install_version]'
	github_handle = 'projectdiscovery/mapcidr'
	opts = {
		'hide_ips': {'is_flag': True, 'short': 'hi', 'default': False, 'help': 'Hide IP addresses from output (too verbose)', 'internal': True, 'display': True},  # noqa: E501
	}
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}

	@staticmethod
	def on_line(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			ip = Ip(ip=line, alive=False)
			if self.get_opt_value('hide_ips'):
				self.add_result(ip, print=False)
				return
			return ip
		return line

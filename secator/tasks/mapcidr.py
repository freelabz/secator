import validators

from secator.decorators import task
from secator.definitions import (CIDR_RANGE, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secator.output_types import Ip
from secator.tasks._categories import ReconIp


@task()
class mapcidr(ReconIp):
	"""Utility program to perform multiple operations for a given subnet/cidr ranges."""
	cmd = 'mapcidr -silent'
	input_flag = '-cidr'
	file_flag = '-cl'
	install_pre = {
		'apk': ['libc6-compat']
	}
	install_cmd = 'go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest'
	install_github_handle = 'projectdiscovery/mapcidr'
	input_type = CIDR_RANGE
	output_types = [Ip]
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}

	@staticmethod
	def item_loader(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			yield {'ip': line, 'alive': False}
		return

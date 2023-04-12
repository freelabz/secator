import validators

from secsy.definitions import (CIDR_RANGE, OPT_NOT_SUPPORTED, PROXY,
							   RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secsy.output_types import Ip
from secsy.tasks._categories import ReconIp


class mapcidr(ReconIp):
	"""Utility program to perform multiple operations for a given subnet/cidr ranges."""
	cmd = 'mapcidr -silent'
	input_flag = '-cidr'
	file_flag = '-cl'
	install_cmd = 'go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest'
	input_type = CIDR_RANGE
	output_types = [Ip]
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
	}

	def item_loader(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			return {'ip': line, 'alive': False}
		return None

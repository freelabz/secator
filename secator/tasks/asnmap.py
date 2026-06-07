import validators

from secator.decorators import task
from secator.definitions import (DELAY, HOST, IP, OPT_NOT_SUPPORTED, OPT_PIPE_INPUT, PROXY,
								 RATE_LIMIT, RETRIES, SLUG, STRING, THREADS, TIMEOUT)
from secator.output_types import Record, Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import Command
from secator.utils import extract_domain_info


@task()
class asnmap(Command):
	"""ASN mapping tool to map ASN, IP or organization to their associated network ranges."""
	cmd = 'asnmap'
	input_types = [HOST, IP, SLUG, STRING]
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	json_flag = '-json'
	output_types = [Record, Subdomain]
	tags = ['ip', 'probe']
	opts = {}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retry',
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.1.1'
	install_cmd = 'go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@[install_version]'
	install_github_handle = 'projectdiscovery/asnmap'
	proxychains = False
	proxy_socks5 = True
	proxy_http = False

	@staticmethod
	def on_json_loaded(self, item):
		input = item.get('input')
		as_number = item.get('as_number')
		as_name = item.get('as_name')
		as_country = item.get('as_country')
		as_range = item.get('as_range') or []
		extra_data = {
			k: v for k, v in {
				'as_number': as_number,
				'as_name': as_name,
				'as_country': as_country,
			}.items() if v
		}

		# Emit a Subdomain finding when the input is a hostname / FQDN
		if input and not validators.ipv4(input) and not validators.ipv6(input):
			domain = extract_domain_info(input, domain_only=True)
			if domain:
				yield Subdomain(
					host=input,
					domain=domain,
					sources=['asn'],
					extra_data=extra_data,
				)

		# Emit one Record per associated network range (ASN -> CIDR)
		for cidr in as_range:
			yield Record(
				name=cidr,
				type='ASN',
				host=input or '',
				extra_data=extra_data,
			)

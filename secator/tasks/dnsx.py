import validators

from secator.decorators import task
from secator.definitions import (HOST, CIDR_RANGE, DELAY, IP, OPT_PIPE_INPUT, PROXY,
								 RATE_LIMIT, RETRIES, THREADS, TIMEOUT, WORDLIST, OPT_NOT_SUPPORTED)
from secator.output_types import Record, Ip, Subdomain, Error, Warning
from secator.output_types.ip import IpProtocol
from secator.tasks._categories import ReconDns
from secator.serializers import JSONSerializer
from secator.utils import extract_domain_info, process_wordlist


@task()
class dnsx(ReconDns):
	"""dnsx is a fast and multi-purpose DNS toolkit designed for running various retryabledns library."""
	cmd = 'dnsx -resp -recon'
	tags = ['dns', 'fuzz']
	input_types = [HOST, CIDR_RANGE, IP]
	output_types = [Record, Ip, Subdomain]
	json_flag = '-json'
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	opt_key_map = {
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'threads',
		PROXY: 'proxy',
		DELAY: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
	}
	opts = {
		'trace': {'is_flag': True, 'default': False, 'help': 'Perform dns tracing'},
		'resolver': {'type': str, 'short': 'r', 'help': 'List of resolvers to use (file or comma separated)'},
		'wildcard_domain': {'type': str, 'short': 'wd', 'help': 'Domain name for wildcard filtering'},
		'rc': {'type': str, 'short': 'rc', 'help': 'DNS return code to filter (noerror, formerr, servfail, nxdomain, notimp, refused, yxdomain, xrrset, notauth, notzone)'},  # noqa: E501
		'subdomains_only': {'is_flag': True, 'short': 'so', 'default': False, 'internal': True, 'help': 'Only return subdomains'},  # noqa: E501
		WORDLIST: {'type': str, 'short': 'w', 'default': None, 'process': process_wordlist, 'help': 'Wordlist to use'},  # noqa: E501
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.2.2'
	install_cmd = 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@[install_version]'
	install_github_handle = 'projectdiscovery/dnsx'
	profile = 'io'

	@staticmethod
	def before_init(self):
		if self.get_opt_value('wordlist'):
			self.file_flag = '-d'
			self.input_flag = '-d'
			rc = self.get_opt_value('rc')
			if not rc:
				self.cmd += ' -rc noerror'
			if len(self.inputs) > 1 and self.get_opt_value('wildcard_domain'):
				fqdn = extract_domain_info(self.inputs[0], domain_only=True)
				for input in self.inputs[1:]:
					fqdn_item = extract_domain_info(input, domain_only=True)
					if fqdn_item != fqdn:
						return Error('Wildcard domain is not supported when using multiple hosts with different FQDNs !')

	@staticmethod
	def on_json_loaded(self, item):
		record_types = ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'srv', 'ptr', 'soa', 'axfr', 'caa']
		host = item['host']
		status_code = item.get('status_code')
		if host.startswith('*'):
			yield Warning(f'Wildcard domain detected: {host}. Ignore previous results.')
			self.stop_process(exit_ok=True)
			return
		is_ip = validators.ipv4(host) or validators.ipv6(host)
		if status_code and status_code == 'NOERROR' and not is_ip:
			yield Subdomain(
				host=host,
				domain=extract_domain_info(host, domain_only=True),
				sources=['dns']
			)
		if self.get_opt_value('subdomains_only'):
			return
		for _type in record_types:
			values = item.get(_type, [])
			if isinstance(values, dict):
				values = [values]
			for value in values:
				name = value
				extra_data = {}
				if isinstance(value, dict):
					name = value.get('name', host)
					extra_data = {k: v for k, v in value.items() if k != 'name' and k != 'host'}
				if _type == 'a':
					ip = Ip(
						host=host,
						ip=name,
						protocol=IpProtocol.IPv4,
						alive=False
					)
					if ip not in self.results:
						yield ip
				elif _type == 'aaaa':
					ip = Ip(
						host=host,
						ip=name,
						protocol=IpProtocol.IPv6,
						alive=False
					)
					if ip not in self.results:
						yield ip
				elif _type == 'ptr':
					ip = Ip(
						host=host,
						ip=name,
						protocol=IpProtocol.IPv4,
						alive=False
					)
					if ip not in self.results:
						yield ip
				record = Record(
					host=host,
					name=name,
					type=_type.upper(),
					extra_data=extra_data,
					_source=self.unique_name
				)

				if record not in self.results:
					yield record

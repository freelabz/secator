from secator.decorators import task
from secator.definitions import (OPT_PIPE_INPUT, RATE_LIMIT, RETRIES, THREADS)
from secator.output_types import Record, Ip, Subdomain
from secator.tasks._categories import ReconDns
from secator.utils import extract_root_domain_from_domain
import json


@task()
class dnsx(ReconDns):
	"""dnsx is a fast and multi-purpose DNS toolkit designed for running various retryabledns library."""
	json_flag = '-json'
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	output_types = [Record, Ip, Subdomain]
	opt_key_map = {
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'threads',
		"reverse": ''
	}
	opts = {
		'trace': {'is_flag': True, 'default': False, 'help': 'Perform dns tracing'},
		'resolver': {'type': str, 'short': 'r', 'help': 'List of resolvers to use (file or comma separated)'},
		'wildcard_domain': {'type': str, 'short': 'wd', 'help': 'Domain name for wildcard filtering'},
		'reverse': {'is_flag': True, 'default': False, 'help': 'Perform reverse dns lookup'},
	}
	item_loaders = []
	install_cmd = 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
	install_github_handle = 'projectdiscovery/dnsx'
	profile = 'io'

	@staticmethod
	def on_init(self):
		reverse = self.get_opt_value('reverse')
		if reverse:
			self.cmd = 'dnsx -ptr'
		else:
			self.cmd = 'dnsx -resp -a -aaaa -cname -mx -ns -txt -srv -soa -axfr -caa'

	@staticmethod
	def item_loader(self, line):
		try:
			item = json.loads(line)
		except json.JSONDecodeError:
			return
		if self.orig:  # original dnsx JSON output
			yield item
			return
		host = item['host']
		record_types = ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'srv', 'ptr', 'soa', 'axfr', 'caa']
		for _type in record_types:
			values = item.get(_type, [])
			for value in values:
				name = value
				extra_data = {}
				if isinstance(value, dict):
					name = value['name']
					extra_data = {k: v for k, v in value.items() if k != 'name'}
				if _type == 'a':
					yield {
						'host': host,
						'ip': name
					}
				if _type == 'ptr':
					yield {
						'host': name,
						'domain': extract_root_domain_from_domain(name),
						'_source': 'dnsx'
					}
				yield {
					'host': host,
					'name': name,
					'type': _type.upper(),
					'extra_data': extra_data
				}

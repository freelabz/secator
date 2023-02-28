"""Discovery tools."""

import json
import logging
import re
import validators

from secsy.cmd import CommandRunner
from secsy.definitions import *

logger = logging.getLogger(__name__)


RECON_META_OPTS = {
	DELAY: {'type': float, 'help': 'Delay to add between each requests'},
	PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
	RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
	TIMEOUT: {'type': int, 'help': 'Request timeout'},
}


class ReconCommand(CommandRunner):
	meta_opts = RECON_META_OPTS
	input_type = HOST


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

	def item_loader(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			return {'ip': line, 'alive': True}
		return None

class maigret(ReconCommand):
	"""Collects a dossier on a person by username."""
	cmd = 'maigret'
	file_flag = None
	input_flag = None
	json_flag = '--json ndjson'
	opt_prefix = '--'
	opts = {
		'site': {'type': str, 'help': 'Sites to check'},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED
	}
	input_type = USERNAME
	output_schema = ['sitename', 'username', 'url_user']
	output_type = USER_ACCOUNT
	install_cmd = 'pip3 install maigret'

	def __iter__(self):
		prev = self._print_item_count
		self._print_item_count = False
		list(super().__iter__())
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_path:
			match = re.search('JSON ndjson report for ocervell saved in (.*)', self.output)
			if match is None:
				logger.warning('JSON output file not found in command output.')
				return
			self.output_path = match.group(1)
		note = f'maigret JSON results saved to {self.output_path}'
		if self._print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				data = [json.loads(line) for line in f.read().splitlines()]
			for item in data:
				item = self._process_item(item)
				if not item:
					continue
				yield item
		self._print_item_count = prev
		self._process_results()

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value('output_path')
		self.output_path = output_path

	@staticmethod
	def validate_item(self, item):
		return item['http_status'] == 200


class mapcidr(ReconCommand):
	"""A utility program to perform multiple operations for a given subnet/cidr ranges."""
	cmd = 'mapcidr'
	input_flag = '-cidr'
	file_flag = '-cl'
	install_cmd = 'go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest'
	input_type = CIDR_RANGE
	output_schema = [IP, 'alive']
	output_type = IP
	opt_key_map = {
		THREADS: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED
	}

	def item_loader(self, line):
		if validators.ipv4(line) or validators.ipv6(line):
			return {'ip': line, 'alive': False}
		return None


class naabu(ReconCommand):
	"""Port scanning tool written in Go."""
	cmd = 'naabu -silent -Pn'
	input_flag = '-host'
	file_flag = '-list'
	json_flag = '-json'
	opts = {
		PORTS: {'type': str},
		TOP_PORTS: {'type': int}
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate',
		RETRIES: 'retries',
		TIMEOUT: 'timeout',
		THREADS: 'c',

		# naabu opts
		PORTS: 'port',
		TOP_PORTS: '--top-ports'
	}
	opt_value_map = {
		TIMEOUT: lambda x: x*1000 if x and x > 0 else None, # convert to milliseconds
		RETRIES: lambda x: 1 if x == 0 else x
	}
	output_schema = [PORT, IP, HOST]
	output_field = PORT # TODO: lambda self, x: '{host}:{port}'.format(**x)
	output_table_sort_fields = (HOST, PORT)
	output_type = PORT
	install_cmd = 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'

	@staticmethod
	def on_item_converted(self, item):
		if item['host'] is None:
			item['host'] = item['ip']
		return item


class subfinder(ReconCommand):
	"""Fast passive subdomain enumeration tool."""
	cmd = 'subfinder -silent -cs'
	file_flag = '-dL'
	input_flag = '-d'
	json_flag = '-json'
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		THREADS: 't'
	}
	opt_value_map = {
		PROXY: lambda x: x.replace('http://', '').replace('https://', '') if x else None
	}
	output_map = {
		DOMAIN: 'input'
	}
	output_schema = [HOST, DOMAIN, SOURCES]
	output_field = HOST
	output_type = SUBDOMAIN
	output_field = HOST
	install_cmd = 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
	proxychains = False

	@staticmethod
	def validate_item(self, item):
		return item['input'] != 'localhost'
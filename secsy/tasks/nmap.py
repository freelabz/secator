import logging
import re

import xmltodict

from secsy.definitions import *
from secsy.tasks._categories import VulnCommand
from secsy.utils import get_file_timestamp

logger = logging.getLogger(__name__)


class nmap(VulnCommand):
	"""Network Mapper is a free and open source utility for network discovery
	and security auditing."""
	cmd = f'nmap -sT -sV -Pn'
	input_flag = None
	input_chunk_size = 1
	file_flag = '-iL'
	opt_prefix = '--'
	opts = {
		PORTS: {'type': str, 'help': 'Ports to scan'},
		SCRIPT: {'type': str, 'default': 'vulscan/,vulners', 'help': 'NSE scripts'},
		'output_path': {'type': str, 'default': None, 'help': 'Output XML file path'}
	}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'scan-delay',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED, # TODO: nmap actually supports --proxies but it does not work in TCP scan mode [https://github.com/nmap/nmap/issues/1098]
		RATE_LIMIT: 'max-rate',
		RETRIES: 'max-retries',
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: 'max-rtt-timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,

		# Nmap opts
		PORTS: '-p',
	}
	opt_value_map = {
		PORTS: lambda x: ','.join([str(p) for p in x]) if isinstance(x, list) else x
	}
	install_cmd = 'sudo apt install -y nmap'

	def __iter__(self):
		# TODO: deduplicate this and amass as it's the same function
		prev = self._print_item_count
		self._print_item_count = False
		list(super().__iter__())
		if self.return_code != 0:
			return
		self.results = []
		note = f'nmap XML results saved to {self.output_path}'
		if self._print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			nmap_data = self.xml_to_json()
			for vuln in nmap_data:
				vuln = self._process_item(vuln)
				if not vuln:
					continue
				yield vuln
		self._print_item_count = prev
		self._process_results()

	def xml_to_json(self):
		results = []
		with open(self.output_path, 'r') as f:
			content = f.read()
			try:
				results = xmltodict.parse(content) # parse XML to dict
			except Exception as e:
				logger.exception(e)
				logger.error(
					f'Cannot parse nmap XML output {self.output_path} to valid JSON.')
		results['_host'] = self.input
		return nmapData(results)

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value('output_path')
		if not output_path:
			timestr = get_file_timestamp()
			output_path = f'{TEMP_FOLDER}/nmap_{timestr}.xml'
		self.output_path = output_path
		self.cmd += f' -oX {self.output_path}'


class nmapData(dict):

	def __iter__(self):
		for host in self._get_hosts():
			hostname = self._get_hostname(host)
			for port in self._get_ports(host):
				port_number = port['@portid']
				if not port_number or not port_number.isdigit():
					continue

				# Get extracted results
				extracted_results = self._get_extracted_results(port)

				# Grab CPEs
				cpes = extracted_results.get('cpe', [])

				# Get script output
				scripts = self._get_scripts(port)

				# Parse each script output to get vulns
				for script in scripts:
					script_id = script['id']
					output = script['output']
					extracted_results['nmap_script'] = script_id
					funcmap = {
						'vulscan': self._parse_vulscan_output,
						'vulners': self._parse_vulners_output,
					}
					func = funcmap.get(script_id)
					metadata = {
						VULN_MATCHED_AT: f'{hostname}:{port_number}',
						VULN_EXTRACTED_RESULTS: extracted_results,
						'_source': 'nmap'
					}
					if not func:
						logger.debug(f'Script output parser for "{script_id}" is not supported YET.')
						continue
					for vuln in func(output, cpes=cpes):
						vuln.update(metadata)
						yield vuln

	#---------------------#
	# XML FILE EXTRACTORS #
	#---------------------#
	def _get_hosts(self):
		hosts = self.get('nmaprun', {}).get('host', {})
		if isinstance(hosts, dict):
			hosts = [hosts]
		return hosts

	def _get_ports(self, host_cfg):
		ports = host_cfg.get('ports', {}).get('port', [])
		if isinstance(ports, dict):
			ports = [ports]
		return ports

	def _get_hostname(self, host_cfg):
		hostnames = host_cfg.get('hostnames', {})
		hostname = self['_host']
		if hostnames:
			hostnames = hostnames.get('hostname', [])
			if isinstance(hostnames, dict):
				hostnames = [hostnames]
			if hostnames:
				hostname = hostnames[0]['@name']
		else:
			hostname = host_cfg.get('address', {}).get('@addr', None)
		return hostname

	def _get_extracted_results(self, port_cfg):
		extracted_results = {
			k.lstrip('@'): v
			for k, v in port_cfg.get('service', {}).items()
		}

		# Strip product / version strings
		if 'product' in extracted_results:
			extracted_results['product'] = extracted_results['product'].lower()

		if 'version' in extracted_results:
			version_split = extracted_results['version'].split(' ')
			version = None
			os = None
			if len(version_split) == 3:
				version, os, extra_version = tuple(version_split)
				version = f'{version}-{extra_version}'
			elif len(version_split) == 2:
				version, os =  tuple(version_split)
			elif len(version_split) == 1:
				version = version_split[0]
			else:
				version = extracted_results['version']
			if os:
				extracted_results['os'] = os
			if version:
				extracted_results['version'] = version

		# Grab CPEs
		cpes = extracted_results.get('cpe', [])
		if not isinstance(cpes, list):
			cpes = [cpes]
			extracted_results['cpe'] = cpes

		return extracted_results

	def _get_scripts(self, port_cfg):
		scripts = port_cfg.get('script', [])
		if isinstance(scripts, dict):
			scripts = [scripts]
		scripts = [
			{k.lstrip('@'): v for k, v in script.items()}
			for script in scripts
		]
		return scripts

	#--------------#
	# VULN PARSERS #
	#--------------#
	def _parse_vulscan_output(self, out, cpes=[]):
		"""Parse nmap vulscan script output.

		Args:
			out (str): Vulscan script output.

		Returns:
			list: List of Vulnerability dicts.
		"""
		provider_name = ''
		for line in out.splitlines():
			if not line:
				continue
			line = line.strip()
			if not line.startswith('[') and line != 'No findings': # provider line
				provider_name, _ = tuple(line.split(' - '))
				continue
			reg = r'\[([ A-Za-z0-9_@./#&+-]*)\] (.*)'
			matches = re.match(reg, line)
			if not matches:
				continue
			vuln_id, vuln_title = matches.groups()
			vuln = {
				VULN_ID: vuln_id,
				VULN_NAME: vuln_id,
				VULN_DESCRIPTION: vuln_title,
				VULN_PROVIDER: provider_name,
				VULN_TAGS: [vuln_id, provider_name]
			}
			if provider_name == 'MITRE CVE':
				vuln_data = VulnCommand.lookup_cve(vuln['id'], cpes=cpes)
				if vuln_data:
					vuln.update(vuln_data)
				yield vuln
			else:
				logger.debug(f'Vulscan provider {provider_name} is not supported YET.')
				continue

	def _parse_vulners_output(self, out, **kwargs):
		cpe = None
		provider_name = 'vulners'
		for line in out.splitlines():
			if not line:
				continue
			line = line.strip()
			if line.startswith('cpe:'):
				cpe = line
				continue
			elems = tuple(line.split('\t'))
			if len(elems) == 4: # exploit
				# TODO: Implement exploit processing
				exploit_id, cvss_score, reference_url, exploit_str = elems
				vuln = {
					VULN_ID: exploit_id,
					VULN_NAME: exploit_id,
					VULN_PROVIDER: provider_name,
					VULN_CVSS_SCORE: cvss_score,
					VULN_REFERENCES: [reference_url],
					VULN_TAGS: ['exploit', exploit_id, provider_name],
					VULN_CONFIDENCE: 'low'
				}
			elif len(elems) == 3: # vuln
				vuln_id, vuln_description, _ = tuple(line.split('\t'))
				vuln_type = vuln_id.split('-')[0]
				vuln = {
					VULN_ID: vuln_id,
					VULN_NAME: vuln_id,
					VULN_TAGS: [vuln_id, provider_name],
					VULN_PROVIDER: provider_name,
					VULN_DESCRIPTION: vuln_description,
				}
				if vuln_type == 'CVE':
					vuln[VULN_TAGS].append('cve')
					vuln_data = VulnCommand.lookup_cve(vuln_id, cpes=[cpe])
					if vuln_data:
						vuln.update(vuln_data)
					yield vuln
				else:
					logger.debug(f'Vulners parser for "{vuln_type}" is not implemented YET.')
			else:
				logger.error(f'Unrecognized vulners output: {elems}')

	def _parse_http_csrf_output(self, out, port_data):
		pass
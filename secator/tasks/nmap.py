import logging
import os
import re

import xmltodict

from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DELAY,
								 DESCRIPTION, EXTRA_DATA, FOLLOW_REDIRECT,
								 HEADER, HOST, ID, IP, MATCHED_AT, NAME,
								 OPT_NOT_SUPPORTED, OUTPUT_PATH, PORT, PORTS, PROVIDER,
								 PROXY, RATE_LIMIT, REFERENCE, REFERENCES,
								 RETRIES, SCRIPT, SERVICE_NAME, STATE, TAGS,
								 THREADS, TIMEOUT, USER_AGENT)
from secator.output_types import Exploit, Port, Vulnerability
from secator.tasks._categories import VulnMulti

logger = logging.getLogger(__name__)


@task()
class nmap(VulnMulti):
	"""Network Mapper is a free and open source utility for network discovery and security auditing."""
	cmd = 'nmap -sT -sV -Pn'
	input_flag = None
	input_chunk_size = 1
	file_flag = '-iL'
	opt_prefix = '--'
	output_types = [Port, Vulnerability, Exploit]
	opts = {
		PORTS: {'type': str, 'help': 'Ports to scan', 'short': 'p'},
		SCRIPT: {'type': str, 'default': 'vulners', 'help': 'NSE scripts'},
		# 'tcp_connect': {'type': bool, 'short': 'sT', 'default': False, 'help': 'TCP Connect scan'},
		'tcp_syn_stealth': {'is_flag': True, 'short': 'sS', 'default': False, 'help': 'TCP SYN Stealth'},
		'output_path': {'type': str, 'short': 'oX', 'default': None, 'help': 'Output XML file path'}
	}
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'scan-delay',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: None,  # TODO: supports --proxies but not in TCP mode [https://github.com/nmap/nmap/issues/1098]
		RATE_LIMIT: 'max-rate',
		RETRIES: 'max-retries',
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: 'max-rtt-timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,

		# Nmap opts
		PORTS: '-p',
		'output_path': '-oX'
	}
	opt_value_map = {
		PORTS: lambda x: ','.join([str(p) for p in x]) if isinstance(x, list) else x
	}
	install_cmd = (
		'sudo apt install -y nmap && sudo git clone https://github.com/scipag/vulscan /opt/scipag_vulscan || true && '
		'sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true'
	)
	proxychains = True
	proxychains_flavor = 'proxychains4'
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def on_init(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.xml'
		self.output_path = output_path
		self.cmd += f' -oX {self.output_path}'

	def yielder(self):
		yield from super().yielder()
		if self.return_code != 0:
			return
		self.results = []
		note = f'nmap XML results saved to {self.output_path}'
		if self.print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			nmap_data = self.xml_to_json()
			yield from nmap_data

	def xml_to_json(self):
		results = []
		with open(self.output_path, 'r') as f:
			content = f.read()
			try:
				results = xmltodict.parse(content)  # parse XML to dict
			except Exception as e:
				logger.exception(e)
				logger.error(
					f'Cannot parse nmap XML output {self.output_path} to valid JSON.')
		results['_host'] = self.input
		return nmapData(results)


class nmapData(dict):

	def __iter__(self):
		for host in self._get_hosts():
			hostname = self._get_hostname(host)
			ip = self._get_ip(host)
			for port in self._get_ports(host):
				# Get port number
				port_number = port['@portid']
				if not port_number or not port_number.isdigit():
					continue
				port_number = int(port_number)

				# Get port state
				state = port.get('state', {}).get('@state', '')

				# Get extra data
				extra_data = self._get_extra_data(port)

				# Grab CPEs
				cpes = extra_data.get('cpe', [])

				# Grab service name
				service_name = ''
				if 'product' in extra_data:
					service_name = extra_data['product']
				elif 'name' in extra_data:
					service_name = extra_data['name']
				if 'version' in extra_data:
					version = extra_data['version']
					service_name += f'/{version}'

				# Get script output
				scripts = self._get_scripts(port)

				# Yield port data
				port = {
					PORT: port_number,
					HOST: hostname,
					STATE: state,
					SERVICE_NAME: service_name,
					IP: ip,
					EXTRA_DATA: extra_data
				}
				yield port

				# Parse each script output to get vulns
				for script in scripts:
					script_id = script['id']
					output = script['output']
					extra_data = {'script': script_id}
					if service_name:
						extra_data['service_name'] = service_name
					funcmap = {
						'vulscan': self._parse_vulscan_output,
						'vulners': self._parse_vulners_output,
					}
					func = funcmap.get(script_id)
					metadata = {
						MATCHED_AT: f'{hostname}:{port_number}',
						IP: ip,
						EXTRA_DATA: extra_data,
					}
					if not func:
						# logger.debug(f'Script output parser for "{script_id}" is not supported YET.')
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

	def _get_ip(self, host_cfg):
		return host_cfg.get('address', {}).get('@addr', None)

	def _get_extra_data(self, port_cfg):
		extra_datas = {
			k.lstrip('@'): v
			for k, v in port_cfg.get('service', {}).items()
		}

		# Strip product / version strings
		if 'product' in extra_datas:
			extra_datas['product'] = extra_datas['product'].lower()

		if 'version' in extra_datas:
			version_split = extra_datas['version'].split(' ')
			version = None
			os = None
			if len(version_split) == 3:
				version, os, extra_version = tuple(version_split)
				version = f'{version}-{extra_version}'
			elif len(version_split) == 2:
				version, os = tuple(version_split)
			elif len(version_split) == 1:
				version = version_split[0]
			else:
				version = extra_datas['version']
			if os:
				extra_datas['os'] = os
			if version:
				extra_datas['version'] = version

		# Grab CPEs
		cpes = extra_datas.get('cpe', [])
		if not isinstance(cpes, list):
			cpes = [cpes]
			extra_datas['cpe'] = cpes

		return extra_datas

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
			if not line.startswith('[') and line != 'No findings':  # provider line
				provider_name, _ = tuple(line.split(' - '))
				continue
			reg = r'\[([ A-Za-z0-9_@./#&+-]*)\] (.*)'
			matches = re.match(reg, line)
			if not matches:
				continue
			vuln_id, vuln_title = matches.groups()
			vuln = {
				ID: vuln_id,
				NAME: vuln_id,
				DESCRIPTION: vuln_title,
				PROVIDER: provider_name,
				TAGS: [vuln_id, provider_name]
			}
			if provider_name == 'MITRE CVE':
				vuln_data = VulnMulti.lookup_cve(vuln['id'], cpes=cpes)
				if vuln_data:
					vuln.update(vuln_data)
				yield vuln
			else:
				# logger.debug(f'Vulscan provider {provider_name} is not supported YET.')
				continue

	def _parse_vulners_output(self, out, **kwargs):
		cpes = []
		provider_name = 'vulners'
		for line in out.splitlines():
			if not line:
				continue
			line = line.strip()
			if line.startswith('cpe:'):
				cpes.append(line)
				continue
			elems = tuple(line.split('\t'))
			vuln = {}

			if len(elems) == 4:  # exploit
				# TODO: Implement exploit processing
				exploit_id, cvss_score, reference_url, _ = elems
				name = exploit_id
				# edb_id = name.split(':')[-1] if 'EDB-ID' in name else None
				vuln = {
					ID: exploit_id,
					NAME: name,
					PROVIDER: provider_name,
					REFERENCE: reference_url,
					'_type': 'exploit'
					# CVSS_SCORE: cvss_score,
					# CONFIDENCE: 'low'
				}
				# TODO: lookup exploit in ExploitDB to find related CVEs
				# if edb_id:
				# 	print(edb_id)
				# 	vuln_data = VulnMulti.lookup_exploitdb(edb_id)
				yield vuln

			elif len(elems) == 3:  # vuln
				vuln_id, vuln_cvss, reference_url = tuple(line.split('\t'))
				vuln_type = vuln_id.split('-')[0]
				vuln = {
					ID: vuln_id,
					NAME: vuln_id,
					PROVIDER: provider_name,
					CVSS_SCORE: vuln_cvss,
					REFERENCES: [reference_url],
					TAGS: [],
					CONFIDENCE: 'low'
				}
				if vuln_type == 'CVE':
					vuln[TAGS].append('cve')
					vuln_data = VulnMulti.lookup_cve(vuln_id, cpes=cpes)
					if vuln_data:
						vuln.update(vuln_data)
					yield vuln
				else:
					logger.debug(f'Vulners parser for "{vuln_type}" is not implemented YET.')
			else:
				logger.error(f'Unrecognized vulners output: {elems}')

import logging
import os
import re
from typing import Dict, List, Generator

import xmltodict

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DELAY,
								 DESCRIPTION, EXTRA_DATA, FOLLOW_REDIRECT,
								 HEADER, HOST, ID, IP, PROTOCOL, MATCHED_AT, NAME,
								 OPT_NOT_SUPPORTED, OUTPUT_PATH, PORT, PORTS, PROVIDER,
								 PROXY, RATE_LIMIT, REFERENCE, REFERENCES,
								 RETRIES, SCRIPT, SERVICE_NAME, SEVERITY, STATE, TAGS,
								 THREADS, TIMEOUT, TOP_PORTS, USER_AGENT)
from secator.output_types import Exploit, Port, Vulnerability
from secator.tasks._categories import VulnMulti
from secator.utils import debug

logger = logging.getLogger(__name__)


@task()
class nmap(VulnMulti):
	"""Network Mapper is a free and open source utility for network discovery and security auditing."""
	cmd = 'nmap'
	input_flag = None
	input_chunk_size = 1
	file_flag = '-iL'
	opt_prefix = '--'
	output_types = [Port, Vulnerability, Exploit]
	opts = {
		PORTS: {'type': str, 'short': 'p', 'help': 'Ports to scan (default: most common 1000 ports for each protocol)'},
		TOP_PORTS: {'type': int, 'short': 'tp', 'help': 'Top ports to scan [full, 100, 1000]'},
		SCRIPT: {'type': str, 'default': 'vulners', 'help': 'NSE scripts'},
		'skip_host_discovery': {'is_flag': True, 'short': 'Pn', 'default': False, 'help': 'Skip host discovery (no ping)'},
		'version_detection': {'is_flag': True, 'short': 'sV', 'default': False, 'help': 'Version detection'},
		'tcp_syn_stealth': {'is_flag': True, 'short': 'sS', 'default': False, 'help': 'TCP SYN Stealth'},
		'tcp_connect': {'is_flag': True, 'short': 'sT', 'default': False, 'help': 'TCP Connect scan'},
		'udp_scan': {'is_flag': True, 'short': 'sU', 'default': False, 'help': 'UDP scan'},
		'output_path': {'type': str, 'short': 'oX', 'default': None, 'help': 'Output XML file path'},
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
		'skip_host_discovery': '-Pn',
		'version_detection': '-sV',
		'tcp_connect': '-sT',
		'tcp_syn_stealth': '-sS',
		'udp_scan': '-sU',
		'output_path': '-oX',
	}
	opt_value_map = {
		PORTS: lambda x: ','.join(map(str, x)) if isinstance(x, list) else x
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
		self.output_path = self.get_opt_value(OUTPUT_PATH) or f'{self.reports_folder}/.outputs/{self.unique_name}.xml'
		self.cmd += f' -oX {self.output_path}'
		tcp_syn_stealth = self.get_opt_value('tcp_syn_stealth')
		tcp_connect = self.get_opt_value('tcp_connect')
		if tcp_syn_stealth:
			self.cmd = f'sudo {self.cmd}'
		if tcp_connect and tcp_syn_stealth:
			self._print(
				'Options -sT (SYN stealth scan) and -sS (CONNECT scan) are conflicting. Keeping only -sT.',
				'bold gold3')
			self.cmd = self.cmd.replace('-sT ', '')

	def yielder(self) -> Generator:
		yield from super().yielder()
		if self.return_code != 0:
			return

		if self.print_line:
			self._print(f'nmap XML results saved to {self.output_path}')

		if os.path.exists(self.output_path):
			yield from self.parse_nmap_output()

	def parse_nmap_output(self) -> Generator:
		with open(self.output_path, 'r') as f:
			try:
				nmap_data = xmltodict.parse(f.read())
			except Exception as e:
				logger.exception(e)
				logger.error(f'Cannot parse nmap XML output {self.output_path} to valid JSON.')
				return

		nmap_data['_host'] = self.input
		return nmapData(nmap_data)


class nmapData(dict):

	def __iter__(self):
		for host in self._get_hosts():
			hostname = self._get_hostname(host)
			ip = self._get_ip(host)
			for port in self._get_ports(host):
				yield from self._process_port(port, hostname, ip)

	def _get_hosts(self) -> List[Dict]:
		hosts = self.get('nmaprun', {}).get('host', {})
		return [hosts] if isinstance(hosts, dict) else hosts

	def _get_ports(self, host_cfg: Dict) -> List[Dict]:
		ports = host_cfg.get('ports', {}).get('port', [])
		return [ports] if isinstance(ports, dict) else ports

	def _get_hostname(self, host_cfg: Dict) -> str:
		hostnames = host_cfg.get('hostnames', {})
		if hostnames:
			hostnames = hostnames.get('hostname', [])
			hostnames = [hostnames] if isinstance(hostnames, dict) else hostnames
			return hostnames[0]['@name'] if hostnames else self['_host']
		return self._get_address(host_cfg).get('@addr', self['_host'])

	def _get_address(self, host_cfg: Dict) -> Dict:
		addresses = host_cfg.get('address', {})
		if isinstance(addresses, list):
			return next((addr for addr in addresses if addr.get('@addrtype') == "ipv4"), {})
		return addresses

	def _get_ip(self, host_cfg: Dict) -> str:
		return self._get_address(host_cfg).get('@addr')

	def _process_port(self, port: Dict, hostname: str, ip: str) -> Generator:
		port_number = port['@portid']
		if not port_number or not port_number.isdigit():
			return

		port_number = int(port_number)
		state = port.get('state', {}).get('@state', '')
		extra_data = self._get_extra_data(port)
		service_name = extra_data.get('service_name', '')
		protocol = port['@protocol'].upper()

		port_data = {
			PORT: port_number,
			HOST: hostname,
			STATE: state,
			SERVICE_NAME: service_name,
			IP: ip,
			PROTOCOL: protocol,
			EXTRA_DATA: extra_data
		}
		yield port_data

		scripts = self._get_scripts(port)
		yield from self._process_scripts(scripts, hostname, ip, port_number, service_name, extra_data)

	def _get_extra_data(self, port_cfg: Dict) -> Dict:
		extra_data = {
			k.lstrip('@'): v
			for k, v in port_cfg.get('service', {}).items()
		}

		# Strip product / version strings
		if 'product' in extra_data:
			extra_data['product'] = extra_data['product'].lower()

		# Get version and post-process it
		version = None
		if 'version' in extra_data:
			vsplit = extra_data['version'].split(' ')
			version_exact = True
			os = None
			if len(vsplit) == 3:
				version, os, extra_version = tuple(vsplit)
				if os == 'or' and extra_version == 'later':
					version_exact = False
					os = None
				version = f'{version}-{extra_version}'
			elif len(vsplit) == 2:
				version, os = tuple(vsplit)
			elif len(vsplit) == 1:
				version = vsplit[0]
			else:
				version = extra_data['version']
			if os:
				extra_data['os'] = os
			if version:
				extra_data['version'] = version
			extra_data['version_exact'] = version_exact

		# Grap service name
		product = extra_data.get('name', None) or extra_data.get('product', None)
		if product:
			service_name = product
			if version:
				service_name += f'/{version}'
			extra_data['service_name'] = service_name

		# Grab CPEs
		cpes = extra_data.get('cpe', [])
		if not isinstance(cpes, list):
			cpes = [cpes]
			extra_data['cpe'] = cpes
		debug(f'Found CPEs: {",".join(cpes)}', sub='cve')

		# Grab confidence
		conf = int(extra_data.get('conf', 0))
		if conf > 7:
			confidence = 'high'
		elif conf > 4:
			confidence = 'medium'
		else:
			confidence = 'low'
		extra_data['confidence'] = confidence

		# Build custom CPE
		if product and version:
			vsplit = version.split('-')
			version_cpe = vsplit[0] if not version_exact else version
			cpe = VulnMulti.create_cpe_string(product, version_cpe)
			if cpe not in cpes:
				cpes.append(cpe)
				debug(f'Added new CPE from identified product and version: {cpe}', sub='cve')

		return extra_data

	def _get_scripts(self, port_cfg: Dict) -> List[Dict]:
		scripts = port_cfg.get('script', [])
		if isinstance(scripts, dict):
			scripts = [scripts]
		return [{k.lstrip('@'): v for k, v in script.items()} for script in scripts]

	def _process_scripts(self, scripts: List[Dict], hostname: str, ip: str, port_number: int, service_name: str, extra_data: Dict) -> Generator:  # noqa: E501
		for script in scripts:
			script_id = script['id']
			output = script['output']
			metadata = {
				MATCHED_AT: f'{hostname}:{port_number}',
				IP: ip,
				EXTRA_DATA: {'script': script_id, 'service_name': service_name} if service_name else {'script': script_id},
			}

			parser_func = getattr(self, f'_parse_{script_id}_output', None)
			if not parser_func:
				debug(f'Script output parser for "{script_id}" is not supported YET.', sub='cve')
				continue

			cpes = extra_data.get('cpe', [])
			for vuln in parser_func(output, cpes=cpes):
				vuln.update(metadata)
				confidence = self._determine_confidence(vuln, extra_data)
				vuln[CONFIDENCE] = confidence

				if CONFIG.runners.skip_cve_low_confidence and confidence == 'low':
					debug(f'{vuln[ID]}: ignored (low confidence).', sub='cve')
					continue

				yield vuln

	def _determine_confidence(self, vuln: Dict, extra_data: Dict) -> str:
		if 'cpe-match' in vuln[TAGS]:
			return 'high' if extra_data.get('version_exact', False) else 'medium'
		return 'low'

	def _parse_vulscan_output(self, out: str, cpes: List[str]) -> Generator:
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
				data = VulnMulti.lookup_cve(vuln['id'], cpes=cpes)
				if data:
					vuln.update(data)
				yield vuln
			else:
				debug(f'Vulscan provider {provider_name} is not supported YET.', sub='cve')
				continue

	def _parse_vulners_output(self, out: str, cpes: List[str]) -> Generator:
		provider_name = 'vulners'
		for line in out.splitlines():
			if not line:
				continue
			line = line.strip()
			if line.startswith('cpe:'):
				cpes.append(line.rstrip(':'))
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
					'_type': 'exploit',
					TAGS: [exploit_id, provider_name]
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
				vuln_cvss = float(vuln_cvss)
				vuln_id = vuln_id.split(':')[-1]
				vuln_type = vuln_id.split('-')[0]
				vuln = {
					ID: vuln_id,
					NAME: vuln_id,
					PROVIDER: provider_name,
					CVSS_SCORE: vuln_cvss,
					SEVERITY: VulnMulti.cvss_to_severity(vuln_cvss),
					REFERENCES: [reference_url],
					TAGS: [vuln_id, provider_name],
					CONFIDENCE: 'low'
				}
				if vuln_type == 'CVE' or vuln_type == 'PRION:CVE':
					vuln[TAGS].append('cve')
					data = VulnMulti.lookup_cve(vuln_id, cpes=cpes)
					if data:
						vuln.update(data)
					yield vuln
				else:
					debug(f'Vulners parser for "{vuln_type}" is not implemented YET.', sub='cve')
			else:
				debug(f'Unrecognized vulners output: {elems}', sub='cve')

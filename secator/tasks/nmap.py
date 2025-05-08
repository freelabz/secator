import logging
import os
import re

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
from secator.output_types import Exploit, Port, Vulnerability, Info, Error
from secator.tasks._categories import VulnMulti
from secator.utils import debug, traceback_as_string

logger = logging.getLogger(__name__)


@task()
class nmap(VulnMulti):
	"""Network Mapper is a free and open source utility for network discovery and security auditing."""
	cmd = 'nmap'
	tags = ['port', 'scan']
	input_flag = None
	input_types = [HOST, IP]
	input_chunk_size = 1
	file_flag = '-iL'
	opt_prefix = '--'
	output_types = [Port, Vulnerability, Exploit]
	opts = {
		# Port specification and scan order
		PORTS: {'type': str, 'short': 'p', 'help': 'Ports to scan (- to scan all)'},
		TOP_PORTS: {'type': int, 'short': 'tp', 'help': 'Top ports to scan [100, 1000, full]'},

		# Script scanning
		SCRIPT: {'type': str, 'default': None, 'help': 'NSE scripts'},
		'script_args': {'type': str, 'short': 'sargs', 'default': None, 'help': 'NSE script arguments (n1=v1,n2=v2,...)'},

		# Host discovery
		'skip_host_discovery': {'is_flag': True, 'short': 'Pn', 'default': False, 'help': 'Skip host discovery (no ping)'},

		# Service and version detection
		'version_detection': {'is_flag': True, 'short': 'sV', 'default': False, 'help': 'Enable version detection (slow)'},
		'detect_all': {'is_flag': True, 'short': 'A', 'default': False, 'help': 'Enable OS detection, version detection, script scanning, and traceroute on open ports'},  # noqa: E501
		'detect_os': {'is_flag': True, 'short': 'O', 'default': False, 'help': 'Enable OS detection', 'requires_sudo': True},

		# Scan techniques
		'tcp_syn_stealth': {'is_flag': True, 'short': 'sS', 'default': False, 'help': 'TCP SYN Stealth', 'requires_sudo': True},  # noqa: E501
		'tcp_connect': {'is_flag': True, 'short': 'sT', 'default': False, 'help': 'TCP Connect scan'},
		'udp_scan': {'is_flag': True, 'short': 'sU', 'default': False, 'help': 'UDP scan', 'requires_sudo': True},
		'tcp_null_scan': {'is_flag': True, 'short': 'sN', 'default': False, 'help': 'TCP Null scan', 'requires_sudo': True},
		'tcp_fin_scan': {'is_flag': True, 'short': 'sF', 'default': False, 'help': 'TCP FIN scan', 'requires_sudo': True},
		'tcp_xmas_scan': {'is_flag': True, 'short': 'sX', 'default': False, 'help': 'TCP Xmas scan', 'requires_sudo': True},
		'tcp_ack_scan': {'is_flag': True, 'short': 'sA', 'default': False, 'help': 'TCP ACK scan', 'requires_sudo': True},
		'tcp_window_scan': {'is_flag': True, 'short': 'sW', 'default': False, 'help': 'TCP Window scan', 'requires_sudo': True},  # noqa: E501
		'tcp_maimon_scan': {'is_flag': True, 'short': 'sM', 'default': False, 'help': 'TCP Maimon scan', 'requires_sudo': True},  # noqa: E501
		'sctp_init_scan': {'is_flag': True, 'short': 'sY', 'default': False, 'help': 'SCTP Init scan', 'requires_sudo': True},
		'sctp_cookie_echo_scan': {'is_flag': True, 'short': 'sZ', 'default': False, 'help': 'SCTP Cookie Echo scan', 'requires_sudo': True},  # noqa: E501
		'ping_scan': {'is_flag': True, 'short': 'sn', 'default': False, 'help': 'Ping scan (disable port scan)'},
		'ip_protocol_scan': {'type': str, 'short': 'sO', 'default': None, 'help': 'IP protocol scan', 'requires_sudo': True},
		'script_scan': {'is_flag': True, 'short': 'sC', 'default': False, 'help': 'Enable default scanning'},
		'zombie_host': {'type': str, 'short': 'sI', 'default': None, 'help': 'Use a zombie host for idle scan', 'requires_sudo': True},  # noqa: E501
		'ftp_relay_host': {'type': str, 'short': 'sB', 'default': None, 'help': 'FTP bounce scan relay host'},

		# Firewall / IDS evasion and spoofing
		'spoof_source_port': {'type': int, 'short': 'g', 'default': None, 'help': 'Send packets from a specific port'},
		'spoof_source_ip': {'type': str, 'short': 'S', 'default': None, 'help': 'Spoof source IP address'},
		'spoof_source_mac': {'type': str, 'short': 'spoofmac', 'default': None, 'help': 'Spoof MAC address'},
		'fragment': {'is_flag': True, 'short': 'fragment', 'default': False, 'help': 'Fragment packets', 'requires_sudo': True},  # noqa: E501
		'mtu': {'type': int, 'short': 'mtu', 'default': None, 'help': 'Fragment packets with given MTU', 'requires_sudo': True},  # noqa: E501
		'ttl': {'type': int, 'short': 'ttl', 'default': None, 'help': 'Set TTL', 'requires_sudo': True},
		'badsum': {'is_flag': True, 'short': 'badsum', 'default': False, 'help': 'Create a bad checksum in the TCP header', 'requires_sudo': True},  # noqa: E501
		'ipv6': {'is_flag': True, 'short': 'ipv6', 'default': False, 'help': 'Enable IPv6 scanning'},

		# Host discovery
		'traceroute': {'is_flag': True, 'short': 'traceroute', 'default': False, 'help': 'Traceroute', 'requires_sudo': True},
		'disable_arp_ping': {'is_flag': True, 'short': 'dap', 'default': False, 'help': 'Disable ARP ping'},

		# Misc
		'output_path': {'type': str, 'short': 'oX', 'default': None, 'help': 'Output XML file path', 'internal': True, 'display': False},  # noqa: E501
		'debug': {'is_flag': True, 'short': 'd', 'default': False, 'help': 'Enable debug mode'},
		'verbose': {'is_flag': True, 'short': 'v', 'default': False, 'help': 'Enable verbose mode'},
		'timing': {'type': int, 'short': 'T', 'default': None, 'help': 'Timing template (0: paranoid, 1: sneaky, 2: polite, 3: normal, 4: aggressive, 5: insane)'},  # noqa: E501
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
		'detect_all': '-A',
		'detect_os': '-O',
		'tcp_syn_stealth': '-sS',
		'tcp_connect': '-sT',
		'tcp_window_scan': '-sW',
		'tcp_maimon_scan': '-sM',
		'udp_scan': '-sU',
		'tcp_null_scan': '-sN',
		'tcp_fin_scan': '-sF',
		'tcp_xmas_scan': '-sX',
		'tcp_ack_scan': '-sA',
		'sctp_init_scan': '-sY',
		'sctp_cookie_echo_scan': '-sZ',
		'ping_scan': '-sn',
		'ip_protocol_scan': '-sO',
		'script_scan': '-sC',
		'zombie_host': '-sI',
		'ftp_relay_host': '-b',
		'spoof_source_port': '-g',
		'spoof_source_ip': '-S',
		'spoof_source_mac': '--spoof-mac',
		'fragment': '-f',
		'mtu': '--mtu',
		'ttl': '--ttl',
		'badsum': '--badsum',
		'ipv6': '-6',
		'traceroute': '--traceroute',
		'disable_arp_ping': '--disable-arp-ping',
		'output_path': '-oX',
	}
	opt_value_map = {
		PORTS: lambda x: ','.join([str(p) for p in x]) if isinstance(x, list) else x
	}
	install_pre = {
		'apt|pacman|brew': ['nmap'],
		'apk': ['nmap', 'nmap-scripts'],
	}
	install_cmd = (
		'sudo git clone --depth 1 --single-branch https://github.com/scipag/vulscan /opt/scipag_vulscan || true && '
		'sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true'
	)
	proxychains = True
	proxychains_flavor = 'proxychains4'
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.xml'
		self.output_path = output_path
		self.cmd += f' -oX {self.output_path}'
		tcp_syn_stealth = self.cmd_options.get('tcp_syn_stealth')
		tcp_connect = self.cmd_options.get('tcp_connect')
		if tcp_connect and tcp_syn_stealth:
			self._print(
				'Options -sT (SYN stealth scan) and -sS (CONNECT scan) are conflicting. Keeping only -sS.',
				'bold gold3')
			self.cmd = self.cmd.replace('-sT ', '')

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find XML results in {self.output_path}')
			return
		yield Info(message=f'XML results saved to {self.output_path}')
		yield from self.xml_to_json()

	def xml_to_json(self):
		results = []
		with open(self.output_path, 'r') as f:
			content = f.read()
			try:
				results = xmltodict.parse(content)  # parse XML to dict
			except Exception as exc:
				yield Error(
					message=f'Cannot parse XML output {self.output_path} to valid JSON.',
					traceback=traceback_as_string(exc)
				)
		yield from nmapData(results)


class nmapData(dict):

	def __iter__(self):
		datas = []
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
				service_name = extra_data.get('service_name', '')
				version_exact = extra_data.get('version_exact', False)
				conf = extra_data.get('confidence')

				# Grab CPEs
				cpes = extra_data.get('cpe', [])

				# Get script output
				scripts = self._get_scripts(port)

				# Get port protocol
				protocol = port['@protocol'].lower()

				# Yield port data
				port = {
					PORT: port_number,
					HOST: hostname,
					STATE: state,
					SERVICE_NAME: service_name,
					IP: ip,
					PROTOCOL: protocol,
					EXTRA_DATA: extra_data,
					CONFIDENCE: conf
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
						debug(f'Script output parser for "{script_id}" is not supported YET.', sub='cve')
						continue
					for data in func(output, cpes=cpes):
						data.update(metadata)
						confidence = 'low'
						if 'cpe-match' in data[TAGS]:
							confidence = 'high' if version_exact else 'medium'
						data[CONFIDENCE] = confidence
						if (CONFIG.runners.skip_cve_low_confidence and data[CONFIDENCE] == 'low'):
							debug(f'{data[ID]}: ignored (low confidence).', sub='cve')
							continue
						if data in datas:
							continue
						yield data
						datas.append(data)

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
		if hostnames:
			hostnames = hostnames.get('hostname', [])
			if isinstance(hostnames, dict):
				hostnames = [hostnames]
			if hostnames:
				hostname = hostnames[0]['@name']
		else:
			hostname = self._get_address(host_cfg).get('@addr', None)
		return hostname

	def _get_address(self, host_cfg):
		if isinstance(host_cfg.get('address', {}), list):
			addresses = host_cfg.get('address', {})
			for address in addresses:
				if address.get('@addrtype') == "ipv4":
					return address
		return host_cfg.get('address', {})

	def _get_ip(self, host_cfg):
		return self._get_address(host_cfg).get('@addr', None)

	def _get_extra_data(self, port_cfg):
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
		product = extra_data.get('product', None) or extra_data.get('name', None)
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
				data = VulnMulti.lookup_cve(vuln['id'], *cpes)
				if data:
					vuln.update(data)
				yield vuln
			else:
				debug(f'Vulscan provider {provider_name} is not supported YET.', sub='cve.provider', verbose=True)
				continue

	def _parse_vulners_output(self, out, **kwargs):
		cpes = kwargs.get('cpes', [])
		provider_name = 'vulners'
		for line in out.splitlines():
			if not line:
				continue
			line = line.strip()
			if line.startswith('cpe:'):
				cpes.append(line.rstrip(':'))
				continue
			elems = tuple(line.split('\t'))

			if len(elems) == 4:  # exploit
				# TODO: Implement exploit processing
				exploit_id, cvss_score, reference_url, _ = elems
				name = exploit_id
				# edb_id = name.split(':')[-1] if 'EDB-ID' in name else None
				exploit = {
					ID: exploit_id,
					NAME: name,
					PROVIDER: provider_name,
					REFERENCE: reference_url,
					TAGS: [exploit_id, provider_name],
					CVSS_SCORE: cvss_score,
					CONFIDENCE: 'low',
					'_type': 'exploit',
				}
				# TODO: lookup exploit in ExploitDB to find related CVEs
				# if edb_id:
				# 	print(edb_id)
				# 	exploit_data = VulnMulti.lookup_exploitdb(edb_id)
				vuln = VulnMulti.lookup_cve_from_vulners_exploit(exploit_id, *cpes)
				if vuln:
					yield vuln
					exploit[TAGS].extend(vuln[TAGS])
					exploit[CONFIDENCE] = vuln[CONFIDENCE]
				yield exploit

			elif len(elems) == 3:  # vuln
				vuln = {}
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
					data = VulnMulti.lookup_cve(vuln_id, *cpes)
					if data:
						vuln.update(data)
					yield vuln
				else:
					debug(f'Vulners parser for "{vuln_type}" is not implemented YET.', sub='cve')
			else:
				debug(f'Unrecognized vulners output: {elems}', sub='cve')

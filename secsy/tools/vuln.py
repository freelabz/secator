"""Vulnerability scanners."""

import logging
import re
from datetime import datetime
from itertools import groupby
from urllib.parse import urlparse

import requests
import xmltodict
from cpe import CPE
from termcolor import colored, cprint

from secsy.cmd import CommandRunner
from secsy.definitions import *

logger = logging.getLogger(__name__)

VULN_META_OPTS = {
	HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
	DELAY: {'type': float, 'help': 'Delay to add between each requests'},
    FOLLOW_REDIRECT: {'is_flag': True, 'default': True, 'help': 'Follow HTTP redirects'},
	PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
	RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
	TIMEOUT: {'type': int, 'help': 'Request timeout'},
	USER_AGENT: {'type': str, 'help': 'User agent, e.g "Mozilla Firefox 1.0"'}
}

VULN_OUTPUT = [
	VULN_ID,
	VULN_PROVIDER,
	VULN_NAME,
	VULN_DESCRIPTION,
	VULN_SEVERITY,
	VULN_CONFIDENCE,
	VULN_CVSS_SCORE,
	VULN_MATCHED_AT,
	VULN_TAGS,
	VULN_REFERENCES,
	VULN_EXTRACTED_RESULTS,
]


class VulnCommand(CommandRunner):
	meta_opts = VULN_META_OPTS
	output_schema = VULN_OUTPUT
	output_table_fields = [VULN_MATCHED_AT, VULN_SEVERITY, VULN_CONFIDENCE, VULN_NAME, VULN_ID, VULN_CVSS_SCORE, VULN_TAGS, VULN_EXTRACTED_RESULTS]
	output_table_sort_fields = ('_confidence', '_severity', 'cvss_score')
	output_type = VULN
	input_type = HOST

	@staticmethod
	def on_table(items):
		return sort_vulns_by_severity(items)

	@staticmethod
	def on_item_converted(self, item):
		severity_map = {
			'critical': 0,
			'high': 1,
			'medium': 2,
			'low': 3,
			'info': 4,
			None: 5
		}
		item['_severity'] = severity_map[item['severity']]
		item['_confidence'] = severity_map[item['confidence']]
		return item


class nmap(VulnCommand):
	"""Network Mapper is a free and open source utility for network discovery
	and security auditing."""
	cmd = f'nmap -sV -Pn'
	input_flag = None
	file_flag = '-iL'
	opt_prefix = '--'
	opts = {
		PORTS: {'type': str, 'help': 'Ports to scan'},
		SCRIPT: {'type': str, 'default': 'vulscan/,vulners', 'help': 'nmap NSE script'},
		'xml_path': {'type': str, 'default': None, 'help': 'Path to nmap XML file'}
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

	install_cmd = 'sudo apt install nmap'

	def stream(self):
		raise NotImplementedError()

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
		output_path = self.get_opt_value('xml_path')
		if not output_path:
			timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
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
			hostname = host_cfg.get('address')['@addr']
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
				vuln_data = self.lookup_cve(vuln['id'], cpes=cpes)
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
					vuln_data = self.lookup_cve(vuln_id, cpes=[cpe])
					if vuln_data:
						vuln.update(vuln_data)
					yield vuln
				else:
					logger.debug(f'Vulners parser for "{vuln_type}" is not implemented YET.')
			else:
				logger.error(f'Unrecognized vulners output: {elems}')

	def _parse_http_csrf_output(self, out, port_data):
		pass

	def lookup_cve(self, cve_id, cpes=[]):
		"""Search for a CVE using CVESearch and return Vulnerability data.

		Args:
			cve_id (str): CVE ID in the form CVE-*
			cpes (str, Optional): CPEs to match for.

		Returns:
			dict: Vulnerability dict.
		"""
		try:
			cve_info = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}').json()
			if not cve_info:
				logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
		except requests.exceptions.ConnectionError:
			return None

		# Match the CPE string against the affected products CPE FS strings from the 
		# CVE data if a CPE was passed.
		# This allow to limit the number of False positives (high) that we get from
		# nmap NSE vuln scripts like vulscan and ensure we keep only right matches.
		# The check is not executed if no CPE was passed (sometimes nmap cannot 
		# properly detect a CPE) or if the CPE version cannot be determined.
		# TODO: Add info to Vulnerability model for the following things
		# * CPE product found     - product_detected=True
		# * CPE version was found - product_version_detected=True
		# * CPE match was success - cpe_match=True
		cpe_match = False
		tags = []
		if cpes:
			for cpe in cpes:
				cpe_obj = CPE(cpe)
				cpe_fs = cpe_obj.as_fs()
				# cpe_version = cpe_obj.get_version()[0]
				vulnerable_fs = cve_info['vulnerable_product']
				logger.debug(f'Matching CPE {cpe} against {len(vulnerable_fs)} vulnerable products for {cve_id}')
				for fs in vulnerable_fs:
					if fs == cpe_fs:
						# logger.debug(f'Found matching CPE FS {cpe_fs} ! The CPE is vulnerable to CVE {cve_id}')
						cpe_match = True
						tags.append('cpe-match')

		# Parse CVE id and CVSS
		name = id = cve_info['id']
		cvss = cve_info.get('cvss')
		# exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
		# osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])

		# Get description
		description = cve_info.get('summary')
		if description is not None:
			description = description.replace(id, '').strip()

		# Get references
		references = cve_info.get(VULN_REFERENCES, [])
		cve_ref_url = f'https://cve.circl.lu/cve/{id}'
		references.append(cve_ref_url)

		# Get CWE ID
		vuln_cwe_id = cve_info.get('cwe')
		if vuln_cwe_id is None:
			tags.append(vuln_cwe_id)

		# Parse capecs for a better vuln name / type
		capecs = cve_info.get('capec', [])
		if capecs and len(capecs) > 0:
			name = capecs[0]['name']

		# Parse ovals for a better vuln name / type
		ovals = cve_info.get('oval', [])
		if ovals:
			if description == 'none':
				description = ovals[0]['title']
			family = ovals[0]['family']
			tags.append(family)

		# Set vulnerability severity based on CVSS score
		severity = None
		if cvss:
			if cvss < 4:
				severity = 'low'
			elif cvss < 7:
				severity = 'medium'
			elif cvss < 9:
				severity = 'high'
			else:
				severity = 'critical'

		# Set confidence
		confidence = 'low' if not cpe_match else 'high'
		vuln = {
			VULN_ID: id,
			VULN_NAME: name,
			VULN_PROVIDER: 'cve.circl.lu',
			VULN_SEVERITY: severity,
			VULN_CVSS_SCORE: cvss,
			VULN_TAGS: tags,
			VULN_REFERENCES: [f'https://cve.circl.lu/cve/{id}'] + references,
			VULN_DESCRIPTION: description,
			VULN_CONFIDENCE: confidence
		}
		return vuln


# class rustscan(nmap):
# 	# nmap but faster
# 	# rustscan -p <PORTS> -a <HOSTS> -- -A --script vulscan/
# 	pass


class nuclei(VulnCommand):
	"""Fast and customisable vulnerability scanner based on simple YAML based
	DSL.
	"""
	cmd = 'nuclei -silent -nc'
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-json'
	opts = {
		'templates': {'type': str, 'help': 'Templates'},
		'tags': {'type': str, 'help': 'Tags'},
		'exclude_tags': {'type': str, 'help': 'Exclude tags'},
		'exclude_severity': {'type': str, 'help': 'Exclude severity'}
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirects',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retries',
		THREADS: 'c',
		TIMEOUT: 'timeout',

		# nuclei opts
		'exclude_tags': 'exclude-tags',
		'exclude_severity': 'exclude-severity',
		'templates': 't'
	}
	opt_value_map = {
		'tags': lambda x: ','.join(x) if isinstance(x, list) else x,
		'templates': lambda x: ','.join(x) if isinstance(x, list) else x,
		'exclude_tags': lambda x: ','.join(x) if isinstance(x, list) else x,
	}
	output_map = {
		VULN_ID: lambda x: nuclei.id_extractor(x),
		VULN_PROVIDER: 'nuclei',
		VULN_NAME: lambda x: x['info']['name'],
		VULN_DESCRIPTION: lambda x: x['info'].get('description'),
		VULN_SEVERITY: lambda x: x['info'][VULN_SEVERITY],
		VULN_CONFIDENCE: lambda x: 'high',
		VULN_CVSS_SCORE: lambda x: x['info'].get('classification', {}).get('cvss-score'),
		VULN_MATCHED_AT:  'matched-at',
		VULN_TAGS: lambda x: x['info']['tags'],
		VULN_REFERENCES: lambda x: x['info']['reference'],
		VULN_EXTRACTED_RESULTS: lambda x: {'data': x.get('extracted-results', [])}
	}
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0]
		return None


class dalfox(VulnCommand):
	"""DalFox is a powerful open source XSS scanning tool."""
	cmd = 'dalfox'
	input_type = URL
	input_flag = 'url'
	file_flag = 'file'
	json_flag = '--format json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		FOLLOW_REDIRECT: 'follow-redirects',
		METHOD: 'method',
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent'
	}
	output_map = {
		VULN_ID: 'XSS Injection',
		VULN_NAME: 'XSS Injection',
		VULN_PROVIDER: 'dalfox',
		VULN_TAGS: lambda x: [x['cwe']],
		VULN_CONFIDENCE: 'high',
		VULN_MATCHED_AT: lambda x: urlparse(x['data'])._replace(query='').geturl(),
		VULN_EXTRACTED_RESULTS: lambda x: {
			k: v for k, v in x.items()
			if k not in ['type', 'severity', 'cwe']
		},
		VULN_SEVERITY: lambda x: x['severity'].lower()
	}

	@staticmethod
	def on_line(self, line):
		line = line.rstrip(',')
		return line


def sort_vulns_by_severity(vulns):
	data = []
	severity_map = {
		'critical': 0,
		'high': 1,
		'medium': 2,
		'low': 3,
		'info': 4,
		None: 5
	}
	for vuln in vulns:
		item = vuln.copy() # do not modify original results
		refs = item.get(VULN_REFERENCES) or []
		if isinstance(refs, list) and len(refs) > 0:
			item[VULN_REFERENCES] = refs[0]
		item['severity_nb'] = severity_map[item[VULN_SEVERITY]]
		item['confidence_nb'] = severity_map[item[VULN_CONFIDENCE]]
		data.append(item)
	return sorted(data, key=lambda x: (x['confidence_nb'], x['severity_nb']))


def extract_field(vulns, callable, default=None):
	items = [callable(v) for v in vulns]
	return next((item for item in items if item), default)


def print_vulns(vulns):
	"""Group list of vulnerability objects by 'matched_at' and print a nice 
	output.

	Args:
		list: List of dict.

	"""
	vulns = sorted(vulns, key=lambda x: x['matched_at'])
	for matched_at, vulns in groupby(vulns, lambda x: x['matched_at']):
		vulns = sort_vulns_by_severity(list(vulns))
		pextract = lambda x: x.get('extracted_results', {}).get('product')
		vextract = lambda x: x.get('extracted_results', {}).get('version')
		cextract = lambda x: x.get('extracted_results', {}).get('cpe')
		product = extract_field(vulns, pextract, default='?')
		version = extract_field(vulns, vextract, default='?')
		cpes = extract_field(vulns, cextract, default=[])
		cpes = ', '.join(cpes)
		msg = colored(f'\n • {matched_at}', 'magenta')
		msg += colored(f' [{product}/{version}]', 'cyan')
		if cpes:
			msg += colored(f' [{cpes}]', 'cyan')
		print(msg)
		# fields = VulnCommand.output_table_fields.copy()
		# fields.remove('matched_at')
		# print(fmt_table(vulns, output_table_fields=VulnCommand.output_table_fields))
		for vuln in vulns:
			name = vuln['name']
			confidence = vuln[VULN_CONFIDENCE]
			source = vuln['_source']
			severity = vuln.get(VULN_SEVERITY) or 'info'
			cvss_score = vuln.get('cvss_score') or '?'
			references = vuln.get(VULN_REFERENCES) or []
			severity_colors = {
				'critical': 'light_red',
				'high': 'red',
				'medium': 'light_yellow',
				'low': 'yellow',
				'info': 'green'
			}
			color = severity_colors[severity]
			color = 'light_grey' if confidence == 'low' else color
			vuln_str = f'{severity: <9} | {name: <45} | score: {cvss_score: <4} | confidence: {confidence: <4} | source: {source: <10}'
			if isinstance(references, list) and len(references) > 0:
					references = references[0]
			if references:
				vuln_str += f' | {references}'
			cprint(f'  {vuln_str}', color)	
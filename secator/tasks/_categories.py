import json
import os

import requests
from bs4 import BeautifulSoup
from cpe import CPE

from secator.definitions import (CIDR_RANGE, CVSS_SCORE, DELAY, DEPTH, DESCRIPTION, FILTER_CODES,
								 FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT, HEADER, HOST, ID,
								 MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, NAME, PATH, PROVIDER, PROXY,
								 RATE_LIMIT, REFERENCES, RETRIES, SEVERITY, TAGS, THREADS, TIMEOUT, URL, USER_AGENT,
								 USERNAME, WORDLIST)
from secator.output_types import Ip, Port, Subdomain, Tag, Url, UserAccount, Vulnerability
from secator.config import CONFIG
from secator.runners import Command
from secator.utils import debug


OPTS = {
	HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
	DELAY: {'type': float, 'short': 'd', 'help': 'Delay to add between each requests'},
	DEPTH: {'type': int, 'help': 'Scan depth', 'default': 2},
	FILTER_CODES: {'type': str, 'short': 'fc', 'help': 'Filter out responses with HTTP codes'},
	FILTER_REGEX: {'type': str, 'short': 'fr', 'help': 'Filter out responses with regular expression'},
	FILTER_SIZE: {'type': str, 'short': 'fs', 'help': 'Filter out responses with size'},
	FILTER_WORDS: {'type': str, 'short': 'fw', 'help': 'Filter out responses with word count'},
	FOLLOW_REDIRECT: {'is_flag': True, 'short': 'frd', 'help': 'Follow HTTP redirects'},
	MATCH_CODES: {'type': str, 'short': 'mc', 'help': 'Match HTTP status codes e.g "201,300,301"'},
	MATCH_REGEX: {'type': str, 'short': 'mr', 'help': 'Match responses with regular expression'},
	MATCH_SIZE: {'type': str, 'short': 'ms', 'help': 'Match respones with size'},
	MATCH_WORDS: {'type': str, 'short': 'mw', 'help': 'Match responses with word count'},
	METHOD: {'type': str, 'help': 'HTTP method to use for requests'},
	PROXY: {'type': str, 'help': 'HTTP(s) / SOCKS5 proxy'},
	RATE_LIMIT: {'type':  int, 'short': 'rl', 'help': 'Rate limit, i.e max number of requests per second'},
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
	TIMEOUT: {'type': int, 'help': 'Request timeout'},
	USER_AGENT: {'type': str, 'short': 'ua', 'help': 'User agent, e.g "Mozilla Firefox 1.0"'},
	WORDLIST: {'type': str, 'short': 'w', 'default': CONFIG.wordlists.defaults.http, 'help': 'Wordlist to use'}
}

OPTS_HTTP = [
	HEADER, DELAY, FOLLOW_REDIRECT, METHOD, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT
]

OPTS_HTTP_CRAWLERS = OPTS_HTTP + [
	DEPTH, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, FILTER_REGEX, FILTER_CODES, FILTER_SIZE, FILTER_WORDS,
	MATCH_CODES
]

OPTS_HTTP_FUZZERS = OPTS_HTTP_CRAWLERS + [WORDLIST]

OPTS_RECON = [
	DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT
]

OPTS_VULN = [
	HEADER, DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT
]


#---------------#
# HTTP category #
#---------------#

class Http(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_CRAWLERS}
	input_type = URL
	output_types = [Url]


class HttpCrawler(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_CRAWLERS}
	input_type = URL
	output_types = [Url]


class HttpFuzzer(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_HTTP_FUZZERS}
	input_type = URL
	output_types = [Url]


#----------------#
# Recon category #
#----------------#

class Recon(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_RECON}
	output_types = [Subdomain, UserAccount, Ip, Port]


class ReconDns(Recon):
	input_type = HOST
	output_types = [Subdomain]


class ReconUser(Recon):
	input_type = USERNAME
	output_types = [UserAccount]


class ReconIp(Recon):
	input_type = CIDR_RANGE
	output_types = [Ip]


class ReconPort(Recon):
	input_type = HOST
	output_types = [Port]


#---------------#
# Vuln category #
#---------------#

class Vuln(Command):
	meta_opts = {k: OPTS[k] for k in OPTS_VULN}
	output_types = [Vulnerability]

	@staticmethod
	def lookup_local_cve(cve_id):
		cve_path = f'{CONFIG.dirs.data}/cves/{cve_id}.json'
		if os.path.exists(cve_path):
			with open(cve_path, 'r') as f:
				return json.load(f)
		return None

	# @staticmethod
	# def lookup_exploitdb(exploit_id):
	# 	print('looking up exploit')
	# 	try:
	# 		resp = requests.get(f'https://exploit-db.com/exploits/{exploit_id}', timeout=5)
	#		resp.raise_for_status()
	#		content = resp.content
	# 	except requests.RequestException as e:
	#		debug(f'Failed remote query for {exploit_id} ({str(e)}).', sub='cve')
	# 		logger.error(f'Could not fetch exploit info for exploit {exploit_id}. Skipping.')
	# 		return None
	# 	return cve_info

	@staticmethod
	def create_cpe_string(product_name, version):
		"""
		Generate a CPE string for a given product and version.

		Args:
			product_name (str): The name of the product.
			version (str): The version of the product.

		Returns:
			str: A CPE string formatted according to the CPE 2.3 specification.
		"""
		cpe_version = "2.3"  # CPE Specification version
		part = "a"           # 'a' for application
		vendor = product_name.lower()  # Vendor name, using product name
		product = product_name.lower()  # Product name
		version = version  # Product version
		cpe_string = f"cpe:{cpe_version}:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
		return cpe_string

	@staticmethod
	def match_cpes(fs1, fs2):
		"""Check if two CPEs match. Partial matches consisting of <vendor>:<product>:<version> are considered a match.

		Args:
			fs1 (str): Format string 1.
			fs2 (str): Format string 2.

		Returns:
			bool: True if the two CPEs match, False otherwise.
		"""
		if fs1 == fs2:
			return True
		split_fs1 = fs1.split(':')
		split_fs2 = fs2.split(':')
		tup1 = split_fs1[3], split_fs1[4], split_fs1[5]
		tup2 = split_fs2[3], split_fs2[4], split_fs2[5]
		return tup1 == tup2

	@staticmethod
	def lookup_cve(cve_id, cpes=[]):
		"""Search for a CVE in local db or using cve.circl.lu and return vulnerability data.

		Args:
			cve_id (str): CVE ID in the form CVE-*
			cpes (str, Optional): CPEs to match for.

		Returns:
			dict: vulnerability data.
		"""
		cve_info = Vuln.lookup_local_cve(cve_id)

		# Online CVE lookup
		if not cve_info:
			if CONFIG.runners.skip_cve_search:
				debug(f'Skip remote query for {cve_id} since config.runners.skip_cve_search is set.', sub='cve')
				return None
			if CONFIG.offline_mode:
				debug(f'Skip remote query for {cve_id} since config.offline_mode is set.', sub='cve')
				return None
			try:
				resp = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}', timeout=5)
				resp.raise_for_status()
				cve_info = resp.json()
			except requests.RequestException as e:
				debug(f'Failed remote query for {cve_id} ({str(e)}).', sub='cve')
				return None

		# Match the CPE string against the affected products CPE FS strings from the CVE data if a CPE was passed.
		# This allow to limit the number of False positives (high) that we get from nmap NSE vuln scripts like vulscan
		# and ensure we keep only right matches.
		# The check is not executed if no CPE was passed (sometimes nmap cannot properly detect a CPE) or if the CPE
		# version cannot be determined.
		cpe_match = False
		tags = []
		if cpes:
			for cpe in cpes:
				cpe_obj = CPE(cpe)
				cpe_fs = cpe_obj.as_fs()
				# cpe_version = cpe_obj.get_version()[0]
				vulnerable_fs = cve_info['vulnerable_product']
				for fs in vulnerable_fs:
					# debug(f'{cve_id}: Testing {cpe_fs} against {fs}', sub='cve')  # for hardcore debugging
					if Vuln.match_cpes(cpe_fs, fs):
						debug(f'{cve_id}: CPE match found for {cpe}.', sub='cve')
						cpe_match = True
						tags.append('cpe-match')
						break
				if not cpe_match:
					debug(f'{cve_id}: no CPE match found for {cpe}.', sub='cve')

		# Parse CVE id and CVSS
		name = id = cve_info['id']
		cvss = cve_info.get('cvss') or 0
		# exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
		# osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])

		# Get description
		description = cve_info.get('summary')
		if description is not None:
			description = description.replace(id, '').strip()

		# Get references
		references = cve_info.get(REFERENCES, [])
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
			severity = Vuln.cvss_to_severity(cvss)

		# Set confidence
		vuln = {
			ID: id,
			NAME: name,
			PROVIDER: 'cve.circl.lu',
			SEVERITY: severity,
			CVSS_SCORE: cvss,
			TAGS: tags,
			REFERENCES: [f'https://cve.circl.lu/cve/{id}'] + references,
			DESCRIPTION: description,
		}
		return vuln

	@staticmethod
	def lookup_ghsa(ghsa_id):
		"""Search for a GHSA on Github and and return associated CVE vulnerability data.

		Args:
			ghsa (str): CVE ID in the form GHSA-*

		Returns:
			dict: vulnerability data.
		"""
		try:
			resp = requests.get(f'https://github.com/advisories/{ghsa_id}', timeout=5)
			resp.raise_for_status()
		except requests.RequestException as e:
			debug(f'Failed remote query for {ghsa_id} ({str(e)}).', sub='cve')
			return None
		soup = BeautifulSoup(resp.text, 'lxml')
		sidebar_items = soup.find_all('div', {'class': 'discussion-sidebar-item'})
		cve_id = sidebar_items[2].find('div').text.strip()
		vuln = Vuln.lookup_cve(cve_id)
		if vuln:
			vuln[TAGS].append('ghsa')
			return vuln
		return None

	@staticmethod
	def cvss_to_severity(cvss):
		if cvss < 4:
			severity = 'low'
		elif cvss < 7:
			severity = 'medium'
		elif cvss < 9:
			severity = 'high'
		else:
			severity = 'critical'
		return severity


class VulnHttp(Vuln):
	input_type = HOST


class VulnCode(Vuln):
	input_type = PATH


class VulnMulti(Vuln):
	input_type = HOST
	output_types = [Vulnerability]


#--------------#
# Tag category #
#--------------#

class Tagger(Command):
	input_type = URL
	output_types = [Tag]

#----------------#
# osint category #
#----------------#


class OSInt(Command):
	output_types = [UserAccount]

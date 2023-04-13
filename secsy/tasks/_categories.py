import json
import logging
import os

import requests
from bs4 import BeautifulSoup
from cpe import CPE

from secsy.definitions import (CIDR_RANGE, DEFAULT_WORDLIST, DELAY, DEPTH,
							   FILTER_CODES, FILTER_REGEX, FILTER_SIZE,
							   FILTER_WORDS, FOLLOW_REDIRECT, HEADER, HOST,
							   MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, PATH, PROXY, RATE_LIMIT,
							   RETRIES, TEMP_FOLDER, THREADS, TIMEOUT, URL,
							   USER_AGENT, USERNAME, VULN_CONFIDENCE,
							   VULN_CVSS_SCORE, VULN_DESCRIPTION, VULN_ID,
							   VULN_NAME, VULN_PROVIDER, VULN_REFERENCES,
							   VULN_SEVERITY, VULN_TAGS, WORDLIST)
from secsy.output_types import (Ip, Port, Subdomain, Tag, Url, UserAccount,
								Vulnerability)
from secsy.runners import Command

logger = logging.getLogger(__name__)

OPTS = {
	HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
	DELAY: {'type': float, 'short': 'd', 'help': 'Delay to add between each requests'},
	DEPTH: {'type': int, 'help': 'Scan depth'},
	FILTER_CODES: {'type': str, 'short': 'fc', 'help': 'Filter out responses with HTTP codes'},
	FILTER_REGEX: {'type': str, 'short': 'fr', 'help': 'Filter out responses with regular expression'},
	FILTER_SIZE: {'type': str, 'short': 'fs', 'help': 'Filter out responses with size'},
	FILTER_WORDS: {'type': str, 'short': 'fw', 'help': 'Filter out responses with word count'},
	FOLLOW_REDIRECT: {'is_flag': True, 'short': 'fr', 'help': 'Follow HTTP redirects'},
	MATCH_CODES: {'type': str, 'short': 'mc', 'help': 'Match HTTP status codes e.g "201,300,301"'},
	MATCH_REGEX: {'type': str, 'short': 'mr', 'help': 'Match responses with regular expression'},
	MATCH_SIZE: {'type': str, 'short': 'ms', 'help': 'Match respones with size'},
	MATCH_WORDS: {'type': str, 'short': 'mw', 'help': 'Match responses with word count'},
	METHOD: {'type': str, 'help': 'HTTP method to use for requests'},
	PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
	RATE_LIMIT: {'type':  int, 'short': 'rl', 'help': 'Rate limit, i.e max number of requests per second'},
	RETRIES: {'type': int, 'help': 'Retries'},
	THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
	TIMEOUT: {'type': int, 'help': 'Request timeout'},
	USER_AGENT: {'type': str, 'short': 'ua', 'help': 'User agent, e.g "Mozilla Firefox 1.0"'},
	WORDLIST: {'type': str, 'short': 'wl', 'default': DEFAULT_WORDLIST, 'help': 'Wordlist to use'}
}

OPTS_HTTP = [
	HEADER, DELAY, FOLLOW_REDIRECT, METHOD, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, USER_AGENT
]

OPTS_HTTP_CRAWLERS = OPTS_HTTP + [
	DEPTH, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, FILTER_REGEX, FILTER_CODES, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
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
		cve_path = f'{TEMP_FOLDER}/cves/{cve_id}.json'
		if os.path.exists(cve_path):
			with open(cve_path, 'r') as f:
				return json.load(f)
		return None

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
		if not cve_info:
			logger.debug(f'{cve_id} not found locally. Use `secsy utils download-cves` to update the local database.')
			try:
				cve_info = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}').json()
				if not cve_info:
					logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
			except requests.exceptions.ConnectionError:
				return None

		# Match the CPE string against the affected products CPE FS strings from the CVE data if a CPE was passed.
		# This allow to limit the number of False positives (high) that we get from nmap NSE vuln scripts like vulscan
		# and ensure we keep only right matches.
		# The check is not executed if no CPE was passed (sometimes nmap cannot properly detect a CPE) or if the CPE
		# version cannot be determined.
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
		cvss = cve_info.get('cvss') or 0
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

	@staticmethod
	def lookup_ghsa(ghsa_id):
		"""Search for a GHSA on Github and and return associated CVE vulnerability data.

		Args:
			ghsa (str): CVE ID in the form GHSA-*

		Returns:
			dict: vulnerability data.
		"""
		reference = f'https://github.com/advisories/{ghsa_id}'
		response = requests.get(reference)
		soup = BeautifulSoup(response.text, 'lxml')
		sidebar_items = soup.find_all('div', {'class': 'discussion-sidebar-item'})
		cve_id = sidebar_items[2].find('div').text.strip()
		data = Vuln.lookup_cve(cve_id)
		data[VULN_TAGS].append('ghsa')
		return data


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

from functools import cache

from secator.utils import debug
from secator.providers._base import CVEProvider

import requests
from bs4 import BeautifulSoup


class ghsa(CVEProvider):
	"""GHSA data from Github."""

	@cache
	@staticmethod
	def lookup_cve(ghsa_id, convert=True):
		"""Search for a GHSA on Github and and return associated CVE vulnerability data.

		Args:
			ghsa (str): GHSA ID in the form GHSA-*
			convert (bool): Whether to convert the CVE data to a Vulnerability object.

		Returns:
			Vulnerability | dict | None: vulnerability data, None if no response or empty response.
		"""
		try:
			resp = requests.get(f'https://github.com/advisories/{ghsa_id}', timeout=5)
			resp.raise_for_status()
		except requests.RequestException as e:
			debug(f'Failed remote query for {ghsa_id} ({str(e)}).', sub='cve')
			return None
		soup = BeautifulSoup(resp.text, 'lxml')
		sidebar_items = soup.find_all('div', {'class': 'discussion-sidebar-item'})
		if len(sidebar_items) < 4:
			debug(f'{ghsa_id}: Unexpected HTML structure, expected at least 4 sidebar items', sub='cve')
			return None
		cve_id = sidebar_items[3].find('div').text.strip()
		if not cve_id:
			debug(f'{ghsa_id}: No CVE ID found in sidebar', sub='cve')
			return None
		if not cve_id.startswith('CVE'):
			debug(f'{ghsa_id}: No CVE_ID extracted from https://github.com/advisories/{ghsa_id}', sub='cve')
			return None
		vuln = CVEProvider.lookup_external_cve(cve_id)
		if vuln and convert:
			vuln.tags.append('ghsa')
			return vuln
		return None

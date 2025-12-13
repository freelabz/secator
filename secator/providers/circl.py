from functools import cache

import requests
import json

from secator.config import CONFIG
from secator.utils import debug
from secator.providers._base import CVEProvider
from secator.output_types import Vulnerability


class circl(CVEProvider):
	"""CVE data from vulnerability.circl.lu."""

	@cache
	@staticmethod
	def lookup_cve(cve_id, convert=True):
		"""Get CVE data from vulnerability.circl.lu.

		Args:
			cve_id (str): CVE id.
			convert (bool): Whether to convert the CVE data to a Vulnerability object.

		Returns:
			Vulnerability | dict | None: CVE data, None if no response or empty response.
		"""
		if CONFIG.runners.skip_cve_search:
			debug(f'{cve_id}: skipped remote query since config.runners.skip_cve_search is set.', sub='cve.circl')
			return None
		if CONFIG.offline_mode:
			debug(f'{cve_id}: skipped remote query since config.offline_mode is set.', sub='cve.circl')
			return None
		try:
			resp = requests.get(f'https://vulnerability.circl.lu/api/cve/{cve_id}', timeout=5)
			resp.raise_for_status()
			cve_info = resp.json()
			if not cve_info:
				debug(f'{cve_id}: empty response from https://vulnerability.circl.lu/api/cve/{cve_id}', sub='cve.circl')
				return None
			debug(f'{cve_id}: response from https://vulnerability.circl.lu/api/cve/{cve_id}:\n{json.dumps(cve_info, indent=2)}', sub='cve.circl', verbose=True)  # noqa: E501
			if convert:
				cve_info = circl.convert_cve_info(cve_info)
				debug(f'{cve_id}: converted CVE info:\n{json.dumps(cve_info.toDict(), indent=2)}', sub='cve.circl', verbose=True)  # noqa: E501
			cve_path = f'{CONFIG.dirs.data}/cves/{cve_id}.json'
			with open(cve_path, 'w') as f:
				if convert:
					f.write(json.dumps(cve_info.toDict(), indent=2))
				else:
					f.write(json.dumps(cve_info, indent=2))
			debug(f'{cve_id}: downloaded to {cve_path}', sub='cve.circl')
			return cve_info
		except requests.RequestException as e:
			debug(f'{cve_id}: failed remote query ({str(e)}).', sub='cve.circl')
			return None

	@staticmethod
	def convert_cve_info(cve_info: dict) -> Vulnerability:
		"""Convert CVE info to secator Vulnerability."""
		cve_id = cve_info['cveMetadata']['cveId']
		cna = cve_info['containers']['cna']
		adp = cve_info['containers']['adp']
		name = cna.get('title')
		if not name or name == 'other':
			name = cve_id
		description = cna.get('descriptions', [{}])[0].get('value', '')
		if description:
			description = description.replace(cve_id, '').strip()
		cwe_id = cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('cweId')
		tags = [cwe_id] if cwe_id else []
		reference = f'https://vulnerability.circl.lu/cve/{cve_id}'
		references = [reference] + [u['url'] for u in cna['references']]

		# Set CVSS score and vector
		cvss_score = 0
		cvss_vec = ''
		severity = ''
		for metric in cna.get('metrics', []):
			for name, value in metric.items():
				if 'cvss' in name:
					cvss_score = value['baseScore']
					severity = value['baseSeverity']
					cvss_vec = value['vectorString']

		# Set CPEs affected
		cpes_affected = []
		for product in cna['affected']:
			cpes_affected.extend(product.get('cpes', []))
		for item in adp:
			affected = item.get('affected', [])
			for product in affected:
				cpes_affected.extend(product.get('cpes', []))

		# Set vulnerability data
		vuln = Vulnerability(
			name=name or cve_id,
			provider='vulnerability.circl.lu',
			id=cve_id,
			severity=severity,
			cvss_score=cvss_score,
			cvss_vec=cvss_vec,
			epss_score=0,
			tags=tags,
			extra_data={'cpes': cpes_affected},
			description=description,
			references=references,
			reference=reference
		)
		return vuln
		return vuln

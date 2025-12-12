import os
import json

from secator.config import CONFIG
from secator.output_types import Vulnerability, Exploit
from secator.utils import debug

from functools import cache


class CVEProvider:
	"""Base class for CVE providers."""

	@cache
	@staticmethod
	def lookup_external_cve(cve_id, provider=CONFIG.providers.defaults['cve']):
		"""Search for a CVE info and return vulnerability data.

		Args:
			cve_id (str): CVE ID in the form CVE-*
			provider (str): Provider name, default is CONFIG.providers.defaults['cve'].

		Returns:
			Vulnerability | None: vulnerability data, None if no response or empty response.
		"""
		if provider == 'circl':
			from secator.providers.circl import circl
			return circl.lookup_cve(cve_id)
		elif provider == 'vulners':
			from secator.providers.vulners import vulners
			return vulners.lookup_cve(cve_id)
		else:
			raise ValueError(f'Provider {provider} not supported')

	@staticmethod
	def lookup_local_cve(cve_id):
		"""Lookup a CVE by ID from local cache."""
		cve_path = f'{CONFIG.dirs.data}/cves/{cve_id}.json'
		if os.path.exists(cve_path):
			debug(f'{cve_id}: found in cache at {cve_path}', sub='cve')
			with open(cve_path, 'r') as f:
				return Vulnerability(**json.load(f))
		debug(f'{cve_id}: not found in cache', sub='cve')
		return None

	@staticmethod
	def lookup_cve(cve_id):
		"""Lookup a CVE by ID."""
		raise NotImplementedError('lookup_cve not implemented by cve provider')

	@staticmethod
	def lookup_cpe(cpe_id):
		"""Lookup a CPE by ID."""
		raise NotImplementedError('lookup_cpe not implemented by cve provider')


class ExploitProvider:
	"""Base class for Exploit providers."""

	@cache
	@staticmethod
	def lookup_external_exploit(exploit_id, provider=CONFIG.providers.defaults['exploit']):
		"""Search for a exploit info and return exploit data.

		Args:
			exploit_id (str): Exploit ID in the form EXPLOIT-*
			provider (str): Provider name, default is CONFIG.providers.defaults['exploit'].

		Returns:
			Exploit | None: exploit data, None if no response or empty response.
		"""
		if provider == 'exploitdb':
			from secator.providers.exploitdb import exploitdb
			return exploitdb.lookup_exploit(exploit_id)
		else:
			raise ValueError(f'Provider {provider} not supported')

	@staticmethod
	def lookup_local_exploit(exploit_id):
		"""Lookup an exploit by ID from local cache."""
		exploit_path = f'{CONFIG.dirs.data}/exploits/{exploit_id}.json'
		if os.path.exists(exploit_path):
			with open(exploit_path, 'r') as f:
				return Exploit(**json.load(f))
		debug(f'{exploit_id}: not found in cache', sub='exploit')

	@staticmethod
	def lookup_exploit(exploit_id):
		"""Lookup an exploit by ID."""
		raise NotImplementedError('lookup_exploit not implemented by exploit provider')

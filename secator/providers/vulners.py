from functools import cache

from secator.config import CONFIG
from secator.utils import debug
from secator.providers._base import CVEProvider


class vulners(CVEProvider):
	"""CVE data from Vulners."""

	@cache
	@staticmethod
	def lookup_cve(cve_id):
		"""Search for a CVE on Vulners and return vulnerability data.

		Args:
			cve_id (str): CVE ID.

		Returns:
			dict: vulnerability data.
		"""
		api_key = CONFIG.addons.vulners.api_key
		enabled = CONFIG.addons.vulners.enabled
		if not enabled:
			return None
		if not api_key:
			raise ValueError('Vulners API key not set. Please run secator config set addons.vulners.api_key <API_KEY>')
		try:
			import vulners
			vulners_client = vulners.VulnersApi(api_key=api_key)
			cve_data = vulners_client.search.get_bulletin(cve_id, fields=["*"])
			return cve_data
		except Exception as e:
			debug(f'Failed to lookup CVE {cve_id} from vulners: {str(e)}', sub='cve.vulners')
			return None

	@cache
	@staticmethod
	def lookup_cpe(cpe_id):
		"""Search for a CPE on Vulners and return CPE data.

		Args:
			cpe_id (str): CPE ID.

		Returns:
			dict: CPE data.
		"""
		api_key = CONFIG.addons.vulners.api_key
		enabled = CONFIG.addons.vulners.enabled
		if not enabled:
			return None
		if not api_key:
			raise ValueError('Vulners API key not set. Please run secator config set addons.vulners.api_key <API_KEY>')
		try:
			import vulners
			vulners_client = vulners.VulnersApi(api_key=api_key)
			cpe_data = vulners_client.search.get_bulletin(cpe_id, fields=["*"])
			return cpe_data
		except Exception as e:
			debug(f'Failed to lookup CPE {cpe_id} from vulners: {str(e)}', sub='cve.vulners')
			return None

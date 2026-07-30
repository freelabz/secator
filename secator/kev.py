"""CISA Known Exploited Vulnerabilities (KEV) catalog helpers.

The CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
lists CVEs that are known to be actively exploited in the wild. Secator downloads the
feed once (cached to the data directory, like wordlists / payloads) and exposes the set
of KEV CVE IDs so that any emitted vulnerability whose CVE is known-exploited can be
tagged with ``kev``.
"""
import json

from secator.config import CONFIG, download_file

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# Lazily-loaded cache of upper-cased KEV CVE IDs. ``None`` means "not loaded yet"; an empty
# set means "loaded but unavailable" (offline / download failed) so we never retry per-vuln.
_KEV_CVE_IDS = None


def get_kev_cve_ids():
	"""Return the set of KEV CVE IDs (upper-cased), downloading the feed once if needed.

	The result is memoized for the lifetime of the process. On any failure (offline mode,
	download error, malformed feed) an empty set is cached and returned, so tagging simply
	becomes a no-op instead of raising.

	Returns:
		set[str]: Upper-cased CVE IDs present in the CISA KEV catalog.
	"""
	global _KEV_CVE_IDS
	if _KEV_CVE_IDS is None:
		_KEV_CVE_IDS = _load_kev_cve_ids()
	return _KEV_CVE_IDS


def _load_kev_cve_ids():
	"""Download and parse the CISA KEV feed, returning the set of CVE IDs."""
	from secator.utils import debug
	try:
		path = download_file(
			KEV_URL, CONFIG.dirs.data, CONFIG.offline_mode, 'kev',
			name='known_exploited_vulnerabilities.json'
		)
		if not path:
			return set()
		with open(path) as f:
			data = json.load(f)
		return {
			vuln['cveId'].upper()
			for vuln in data.get('vulnerabilities', [])
			if vuln.get('cveId')
		}
	except Exception as e:
		debug(f'Failed to load CISA KEV catalog: {e}', sub='cve')
		return set()

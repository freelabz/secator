"""CISA Known Exploited Vulnerabilities (KEV) catalog helpers.

The CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
lists CVEs that are known to be actively exploited in the wild. Secator exposes the set
of KEV CVE IDs so any emitted vulnerability whose CVE is known-exploited can be tagged
with ``kev``.

Sources are tried in order and fail open (an empty set means "no tagging", never an error):
first the live/cached CISA feed downloaded to the data dir (like wordlists / payloads), then
the mirror bundled with the package (secator/data/known_exploited_vulnerabilities.json). The
bundled mirror — kept current by a nightly workflow and each release — is what makes KEV
tagging work in offline / constrained environments where cisa.gov isn't reachable.

``secator update`` refreshes the cached copy from the live feed (see ``refresh_kev``).
"""
import json
import os
from pathlib import Path

from secator.config import CONFIG, download_file

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
KEV_FILENAME = 'known_exploited_vulnerabilities.json'

# Mirror bundled with the package (offline fallback). Kept fresh by .github/workflows/update-kev.yml.
BUNDLED_KEV_PATH = Path(os.path.dirname(__file__)) / 'data' / KEV_FILENAME

# Lazily-loaded cache of upper-cased KEV CVE IDs. ``None`` means "not loaded yet"; an empty
# set means "loaded but unavailable" so we never retry per-vuln.
_KEV_CVE_IDS = None


def get_kev_cve_ids():
	"""Return the set of KEV CVE IDs (upper-cased), loading them once if needed.

	The result is memoized for the lifetime of the process. Sources are tried in order
	(live/cached feed, then the bundled mirror); on total failure an empty set is cached
	and returned, so tagging becomes a no-op instead of raising.

	Returns:
		set[str]: Upper-cased CVE IDs present in the CISA KEV catalog.
	"""
	global _KEV_CVE_IDS
	if _KEV_CVE_IDS is None:
		_KEV_CVE_IDS = _load_kev_cve_ids()
	return _KEV_CVE_IDS


def _parse_kev_cve_ids(data):
	"""Extract the set of upper-cased CVE IDs from a parsed CISA KEV feed.

	The CISA feed key is ``cveID`` (capital I/D) — the original code used ``cveId``, which
	silently skipped every entry, making KEV tagging a permanent no-op.
	"""
	return {
		vuln['cveID'].upper()
		for vuln in (data or {}).get('vulnerabilities', [])
		if vuln.get('cveID')
	}


def _load_kev_cve_ids():
	"""Load KEV CVE IDs: live/cached CISA feed first, then the bundled mirror."""
	from secator.utils import debug

	# 1. Live/cached CISA feed (download_file caches to the data dir; honors offline_mode
	#    and returns None on offline / download error / no cache).
	try:
		path = download_file(KEV_URL, CONFIG.dirs.data, CONFIG.offline_mode, 'kev', name=KEV_FILENAME)
		if path:
			with open(path) as f:
				return _parse_kev_cve_ids(json.load(f))
	except Exception as e:
		debug(f'Failed to load CISA KEV catalog from the live feed: {e}', sub='cve')

	# 2. Fallback: the mirror bundled with the package (offline / constrained environments).
	try:
		with open(BUNDLED_KEV_PATH) as f:
			ids = _parse_kev_cve_ids(json.load(f))
		debug(f'Using bundled CISA KEV mirror ({len(ids)} CVEs).', sub='cve')
		return ids
	except Exception as e:
		debug(f'Failed to load bundled CISA KEV mirror: {e}', sub='cve')
		return set()


def refresh_kev():
	"""Force a fresh download of the CISA KEV feed into the cache. Returns the CVE-ID set.

	``download_file`` returns the cached copy when it exists and never re-downloads, so we
	clear it first. No-op in offline mode (returns whatever is currently available). Called
	by ``secator update`` so users get the latest catalog without a secator release.
	"""
	global _KEV_CVE_IDS
	if not CONFIG.offline_mode:
		cached = Path(CONFIG.dirs.data) / KEV_FILENAME
		try:
			cached.unlink()
		except (FileNotFoundError, OSError):
			pass
	_KEV_CVE_IDS = None  # bust the in-process memo so get_kev_cve_ids() re-loads
	return get_kev_cve_ids()

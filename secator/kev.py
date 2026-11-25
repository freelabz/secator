"""CISA Known Exploited Vulnerabilities (KEV) catalog helpers.

The CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
lists CVEs known to be actively exploited in the wild. Secator exposes the set of KEV
CVE IDs so any emitted vulnerability whose CVE is known-exploited can be tagged ``kev``.

The catalog ships as a mirror bundled with the package
(``secator/data/known_exploited_vulnerabilities.json``). On first use it is copied into
the cache dir (``CONFIG.dirs.cves``); reads always come from that cache, so KEV tagging
works offline / in constrained environments with no network at run time. ``secator
update`` re-downloads the mirror from GitHub (where the nightly workflow keeps it fresh from
cisa.gov), updates the bundled copy, and re-copies it to the cache (see ``refresh_kev``).
"""
import hashlib
import json
import os
import shutil
from pathlib import Path

from secator.config import CONFIG

KEV_URL = 'https://raw.githubusercontent.com/freelabz/secator/main/secator/data/known_exploited_vulnerabilities.json'
KEV_FILENAME = 'known_exploited_vulnerabilities.json'

# Mirror bundled with the package (source of truth, refreshed nightly + on release).
BUNDLED_KEV_PATH = Path(os.path.dirname(__file__)) / 'data' / KEV_FILENAME

# Lazily-loaded cache of upper-cased KEV CVE IDs. ``None`` means "not loaded yet"; an empty
# set means "loaded but unavailable" so we never retry per-vuln.
_KEV_CVE_IDS = None


def _cache_path():
	"""Cache location for the KEV catalog (under the configured cves dir)."""
	return Path(CONFIG.dirs.cves) / KEV_FILENAME


def get_kev_cve_ids():
	"""Return the set of KEV CVE IDs (upper-cased), loading them once from the cache.

	Memoized for the process lifetime. On any failure an empty set is cached and returned,
	so tagging becomes a no-op instead of raising.

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


def ensure_kev_cache():
	"""Seed the cache from the bundled mirror when it is missing or older than the bundle.

	Called on first use (startup). Idempotent: a cache that ``secator update`` wrote from
	the live feed (same-or-newer mtime than the bundle) is left untouched; a pip upgrade
	that ships a newer bundle re-seeds it.
	"""
	from secator.utils import debug
	try:
		cache = _cache_path()
		fresh_bundle = BUNDLED_KEV_PATH.exists() and (
			not cache.exists() or BUNDLED_KEV_PATH.stat().st_mtime > cache.stat().st_mtime
		)
		if fresh_bundle:
			cache.parent.mkdir(parents=True, exist_ok=True)
			shutil.copyfile(BUNDLED_KEV_PATH, cache)
			debug(f'Seeded KEV cache from bundled mirror -> {cache}', sub='cve')
	except Exception as e:
		debug(f'Failed to seed KEV cache: {e}', sub='cve')


def _load_kev_cve_ids():
	"""Load KEV CVE IDs from the cache (seeded from the bundled mirror). No network."""
	from secator.utils import debug
	ensure_kev_cache()
	for path in (_cache_path(), BUNDLED_KEV_PATH):  # cache first, bundle as last resort
		try:
			with open(path) as f:
				return _parse_kev_cve_ids(json.load(f))
		except Exception as e:
			debug(f'Failed to load KEV catalog from {path}: {e}', sub='cve')
	return set()


def get_kev_sha():
	"""Return the git blob SHA-1 of the local KEV catalog (cache, else bundle), or None.

	Comparable to the ``sha`` the GitHub contents API returns for the mirror on main.
	"""
	ensure_kev_cache()
	for path in (_cache_path(), BUNDLED_KEV_PATH):
		try:
			data = path.read_bytes()
		except OSError:
			continue
		return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()
	return None


def refresh_kev():
	"""Download the KEV mirror from GitHub, update the bundled mirror, and re-copy it to
	the cache. Called by ``secator update``.

	Fail-safe: on offline mode or any download error the existing files are kept and the
	current set is returned (never raises).

	Returns:
		tuple[set[str], str]: The resulting CVE-ID set, and the refresh error ('' when the
			catalog was refreshed).
	"""
	global _KEV_CVE_IDS
	from secator.utils import debug
	if CONFIG.offline_mode:
		return get_kev_cve_ids(), 'offline mode'
	import requests
	try:
		resp = requests.get(KEV_URL, timeout=10)
		resp.raise_for_status()
		if not _parse_kev_cve_ids(resp.json()):
			raise ValueError('empty or malformed KEV feed')
		blob = resp.content  # kept byte-identical to the mirror, so get_kev_sha() matches it
	except Exception as e:
		debug(f'KEV refresh download failed, keeping existing catalog: {e}', sub='cve')
		if isinstance(e, (requests.ConnectionError, requests.Timeout)):
			from secator.installer import warn_github_unreachable
			warn_github_unreachable()
		return get_kev_cve_ids(), str(e) or type(e).__name__

	# Update the bundled mirror (best-effort — may be read-only in site-packages) and the
	# cache (always writable; it's what reads use).
	from secator.data_files import atomic_write_bytes
	for target in (BUNDLED_KEV_PATH, _cache_path()):
		try:
			atomic_write_bytes(target, blob)
		except OSError as e:
			debug(f'KEV refresh could not write {target}: {e}', sub='cve')

	_KEV_CVE_IDS = None  # bust the in-process memo so get_kev_cve_ids() re-loads
	return get_kev_cve_ids(), ''

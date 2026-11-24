"""Readable names for CVE ids, from the vulnamer dataset.

Many tools report a vulnerability with its bare CVE id as the name (``CVE-2020-1350``).
The vulnamer project (https://github.com/freelabz/vulnamer, MIT) publishes a nightly
dataset that gives most CVEs a short "Product - Flaw" name, plus the community name for
the few that have one (``SIGRed``, ``Log4Shell``). Published names never change, so they
are safe to use in a finding's ``name`` (which is part of its dedup key).

The dataset ships with the package as a sorted TSV (``secator/data/cve_names.tsv``), kept
current by a nightly workflow, like the CISA KEV mirror: an install with no internet access
still names CVEs, with the data of its release. ``secator update`` (or ``secator update
--data-only``) downloads the latest dataset and rewrites the bundled file, or writes it to
the cache dir (``CONFIG.dirs.cves``) when the package dir is read-only. There is no
automatic download at run time.

Lookups read the larger of the bundled and cached files: published names are append-only,
so the larger file is the newer one. The TSV is memory-mapped on first use and searched
with a binary search, so it is never loaded into the Python heap (~28 MB for ~400k CVEs).

Naming rule: ``"<public_name> - <name>"`` when the CVE has a community name (e.g.
``Log4Shell - Apache Log4j2 Remote Code Execution``), otherwise the descriptive name
(``name``). See ``get_cve_name``.

Part of the dataset is derived from GitHub Security Advisories, licensed CC-BY-4.0
(see the NOTICE file).
"""
import gzip
import io
import json
import mmap
import os
import re
import time
from pathlib import Path

from secator.config import CONFIG

CVE_NAMES_FILENAME = 'cve_names.tsv'

# Dataset bundled with the package (refreshed nightly on the main branch).
BUNDLED_CVE_NAMES_PATH = Path(os.path.dirname(__file__)) / 'data' / CVE_NAMES_FILENAME

# A full dataset names ~400k CVEs. Refuse anything far smaller: a truncated or wrong
# download must never replace a good file.
MIN_ROWS = 100_000

_WHITESPACE = re.compile(r'\s+')

# Lazily-opened (file, mmap) pair. ``None`` means "not opened yet"; ``False`` means
# "unavailable": not retried per finding, only every ``RETRY_SECONDS`` (so a long-running
# process picks up a file written by ``secator update`` later on).
_INDEX = None
_INDEX_FAILED_AT = 0.0
RETRY_SECONDS = 300


def _candidate_paths():
	"""Files the dataset can be read from or written to, in write-preference order.

	``cve_names.path`` when set (the only file used), else the bundled file then the cache.
	"""
	path = CONFIG.cve_names.path
	if path:
		return [Path(path).expanduser()]
	return [BUNDLED_CVE_NAMES_PATH, Path(CONFIG.dirs.cves) / CVE_NAMES_FILENAME]


def cve_names_path():
	"""The CVE names TSV to read: the largest existing candidate (names are append-only, so
	the larger file is the newer one; the bundled file wins a tie). Falls back to the first
	candidate when none exists.
	"""
	best, best_size = None, -1
	for path in _candidate_paths():
		try:
			size = path.stat().st_size
		except OSError:
			continue
		if size > best_size:
			best, best_size = path, size
	return best or _candidate_paths()[0]


def _clean(value):
	"""Collapse whitespace (tabs and newlines included) so a value fits in one TSV cell."""
	return _WHITESPACE.sub(' ', str(value or '')).strip()


def _open_index():
	"""Memory-map the TSV, or return False when it is missing or unreadable."""
	from secator.utils import debug
	path = cve_names_path()
	try:
		f = open(path, 'rb')
	except OSError as e:
		debug(f'CVE names unavailable ({path}): {e}', sub='cve')
		return False
	try:
		return f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	except (OSError, ValueError) as e:  # ValueError: empty file
		f.close()
		debug(f'CVE names unavailable ({path}): {e}', sub='cve')
		return False


def _get_index():
	global _INDEX, _INDEX_FAILED_AT
	if _INDEX is False and time.monotonic() - _INDEX_FAILED_AT >= RETRY_SECONDS:
		_INDEX = None
	if _INDEX is None:
		_INDEX = _open_index()
		if _INDEX is False:
			_INDEX_FAILED_AT = time.monotonic()
	return _INDEX


def reset():
	"""Close the memory-mapped file, so the next lookup re-opens it (after a refresh)."""
	global _INDEX
	if _INDEX:
		f, mm = _INDEX
		try:
			mm.close()
		finally:
			f.close()
	_INDEX = None


def _find_line(mm, key):
	"""Binary search the sorted TSV for the line whose first cell is ``key``.

	``[lo, hi)`` is a byte range that always starts at a line start. Each step reads the
	line holding the middle byte and keeps the half that can still contain ``key``.
	"""
	lo, hi = 0, len(mm)
	while lo < hi:
		mid = (lo + hi) // 2
		newline = mm.rfind(b'\n', lo, mid)
		start = newline + 1 if newline != -1 else lo  # start of the line holding mid
		end = mm.find(b'\n', start)
		if end == -1:
			end = len(mm)
		line = mm[start:end]
		cell = line.split(b'\t', 1)[0]
		if cell == key:
			return line
		if cell < key:
			lo = end + 1
		else:
			hi = start
	return None


def lookup(cve_id):
	"""Return the dataset entry for a CVE id, or None.

	Args:
		cve_id (str): CVE id, any case (``cve-2020-1350``).

	Returns:
		dict | None: ``{'name': str, 'public_name': str}`` (either may be empty), or None when
			the CVE is not listed or the dataset is unavailable.
	"""
	if not cve_id:
		return None
	index = _get_index()
	if not index:
		return None
	key = cve_id.strip().upper().encode('ascii', 'ignore')
	if not key.startswith(b'CVE-'):
		return None
	line = _find_line(index[1], key)
	if line is None:
		return None
	cells = [cell.strip() for cell in line.rstrip(b'\r').decode('utf-8', 'replace').split('\t')]
	cells += [''] * (3 - len(cells))
	return {'name': cells[1], 'public_name': cells[2]}


def get_cve_name(cve_id):
	"""Return the readable name for a CVE id, or '' when there is none.

	The descriptive "Product - Flaw" name, prefixed with the community name when the dataset
	has one (e.g. ``SIGRed - Microsoft Windows DNS Server Remote Code Execution``): the
	community name is what people search for, the rest says what is affected.

	Args:
		cve_id (str): CVE id, any case.

	Returns:
		str: The name, or '' when the CVE is not listed or the dataset is unavailable.
	"""
	entry = lookup(cve_id)
	if not entry:
		return ''
	public_name, name = entry['public_name'], entry['name']
	if not public_name:
		return name
	if not name or public_name.lower() in name.lower():
		return name or public_name
	return f'{public_name} - {name}'


def build_tsv(data):
	"""Convert a vulnamer names dataset (gzipped JSON lines) to sorted TSV bytes.

	Each output line is ``<CVE id>\\t<name>\\t<public_name>``, sorted by CVE id (bytewise),
	which is what ``lookup`` binary-searches.

	Args:
		data (bytes): The ``vuln_names.min.jsonl.gz`` content (``vuln_names.jsonl.gz`` works too).

	Returns:
		tuple[bytes, int]: The TSV content and its number of rows.

	Raises:
		ValueError: The dataset is malformed or has fewer than ``MIN_ROWS`` named CVEs.
	"""
	rows = {}
	with gzip.open(io.BytesIO(data), 'rt', encoding='utf-8') as lines:
		for raw in lines:
			if not raw.strip():
				continue
			entry = json.loads(raw)
			cve_id = _clean(entry.get('id')).upper()
			name, public_name = _clean(entry.get('name')), _clean(entry.get('public_name'))
			if not cve_id.startswith('CVE-') or not (name or public_name):
				continue
			rows[cve_id] = f'{cve_id}\t{name}\t{public_name}\n'
	if len(rows) < MIN_ROWS:
		raise ValueError(f'CVE names dataset has {len(rows)} named CVEs, expected at least {MIN_ROWS}')
	tsv = ''.join(rows[cve_id] for cve_id in sorted(rows)).encode('utf-8')
	return tsv, len(rows)


def count():
	"""Number of CVEs in the local dataset (0 when unavailable). Reads the file in chunks."""
	try:
		with open(cve_names_path(), 'rb') as f:
			return sum(chunk.count(b'\n') for chunk in iter(lambda: f.read(1 << 20), b''))
	except OSError:
		return 0


def refresh_cve_names():
	"""Download the dataset, convert it to the sorted TSV and replace the local file.

	Writes the bundled file, or the cache file when the package dir is not writable.
	Called by ``secator update``. Fail-safe: in offline mode, or when the download or the
	validation fails, the existing files are kept and nothing raises.

	Returns:
		tuple[int, str]: Number of CVEs in the local dataset after the refresh (0 when
			unavailable), and the refresh error ('' when the file was refreshed).
	"""
	from secator.data_files import atomic_write_bytes, download_bytes
	from secator.utils import debug
	if CONFIG.offline_mode:
		return count(), 'offline mode'
	error = ''
	try:
		tsv, _ = build_tsv(download_bytes(CONFIG.cve_names.url, timeout=60))
		for target in _candidate_paths():
			try:
				atomic_write_bytes(target, tsv)
				break
			except OSError as e:  # read-only package dir: fall back to the cache
				debug(f'CVE names refresh could not write {target}: {e}', sub='cve')
		else:
			raise OSError('no writable location for the CVE names dataset')
	except Exception as e:
		error = str(e) or type(e).__name__
		debug(f'CVE names refresh failed, keeping the existing file: {error}', sub='cve')
	reset()
	return count(), error

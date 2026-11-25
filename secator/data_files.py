"""Small helpers for the downloadable data files secator keeps in its cache dirs.

Shared by the CISA KEV catalog (``secator.kev``) and the CVE names dataset
(``secator.cve_names``): both are refreshed by ``secator update`` and written atomically,
so a reader in another process never sees a half-written file.
"""
import os
import tempfile
from pathlib import Path


def download_bytes(url, timeout=30, retries=3):
	"""Download ``url`` and return the response body.

	Args:
		url (str): URL to fetch.
		timeout (int): Per-attempt timeout, in seconds.
		retries (int): Number of attempts before giving up.

	Returns:
		bytes: The response body.

	Raises:
		Exception: The last download error, once every attempt failed.
	"""
	import requests
	error = None
	for _ in range(max(retries, 1)):
		try:
			resp = requests.get(url, timeout=timeout)
			resp.raise_for_status()
			return resp.content
		except Exception as e:
			error = e
	raise error


def atomic_write_bytes(path, data):
	"""Write ``data`` to ``path`` through a temp file in the same dir and ``os.replace``.

	Readers see either the old file or the new one, never a partial write. On any failure
	the temp file is removed and the original file is left untouched.

	Args:
		path (str | Path): Destination file. Its parent dir is created if needed.
		data (bytes | callable): The bytes to write, or a callable taking the open binary
			file object and writing to it (to stream large files).
	"""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f'.{path.name}-', suffix='.tmp')
	try:
		with os.fdopen(fd, 'wb') as f:
			if callable(data):
				data(f)
			else:
				f.write(data)
			f.flush()
			os.fsync(f.fileno())
		os.chmod(tmp, 0o644)  # mkstemp creates 0600; data files are read by other users (e.g. in images)
		os.replace(tmp, path)
	except BaseException:
		try:
			os.unlink(tmp)
		except OSError:
			pass
		raise

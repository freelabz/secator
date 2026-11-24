import requests as requests_lib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_STATUS_FORCELIST = (408, 429, 500, 502, 503, 504)


class _Retry(Retry):
	"""urllib3 Retry that can also retry a POST, on the statuses in `retry_post_on` only.

	A POST (create) is not idempotent: replaying one the server already handled can create a
	duplicate. Only statuses meaning the request never reached a backend (e.g. 503 from a
	gateway) are safe to list in `retry_post_on`.
	"""

	def __init__(self, *args, retry_post_on=(), **kwargs):
		super().__init__(*args, **kwargs)
		self.retry_post_on = tuple(retry_post_on)

	def new(self, **kw):
		# Retry.new() rebuilds the object from its own init params: carry ours over.
		retry = super().new(**kw)
		retry.retry_post_on = self.retry_post_on
		return retry

	def is_retry(self, method, status_code, has_retry_after=False):
		if self.retry_post_on and method.upper() == 'POST':
			return bool(self.total) and status_code in self.retry_post_on
		return super().is_retry(method, status_code, has_retry_after)


def get_session(
		retries=3,
		backoff=1,
		status_forcelist=DEFAULT_STATUS_FORCELIST,
		retry_post_on=(),
		retry_other_errors=True,
		raise_on_status=True,
		respect_retry_after=True):
	"""HTTP session retrying transient failures.

	Called with no arguments, it builds the default shared session (3 retries, backoff 1s,
	statuses DEFAULT_STATUS_FORCELIST, urllib3's default idempotent methods).

	In every case, connections that could not be established (refused, connect timeout, DNS
	failure) are retried for every method (the request was never sent), and read errors (read
	timeout, connection dropped after sending) for idempotent methods only.

	Args:
		retries (int): Max number of retries (negative values count as 0; 0 disables retries).
		backoff (float): Backoff factor (s): the first retry is immediate, retry N waits backoff * 2^(N-1).
		status_forcelist (tuple): HTTP statuses retried for idempotent methods.
		retry_post_on (tuple): HTTP statuses a POST is also retried on (default: none).
		retry_other_errors (bool): Retry other errors (TLS failure, proxy tunnel error) for every
			method. Set to False when they may have happened after the request was sent.
		raise_on_status (bool): Raise a RetryError when retries are exhausted on a status, instead
			of returning the last error response.
		respect_retry_after (bool): Honor the Retry-After header. Set to False to keep waits
			bounded by the backoff settings.
	"""
	retry = _Retry(
		total=max(0, retries),
		other=None if retry_other_errors else 0,
		backoff_factor=backoff,
		status_forcelist=list(status_forcelist),
		retry_post_on=retry_post_on,
		raise_on_status=raise_on_status,
		respect_retry_after_header=respect_retry_after,
	)
	session = requests_lib.Session()
	session.mount('http://', HTTPAdapter(max_retries=retry))
	session.mount('https://', HTTPAdapter(max_retries=retry))
	return session


def get_api_session(retries=3, backoff=1):
	"""HTTP session for the api addon (driver hooks and query backend): retries only what is safe to repeat.

	- Gateway errors (HTTP 502/503/504: a proxy in front of the API answered) for idempotent
	  methods, HTTP 503 only for POST: creates are not deduped by the API, and on a 502 or 504
	  the backend may already have processed the request.
	- Connections that could not be established, for every method; read errors (read timeout,
	  connection dropped after sending) for idempotent methods only.
	- Never any other error (TLS failure, proxy tunnel error): it may have happened after the
	  request was sent, and retrying a certificate error cannot help.
	- When retries are exhausted the last error response is returned, for the caller to raise
	  with its detail; waits stay bounded by the backoff settings (Retry-After is ignored).
	"""
	return get_session(
		retries=retries,
		backoff=backoff,
		status_forcelist=(502, 503, 504),
		retry_post_on=(503,),
		retry_other_errors=False,
		raise_on_status=False,
		respect_retry_after=False,
	)


requests = get_session()
requests.RequestException = requests_lib.RequestException
requests.codes = requests_lib.codes

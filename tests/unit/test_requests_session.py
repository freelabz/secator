"""Unit tests for the shared HTTP session factory (secator.requests) and the retry policy of the
api driver hooks and api query backend built with it."""
import http.server
import threading
import unittest
from unittest.mock import patch

import requests
from urllib3.util.retry import Retry

from secator.hooks import api
from secator.query.api import ApiBackend
from secator.requests import DEFAULT_STATUS_FORCELIST, get_api_session, get_session


class TestDefaultSession(unittest.TestCase):
	"""get_session() with no arguments keeps the shared session's historical behaviour."""

	ATTRS = ('total', 'connect', 'read', 'redirect', 'status', 'other', 'allowed_methods', 'status_forcelist',
		'backoff_factor', 'backoff_max', 'raise_on_redirect', 'raise_on_status', 'respect_retry_after_header',
		'remove_headers_on_redirect')

	def _assert_default(self, session):
		expected = Retry(total=3, backoff_factor=1, status_forcelist=[408, 429, 500, 502, 503, 504])
		for scheme in ('http://x', 'https://x'):
			retry = session.get_adapter(scheme).max_retries
			for attr in self.ATTRS:
				self.assertEqual(getattr(retry, attr), getattr(expected, attr), attr)
			for method in ('GET', 'PUT', 'POST'):
				for status in (408, 429, 500, 502, 503, 504, 404):
					self.assertEqual(retry.is_retry(method, status), expected.is_retry(method, status), (method, status))

	def test_no_args_matches_previous_configuration(self):
		self.assertEqual(DEFAULT_STATUS_FORCELIST, (408, 429, 500, 502, 503, 504))
		self._assert_default(get_session())

	def test_shared_module_session_is_unchanged(self):
		from secator.requests import requests as shared
		self._assert_default(shared)
		self.assertIs(shared.RequestException, requests.RequestException)


class _Handler(http.server.BaseHTTPRequestHandler):
	"""Answers each request with the next status of `server.statuses` (then 200 with a JSON body)."""

	def _answer(self):
		self.server.calls.append(self.command)
		status = self.server.statuses.pop(0) if self.server.statuses else 200
		body = b'{"id": "ok"}' if status == 200 else b'<html>gateway error</html>'
		self.send_response(status)
		self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	do_GET = do_PUT = do_POST = do_DELETE = _answer

	def log_message(self, *args):
		pass


class _ServerTestCase(unittest.TestCase):
	"""Runs a local HTTP server answering with `self.server.statuses`."""

	def setUp(self):
		self.server = http.server.HTTPServer(('127.0.0.1', 0), _Handler)
		self.server.statuses, self.server.calls = [], []
		threading.Thread(target=self.server.serve_forever, daemon=True).start()
		self.addCleanup(self.server.server_close)
		self.addCleanup(self.server.shutdown)
		self.url = f'http://127.0.0.1:{self.server.server_port}'

	def _patch(self, obj, name, value):
		patcher = patch.object(obj, name, value)
		patcher.start()
		self.addCleanup(patcher.stop)


class TestApiDriverRetries(_ServerTestCase):
	"""The api driver hooks retry through the real urllib3 adapter, against a local HTTP server."""

	def setUp(self):
		super().setUp()
		self._patch(api, 'API_URL', self.url)
		self._patch(api, '_session', get_api_session(retries=3, backoff=0))

	def _call(self, method, statuses):
		self.server.statuses = list(statuses)
		return api._make_request(method, 'runners', {'name': 'httpx'} if method in ('POST', 'PUT') else None)

	def test_put_retries_gateway_errors_then_succeeds(self):
		self.assertEqual(self._call('PUT', [502, 503, 504]), {'id': 'ok'})
		self.assertEqual(len(self.server.calls), 4)

	def test_gives_up_after_configured_retries_with_http_error(self):
		with self.assertRaises(requests.HTTPError) as cm:
			self._call('GET', [502] * 5)
		self.assertEqual(cm.exception.response.status_code, 502)
		self.assertIn('HTTP 502', str(cm.exception))
		self.assertEqual(len(self.server.calls), 4)  # 1 attempt + 3 retries

	def test_retries_zero_disables_retry(self):
		self._patch(api, '_session', get_api_session(retries=0, backoff=0))
		with self.assertRaises(requests.HTTPError):
			self._call('PUT', [503])
		self.assertEqual(len(self.server.calls), 1)

	def test_other_server_errors_are_not_retried(self):
		with self.assertRaises(requests.HTTPError) as cm:
			self._call('PUT', [500])
		self.assertEqual(cm.exception.response.status_code, 500)
		self.assertEqual(len(self.server.calls), 1)

	def test_post_retries_503(self):
		self.assertEqual(self._call('POST', [503, 503]), {'id': 'ok'})
		self.assertEqual(self.server.calls, ['POST'] * 3)

	def test_post_does_not_retry_502_or_504(self):
		for status in (502, 504):
			self.server.calls.clear()
			with self.assertRaises(requests.HTTPError):
				self._call('POST', [status])
			self.assertEqual(len(self.server.calls), 1, status)


class TestApiRetryPolicy(unittest.TestCase):
	"""Which errors the policy retries (urllib3 Retry.increment raises when it does not)."""

	def setUp(self):
		self.retry = get_api_session(retries=3, backoff=0).get_adapter('https://x').max_retries

	def test_policy_comes_from_arguments(self):
		retry = get_api_session(retries=5, backoff=2.5).get_adapter('https://x').max_retries
		self.assertEqual((retry.total, retry.backoff_factor, retry.other), (5, 2.5, 0))
		self.assertFalse(retry.raise_on_status)
		self.assertFalse(retry.respect_retry_after_header)
		self.assertEqual(get_api_session(retries=-1).get_adapter('https://x').max_retries.total, 0)

	def test_sessions_use_the_configured_policy(self):
		from secator.config import CONFIG
		from secator.query import api as query_api
		for session in (api._session, query_api._session):
			retry = session.get_adapter('https://x').max_retries
			self.assertEqual((retry.total, retry.backoff_factor), (CONFIG.addons.api.retries, CONFIG.addons.api.retry_backoff))
			self.assertEqual(retry.retry_post_on, (503,))

	def test_post_retry_statuses_survive_increment(self):
		retry = self.retry.increment('POST', '/runners', error=__import__('urllib3').exceptions.ConnectTimeoutError('t'))
		self.assertEqual(retry.retry_post_on, (503,))
		self.assertTrue(retry.is_retry('POST', 503))

	def test_connection_not_established_is_retried_for_post(self):
		from urllib3.exceptions import NewConnectionError, ConnectTimeoutError, ProxyError
		refused = NewConnectionError(None, 'Connection refused')
		for error in (refused, ConnectTimeoutError('connect timeout'), ProxyError('proxy refused', refused)):
			self.assertEqual(self.retry.increment('POST', '/runners', error=error).total, 2, error)

	def test_read_errors_are_retried_for_idempotent_methods_only(self):
		from urllib3.exceptions import MaxRetryError, ProtocolError, ReadTimeoutError
		errors = (ReadTimeoutError(None, '/runners', 'read timeout'), ProtocolError('connection reset'))
		for error in errors:
			for method in ('PUT', 'GET'):
				self.assertEqual(self.retry.increment(method, '/runners', error=error).total, 2, (method, error))
			with self.assertRaises((MaxRetryError, ReadTimeoutError, ProtocolError)):
				self.retry.increment('POST', '/runners', error=error)

	def test_tls_errors_are_never_retried(self):
		import ssl
		from urllib3.exceptions import MaxRetryError, SSLError
		for method in ('POST', 'PUT', 'GET'):
			with self.assertRaises(MaxRetryError):
				self.retry.increment(method, '/runners', error=SSLError(ssl.SSLEOFError()))

	def test_post_status_retry_is_503_only(self):
		self.assertTrue(self.retry.is_retry('POST', 503))
		self.assertFalse(self.retry.is_retry('POST', 502))
		self.assertFalse(self.retry.is_retry('POST', 504))
		self.assertTrue(self.retry.is_retry('PUT', 502))
		self.assertFalse(self.retry.is_retry('PUT', 500))


class TestApiQueryBackendRetries(_ServerTestCase):
	"""The api query backend retries like the driver hooks, against a local HTTP server."""

	def setUp(self):
		super().setUp()
		from secator.query import api as query_api
		self._patch(query_api, '_session', get_api_session(retries=3, backoff=0))
		self.backend = ApiBackend(workspace_id='ws1')
		self.backend.api_url = self.url
		self.backend.api_key = 'k'

	def _call(self, method, statuses):
		self.server.statuses = list(statuses)
		return self.backend._make_request(method, 'search', {'q': 1} if method == 'POST' else None)

	def test_get_retries_503(self):
		self.assertEqual(self._call('GET', [503, 503]), {'id': 'ok'})
		self.assertEqual(self.server.calls, ['GET'] * 3)

	def test_post_retries_503_only(self):
		self.assertEqual(self._call('POST', [503]), {'id': 'ok'})
		self.assertEqual(self.server.calls, ['POST'] * 2)
		for status in (500, 502, 504):
			self.server.calls.clear()
			with self.assertRaises(requests.HTTPError):
				self._call('POST', [status])
			self.assertEqual(len(self.server.calls), 1, status)

	def test_exhausted_retries_raise_http_error(self):
		with self.assertRaises(requests.HTTPError):
			self._call('GET', [503] * 5)
		self.assertEqual(len(self.server.calls), 4)  # 1 attempt + 3 retries


if __name__ == '__main__':
	unittest.main()

"""Unit tests for the api driver hooks (secator.hooks.api)."""
import http.server
import threading
import unittest
import uuid
from unittest.mock import MagicMock, patch

import requests

from secator.hooks import api


class _Cfg:
	type = 'task'
	name = 'httpx'


class _FakeRunner:
	def __init__(self, context, chunk=None):
		self.config = _Cfg()
		self.context = context
		self.chunk = chunk
		self.unique_name = 'httpx'
		self.status = 'RUNNING'
		self.last_updated_db = None

	def toDict(self):
		return {'status': self.status, 'chunk': self.chunk, 'context': dict(self.context)}


def _resp(body):
	r = MagicMock()
	r.status_code = 200
	r.ok = True
	r.text = '{}'
	r.json.return_value = body
	return r


def _raw_resp(status_code, text, json_body=None):
	"""Response whose body is `text`; .json() fails unless `json_body` is given."""
	import requests
	r = MagicMock()
	r.status_code = status_code
	r.ok = status_code < 400
	r.text = text
	if json_body is None:
		r.json.side_effect = requests.exceptions.JSONDecodeError('Expecting value', text, 0)
	else:
		r.json.return_value = json_body
	return r


@patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
class TestApiRunnerId(unittest.TestCase):

	def test_run_scope_uuid_id_is_created_not_updated(self, _ws):
		"""The runner constructor mints a uuid {type}_id; the first update must POST (create), not PUT runner/<uuid>."""
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with patch.object(api._session, 'request', return_value=_resp({'id': 'b' * 24})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'POST')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runners'))
		self.assertEqual(runner.context['task_id'], 'b' * 24)
		# Later updates hit the created runner.
		with patch.object(api._session, 'request', return_value=_resp({})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'PUT')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runner/' + 'b' * 24))

	def test_run_scope_uuid_chunk_id_is_created(self, _ws):
		runner = _FakeRunner({'task_id': 'c' * 24, 'task_chunk_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24}, chunk=1)
		with patch.object(api._session, 'request', return_value=_resp({'id': 'd' * 24})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'POST')
		self.assertEqual(runner.context['task_chunk_id'], 'd' * 24)
		self.assertEqual(runner.context['task_id'], 'c' * 24)

	def test_existing_object_id_is_updated(self, _ws):
		"""An ObjectId {type}_id (a runner that already exists remotely) is updated in place."""
		runner = _FakeRunner({'task_id': 'c' * 24, 'workspace_id': 'a' * 24})
		with patch.object(api._session, 'request', return_value=_resp({})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'PUT')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runner/' + 'c' * 24))
		self.assertEqual(runner.context['task_id'], 'c' * 24)


class TestApiMakeRequestErrors(unittest.TestCase):
	"""An error response raises requests.HTTPError naming the request, never a bare JSON decode error."""

	def _call(self, resp, method='POST', endpoint='runners'):
		with patch.object(api._session, 'request', return_value=resp):
			return api._make_request(method, endpoint, {'name': 'httpx'})

	def test_non_json_error_page_raises_http_error(self):
		import requests
		page = '<html>\n<head><title>502 Bad Gateway</title></head></html>'
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(502, page))
		msg = str(cm.exception)
		self.assertIn('POST runners', msg)
		self.assertIn('HTTP 502', msg)
		self.assertIn('<html> <head><title>502 Bad Gateway</title>', msg)
		self.assertEqual(cm.exception.response.status_code, 502)

	def test_json_error_detail_is_in_the_message(self):
		import requests
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(403, '{"detail": "Access denied"}', json_body={'detail': 'Access denied'}))
		self.assertIn('HTTP 403: Access denied', str(cm.exception))

	def test_long_body_is_truncated(self):
		import requests
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(500, 'x' * 5000), method='GET')
		self.assertLess(len(str(cm.exception)), 300)

	def test_empty_success_body_returns_none(self):
		self.assertIsNone(self._call(_raw_resp(204, ''), method='DELETE'))


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


class TestApiRetries(unittest.TestCase):
	"""Retries go through the real urllib3 adapter, against a local HTTP server."""

	def setUp(self):
		self.server = http.server.HTTPServer(('127.0.0.1', 0), _Handler)
		self.server.statuses, self.server.calls = [], []
		threading.Thread(target=self.server.serve_forever, daemon=True).start()
		self.addCleanup(self.server.server_close)
		self.addCleanup(self.server.shutdown)
		self._patch(api, 'API_URL', f'http://127.0.0.1:{self.server.server_port}')
		self._patch(api, '_session', api._build_session(retries=3, backoff=0))

	def _patch(self, obj, name, value):
		patcher = patch.object(obj, name, value)
		patcher.start()
		self.addCleanup(patcher.stop)

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
		self._patch(api, '_session', api._build_session(retries=0, backoff=0))
		with self.assertRaises(requests.HTTPError):
			self._call('PUT', [503])
		self.assertEqual(len(self.server.calls), 1)

	def test_client_errors_are_not_retried(self):
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

	def test_non_json_success_body_raises_clear_error(self):
		with patch.object(api._session, 'request', return_value=_raw_resp(200, '<html>ok</html>')):
			with self.assertRaises(requests.exceptions.RequestException) as cm:
				api._make_request('GET', 'runners')
		self.assertIn('GET runners returned HTTP 200 with a non-JSON body: <html>ok</html>', str(cm.exception))


class TestApiRetryPolicy(unittest.TestCase):
	"""Which errors the policy retries (urllib3 Retry.increment raises when it does not)."""

	def setUp(self):
		self.retry = api._build_session(retries=3, backoff=0).get_adapter('https://x').max_retries

	def test_policy_comes_from_config(self):
		retry = api._build_session(retries=5, backoff=2.5).get_adapter('https://x').max_retries
		self.assertEqual((retry.total, retry.backoff_factor, retry.read), (5, 2.5, 0))
		session = api._build_session()
		self.assertIs(session.get_adapter('http://x'), session.get_adapter('https://x'))

	def test_connection_not_established_is_retried_for_post(self):
		from urllib3.exceptions import NewConnectionError, ConnectTimeoutError, ProxyError
		refused = NewConnectionError(None, 'Connection refused')
		for error in (refused, ConnectTimeoutError('connect timeout'), ProxyError('proxy refused', refused)):
			self.assertEqual(self.retry.increment('POST', '/runners', error=error).total, 2, error)

	def test_read_errors_are_never_retried(self):
		from urllib3.exceptions import MaxRetryError, ProtocolError, ReadTimeoutError
		for method in ('POST', 'PUT', 'GET'):
			for error in (ReadTimeoutError(None, '/runners', 'read timeout'), ProtocolError('connection dropped')):
				with self.assertRaises((MaxRetryError, ReadTimeoutError, ProtocolError)):
					self.retry.increment(method, '/runners', error=error)

	def test_post_status_retry_is_503_only(self):
		self.assertTrue(self.retry.is_retry('POST', 503))
		self.assertFalse(self.retry.is_retry('POST', 502))
		self.assertFalse(self.retry.is_retry('POST', 504))
		self.assertTrue(self.retry.is_retry('PUT', 502))
		self.assertFalse(self.retry.is_retry('PUT', 500))


if __name__ == '__main__':
	unittest.main()

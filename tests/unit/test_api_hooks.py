"""Unit tests for the api driver hooks (secator.hooks.api)."""
import unittest
import uuid
from unittest.mock import MagicMock, patch

import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError, ProxyError

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
	r.json.return_value = body
	return r


@patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
class TestApiRunnerId(unittest.TestCase):

	def test_run_scope_uuid_id_is_created_not_updated(self, _ws):
		"""The runner constructor mints a uuid {type}_id; the first update must POST (create), not PUT runner/<uuid>."""
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with patch.object(api.requests, 'request', return_value=_resp({'id': 'b' * 24})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'POST')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runners'))
		self.assertEqual(runner.context['task_id'], 'b' * 24)
		# Later updates hit the created runner.
		with patch.object(api.requests, 'request', return_value=_resp({})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'PUT')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runner/' + 'b' * 24))

	def test_run_scope_uuid_chunk_id_is_created(self, _ws):
		runner = _FakeRunner({'task_id': 'c' * 24, 'task_chunk_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24}, chunk=1)
		with patch.object(api.requests, 'request', return_value=_resp({'id': 'd' * 24})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'POST')
		self.assertEqual(runner.context['task_chunk_id'], 'd' * 24)
		self.assertEqual(runner.context['task_id'], 'c' * 24)

	def test_existing_object_id_is_updated(self, _ws):
		"""An ObjectId {type}_id (a runner that already exists remotely) is updated in place."""
		runner = _FakeRunner({'task_id': 'c' * 24, 'workspace_id': 'a' * 24})
		with patch.object(api.requests, 'request', return_value=_resp({})) as req:
			api.update_runner(runner)
		self.assertEqual(req.call_args.kwargs['method'], 'PUT')
		self.assertTrue(req.call_args.kwargs['url'].endswith('/runner/' + 'c' * 24))
		self.assertEqual(runner.context['task_id'], 'c' * 24)


def _http(status, body=b'', content_type='application/json'):
	"""A real requests.Response with the given status and raw body."""
	r = requests.Response()
	r.status_code = status
	r._content = body
	r.headers['Content-Type'] = content_type
	r.url = 'https://api.example/x'
	return r


_GATEWAY_503 = b'<!DOCTYPE html><html><body>upstream connect error</body></html>'


def _refused():
	"""ConnectionError as raised when the TCP connect itself fails (nothing sent)."""
	reason = NewConnectionError(None, 'Failed to establish a new connection: [Errno 111] Connection refused')
	return requests.exceptions.ConnectionError(MaxRetryError(None, '/x', reason=reason))


@patch.object(api.time, 'sleep')
@patch.object(api, 'API_RETRY_BACKOFF', 0.5)
@patch.object(api, 'API_RETRIES', 3)
class TestApiTransientErrors(unittest.TestCase):

	def test_put_retries_gateway_errors_then_succeeds(self, sleep):
		responses = [_http(503, _GATEWAY_503, 'text/html'), _http(502, b'bad gateway', 'text/html'), _http(200, b'{"ok": 1}')]
		with patch.object(api.requests, 'request', side_effect=responses) as req:
			self.assertEqual(api._make_request('PUT', 'runner/x', {'a': 1}), {'ok': 1})
		self.assertEqual(req.call_count, 3)
		self.assertEqual([c.args[0] for c in sleep.call_args_list], [0.5, 1.0])

	def test_get_retries_connection_errors_and_timeouts(self, sleep):
		effects = [requests.exceptions.ConnectionError('reset'), requests.exceptions.ReadTimeout('slow'), _http(200, b'[]')]
		with patch.object(api.requests, 'request', side_effect=effects) as req:
			self.assertEqual(api._make_request('GET', 'workspaces'), [])
		self.assertEqual(req.call_count, 3)

	def test_gives_up_after_configured_retries_with_clear_error(self, sleep):
		with patch.object(api.requests, 'request', return_value=_http(503, _GATEWAY_503, 'text/html')) as req:
			with self.assertRaises(api.ApiResponseError) as ctx:
				api._make_request('PUT', 'runner/x', {'a': 1})
		self.assertEqual(req.call_count, 4)  # 1 try + 3 retries
		msg = str(ctx.exception)
		self.assertIn('HTTP 503', msg)
		self.assertIn('non-JSON body', msg)
		self.assertIn('upstream connect error', msg)
		self.assertEqual(ctx.exception.response.status_code, 503)

	def test_retries_zero_disables_retry(self, sleep):
		with patch.object(api, 'API_RETRIES', 0), \
				patch.object(api.requests, 'request', return_value=_http(503, _GATEWAY_503, 'text/html')) as req:
			with self.assertRaises(api.ApiResponseError):
				api._make_request('PUT', 'runner/x', {'a': 1})
		self.assertEqual(req.call_count, 1)
		sleep.assert_not_called()

	def test_non_transient_error_is_not_retried(self, sleep):
		with patch.object(api.requests, 'request', return_value=_http(404, b'{"detail": "Not found"}')) as req:
			with self.assertRaises(requests.exceptions.HTTPError):
				api._make_request('PUT', 'runner/x', {'a': 1})
		self.assertEqual(req.call_count, 1)

	def test_non_json_success_body_raises_clear_error(self, sleep):
		body = b'<html>' + b'x' * 1000 + b'</html>'
		with patch.object(api.requests, 'request', return_value=_http(200, body, 'text/html')):
			with self.assertRaises(api.ApiResponseError) as ctx:
				api._make_request('GET', 'workspaces')
		msg = str(ctx.exception)
		self.assertIn('HTTP 200', msg)
		self.assertLess(len(msg), 400)  # body is truncated

	def test_empty_body_is_none(self, sleep):
		with patch.object(api.requests, 'request', return_value=_http(200, b'')):
			self.assertIsNone(api._make_request('PUT', 'runner/x', {'a': 1}))

	# POST (create) is not deduplicated by the API: only retry when it cannot have been processed.

	def test_post_retries_503(self, sleep):
		responses = [_http(503, _GATEWAY_503, 'text/html'), _http(200, b'{"id": "abc"}')]
		with patch.object(api.requests, 'request', side_effect=responses) as req:
			self.assertEqual(api._make_request('POST', 'runners', {'a': 1}), {'id': 'abc'})
		self.assertEqual(req.call_count, 2)

	def test_post_does_not_retry_502_or_504(self, sleep):
		for status in (502, 504):
			with patch.object(api.requests, 'request', return_value=_http(status, b'gateway', 'text/html')) as req:
				with self.assertRaises(api.ApiResponseError):
					api._make_request('POST', 'runners', {'a': 1})
			self.assertEqual(req.call_count, 1, status)

	def test_post_retries_connection_never_established(self, sleep):
		effects = [_refused(), requests.exceptions.ConnectTimeout('connect timeout'), _http(200, b'{"id": "abc"}')]
		with patch.object(api.requests, 'request', side_effect=effects) as req:
			self.assertEqual(api._make_request('POST', 'findings', {'a': 1}), {'id': 'abc'})
		self.assertEqual(req.call_count, 3)

	def test_post_does_not_retry_after_request_was_sent(self, sleep):
		for exc in (requests.exceptions.ReadTimeout('slow'), requests.exceptions.ConnectionError('Connection aborted.')):
			with patch.object(api.requests, 'request', side_effect=exc) as req:
				with self.assertRaises(type(exc)):
					api._make_request('POST', 'runners', {'a': 1})
			self.assertEqual(req.call_count, 1, exc)
		sleep.assert_not_called()

	def test_put_retries_body_read_interrupted(self, sleep):
		effects = [requests.exceptions.ChunkedEncodingError('connection broken'), _http(200, b'{"ok": 1}')]
		with patch.object(api.requests, 'request', side_effect=effects) as req:
			self.assertEqual(api._make_request('PUT', 'runner/x', {'a': 1}), {'ok': 1})
		self.assertEqual(req.call_count, 2)

	def test_post_does_not_retry_body_read_interrupted(self, sleep):
		with patch.object(api.requests, 'request', side_effect=requests.exceptions.ChunkedEncodingError('broken')) as req:
			with self.assertRaises(requests.exceptions.ChunkedEncodingError):
				api._make_request('POST', 'runners', {'a': 1})
		self.assertEqual(req.call_count, 1)
		sleep.assert_not_called()

	def test_post_retries_refused_proxy_connection_only(self, sleep):
		conn = NewConnectionError(None, 'Connection refused')
		refused = requests.exceptions.ProxyError(MaxRetryError(None, 'http://x', ProxyError('proxy down', conn)))
		with patch.object(api.requests, 'request', side_effect=[refused, _http(200, b'{"id": "abc"}')]) as req:
			self.assertEqual(api._make_request('POST', 'runners', {'a': 1}), {'id': 'abc'})
		self.assertEqual(req.call_count, 2)
		other = requests.exceptions.ProxyError(MaxRetryError(None, 'http://x', ProxyError('proxy said no', OSError('x'))))
		with patch.object(api.requests, 'request', side_effect=other) as req:
			with self.assertRaises(requests.exceptions.ProxyError):
				api._make_request('POST', 'runners', {'a': 1})
		self.assertEqual(req.call_count, 1)


if __name__ == '__main__':
	unittest.main()

"""Unit tests for the api driver hooks (secator.hooks.api)."""
import unittest
import uuid
from unittest.mock import MagicMock, patch

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


if __name__ == '__main__':
	unittest.main()


def _raw_resp(status_code, text, json_body=None):
	"""Response whose body is `text`; .json() fails unless `json_body` is given."""
	r = MagicMock()
	r.status_code = status_code
	r.ok = 200 <= status_code < 400
	r.text = text
	if json_body is None:
		import requests
		r.json.side_effect = requests.exceptions.JSONDecodeError('Expecting value', text, 0)
	else:
		r.json.return_value = json_body
	return r


class TestApiMakeRequestErrors(unittest.TestCase):
	"""_make_request never surfaces a bare JSONDecodeError: it names the request."""

	def test_non_json_error_page_names_method_endpoint_status_and_body(self):
		page = '<html>\n<head><title>502 Bad Gateway</title></head>\n<body>bad gateway</body></html>'
		with patch.object(api.requests, 'request', return_value=_raw_resp(502, page)):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		msg = str(cm.exception)
		self.assertIn('POST runners', msg)
		self.assertIn('HTTP 502', msg)
		self.assertIn('non-JSON', msg)
		self.assertIn('<html> <head><title>502 Bad Gateway</title>', msg)
		self.assertEqual(cm.exception.status_code, 502)

	def test_non_json_body_on_success_status_is_an_error(self):
		with patch.object(api.requests, 'request', return_value=_raw_resp(200, 'OK')):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		self.assertIn('HTTP 200', str(cm.exception))

	def test_body_snippet_is_truncated(self):
		with patch.object(api.requests, 'request', return_value=_raw_resp(500, 'x' * 5000)):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('GET', 'workspaces')
		self.assertLess(len(str(cm.exception)), 300)
		self.assertTrue(str(cm.exception).endswith('...'))

	def test_json_error_detail_is_in_the_message(self):
		resp = _raw_resp(403, '{"detail": "Access denied"}', json_body={'detail': 'Access denied'})
		with patch.object(api.requests, 'request', return_value=resp):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		msg = str(cm.exception)
		self.assertIn('POST runners', msg)
		self.assertIn('HTTP 403', msg)
		self.assertIn('Access denied', msg)

	def test_empty_success_body_returns_none(self):
		with patch.object(api.requests, 'request', return_value=_raw_resp(204, '')):
			self.assertIsNone(api._make_request('DELETE', 'workspace/' + 'a' * 24))

	def test_api_key_is_never_in_the_error(self):
		key = patch.object(api, 'API_KEY', 'secret-key-value')
		with key, patch.object(api.requests, 'request', return_value=_raw_resp(401, 'Unauthorized')):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		self.assertNotIn('secret-key-value', str(cm.exception))

	@patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
	def test_failed_runner_create_hook_error_names_the_request(self, _ws):
		"""A failing create surfaces through update_runner as the clear error, not a decode error."""
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with patch.object(api.requests, 'request', return_value=_raw_resp(504, '<html>Gateway Timeout</html>')):
			with self.assertRaises(api.ApiRequestError) as cm:
				api.update_runner(runner)
		self.assertIn('POST runners failed (HTTP 504', str(cm.exception))


class TestApiRunnerCreateSyncVsWorker(unittest.TestCase):
	"""The client runner's create request does not depend on sync (local) vs worker mode."""

	def _create_request(self, sync):
		from secator.loader import TemplateLoader
		from secator.runners import Task
		calls = []

		def fake(method, url, data=None, headers=None, verify=None, timeout=None):
			calls.append({'method': method, 'url': url, 'headers': headers, 'data': data})
			return _resp({'id': 'b' * 24})

		ws = patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
		url = patch.object(api, 'API_URL', 'https://api.example.com/api')
		with ws, url, patch.object(api.requests, 'request', side_effect=fake):
			Task(
				TemplateLoader(input={'name': 'httpx', 'type': 'task'}),
				['example.com'],
				run_opts={'sync': sync},
				hooks=api.HOOKS,
				context={'workspace_name': 'ws', 'workspace_id': 'a' * 24, 'drivers': ['api']},
			)
		creates = [c for c in calls if c['method'] == 'POST']
		self.assertEqual(len(creates), 1)
		return creates[0]

	def test_create_request_is_identical_in_both_modes(self):
		import json
		local, worker = self._create_request(True), self._create_request(False)
		self.assertEqual(local['url'], 'https://api.example.com/api/runners')
		self.assertEqual(local['url'], worker['url'])
		self.assertEqual(local['headers'], worker['headers'])
		volatile = ('start_time', 'elapsed', 'elapsed_human')
		local_data, worker_data = json.loads(local['data']), json.loads(worker['data'])
		for data in (local_data, worker_data):
			for key in volatile:
				data.pop(key, None)
			data['context'].pop('task_id')
			data.pop('sync')
			data['run_opts'].pop('sync')
		self.assertEqual(local_data, worker_data)


@patch.object(api.time, 'sleep')
class TestApiMakeRequestRetries(unittest.TestCase):
	"""Idempotent requests are retried on gateway errors / refused connections; creates never are."""

	def test_update_is_retried_on_gateway_error(self, sleep):
		responses = [_raw_resp(503, '<html>Service Unavailable</html>'), _resp({'ok': True})]
		with patch.object(api.requests, 'request', side_effect=responses) as req:
			self.assertEqual(api._make_request('PUT', 'runner/' + 'b' * 24, {'status': 'RUNNING'}), {'ok': True})
		self.assertEqual(req.call_count, 2)
		sleep.assert_called_once_with(api.API_RETRY_BACKOFFS[0])

	def test_read_is_retried_on_connection_error_then_raises(self, sleep):
		import requests
		error = requests.exceptions.ConnectionError('connection refused')
		with patch.object(api.requests, 'request', side_effect=error) as req:
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('GET', 'workspaces')
		self.assertEqual(req.call_count, len(api.API_RETRY_BACKOFFS) + 1)
		self.assertIn('GET workspaces failed (connection error', str(cm.exception))

	def test_persistent_gateway_error_surfaces_after_retries(self, sleep):
		with patch.object(api.requests, 'request', return_value=_raw_resp(502, 'Bad Gateway')) as req:
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('GET', 'workspaces')
		self.assertEqual(req.call_count, len(api.API_RETRY_BACKOFFS) + 1)
		self.assertIn('HTTP 502', str(cm.exception))

	def test_create_is_not_retried(self, sleep):
		"""A create that reached the backend before the gateway error would be duplicated by a replay."""
		import requests
		for failure in (_raw_resp(502, 'Bad Gateway'), requests.exceptions.ConnectionError('reset')):
			with self.subTest(failure=type(failure).__name__):
				kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
				with patch.object(api.requests, 'request', **kwargs) as req:
					with self.assertRaises(api.ApiRequestError):
						api._make_request('POST', 'runners', {'name': 'httpx'})
				self.assertEqual(req.call_count, 1)
		sleep.assert_not_called()

	def test_client_errors_are_not_retried(self, sleep):
		resp = _raw_resp(404, '{"detail": "Not found"}', json_body={'detail': 'Not found'})
		with patch.object(api.requests, 'request', return_value=resp) as req:
			with self.assertRaises(api.ApiRequestError):
				api._make_request('GET', 'workspace/' + 'a' * 24)
		self.assertEqual(req.call_count, 1)


class TestApiTimeouts(unittest.TestCase):

	def test_timeout_is_explicit_and_bounded(self):
		with patch.object(api.requests, 'request', return_value=_resp({})) as req:
			api._make_request('GET', 'workspaces')
		self.assertEqual(req.call_args.kwargs['timeout'], api._request_timeout())
		for setting in (0, -1, None):
			with self.subTest(setting=setting), patch.object(api, 'API_TIMEOUT', setting):
				self.assertEqual(api._request_timeout(), (api.API_CONNECT_TIMEOUT, api.API_DEFAULT_TIMEOUT))
		with patch.object(api, 'API_TIMEOUT', 30):
			self.assertEqual(api._request_timeout(), (10, 30))

	def test_read_timeout_is_a_clear_error_and_not_retried(self):
		import requests
		slow = patch.object(api.requests, 'request', side_effect=requests.exceptions.ReadTimeout('read timed out'))
		with patch.object(api, 'API_TIMEOUT', 30), slow as req:
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('PUT', 'runner/' + 'b' * 24, {'status': 'RUNNING'})
		self.assertEqual(str(cm.exception), 'API PUT runner/' + 'b' * 24 + ' failed (no response within 30s)')
		self.assertTrue(cm.exception.delivered)
		self.assertEqual(req.call_count, 1)

	def test_connect_timeout_is_not_delivered(self):
		import requests
		down = patch.object(api.requests, 'request', side_effect=requests.exceptions.ConnectTimeout('connect'))
		with patch.object(api.time, 'sleep'), down:
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		self.assertIn('could not connect within', str(cm.exception))
		self.assertFalse(cm.exception.delivered)


@patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
class TestApiRunnerCreateNotReplayed(unittest.TestCase):
	"""A create the endpoint may have completed is never sent again by later lifecycle hooks."""

	def _posts(self, runner, failure, hooks=3):
		posts = []

		def fake(method, url, **kwargs):
			if method == 'POST':
				posts.append(url)
			if isinstance(failure, Exception):
				raise failure
			return failure

		with patch.object(api.requests, 'request', side_effect=fake), patch.object(api.time, 'sleep'):
			for _ in range(hooks):  # on_init, on_start, on_end
				try:
					api.update_runner(runner)
				except api.ApiRequestError:
					pass
		return posts

	def test_create_after_gateway_error_is_not_resent(self, _ws):
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		self.assertEqual(len(self._posts(runner, _raw_resp(504, '<html>Gateway Timeout</html>'))), 1)

	def test_create_after_read_timeout_is_not_resent(self, _ws):
		import requests
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		self.assertEqual(len(self._posts(runner, requests.exceptions.ReadTimeout('slow'))), 1)

	def test_create_never_delivered_is_tried_again(self, _ws):
		import requests
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		self.assertEqual(len(self._posts(runner, requests.exceptions.ConnectTimeout('down'))), 3)

	def test_child_with_its_own_id_still_creates(self, _ws):
		parent_id = str(uuid.uuid4())
		parent = _FakeRunner({'task_id': parent_id, 'workspace_id': 'a' * 24})
		self._posts(parent, _raw_resp(502, 'Bad Gateway'), hooks=1)
		child = _FakeRunner({**parent.context, 'task_chunk_id': str(uuid.uuid4())}, chunk=1)
		self.assertEqual(len(self._posts(child, _raw_resp(502, 'Bad Gateway'), hooks=1)), 1)


class TestApiReviewFollowups(unittest.TestCase):

	def test_truncated_body_is_a_delivered_request_error(self):
		import requests
		with patch.object(api.requests, 'request', side_effect=requests.exceptions.ChunkedEncodingError('truncated')):
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('POST', 'runners', {'name': 'httpx'})
		self.assertTrue(cm.exception.delivered)

	def test_body_read_timeout_wrapped_in_connection_error_is_not_retried(self):
		import requests
		from urllib3.exceptions import ReadTimeoutError
		wrapped = requests.exceptions.ConnectionError(ReadTimeoutError(None, None, 'read timed out'))
		with patch.object(api.time, 'sleep'), patch.object(api.requests, 'request', side_effect=wrapped) as req:
			with self.assertRaises(api.ApiRequestError) as cm:
				api._make_request('GET', 'workspaces')
		self.assertEqual(req.call_count, 1)
		self.assertIn('no response within', str(cm.exception))

	def test_empty_redirect_is_not_success(self):
		with patch.object(api.requests, 'request', return_value=_raw_resp(304, '')):
			with self.assertRaises(api.ApiRequestError):
				api._make_request('DELETE', 'workspace/' + 'a' * 24)

	def test_echoed_api_key_is_redacted(self):
		body = '{"detail": "bad token secret-key-value"}'
		resp = _raw_resp(401, body, json_body={'detail': 'bad token secret-key-value'})
		for r in (resp, _raw_resp(401, 'bad token secret-key-value')):
			key = patch.object(api, 'API_KEY', 'secret-key-value')
			with self.subTest(json=r is resp), key, patch.object(api.requests, 'request', return_value=r):
				with self.assertRaises(api.ApiRequestError) as cm:
					api._make_request('GET', 'workspaces')
			self.assertNotIn('secret-key-value', str(cm.exception))
			self.assertIn('<redacted>', str(cm.exception))

	def test_create_workspace_does_not_create_on_lookup_error(self):
		error = api.ApiRequestError('GET', 'workspaces', 403, 'Organization not found in remote API')
		lookup = patch.object(api, 'resolve_workspace', side_effect=error)
		with lookup, patch.object(api, '_make_request') as req:
			with self.assertRaises(api.ApiRequestError):
				api.create_workspace('ws')
		req.assert_not_called()


@patch.object(api, 'resolve_workspace', return_value=('a' * 24, 'ws'))
class TestApiRunnerCreateReviewFollowups(unittest.TestCase):

	def test_create_without_id_is_unconfirmed(self, _ws):
		runner = _FakeRunner({'task_id': str(uuid.uuid4()), 'workspace_id': 'a' * 24})
		with patch.object(api.requests, 'request', return_value=_raw_resp(201, '')) as req:
			with self.assertRaises(api.ApiRequestError):
				api.update_runner(runner)
			api.update_runner(runner)
		self.assertEqual(req.call_count, 1)

	def test_chunk_without_id_gets_a_stable_local_id(self, _ws):
		runner = _FakeRunner({'task_id': 'c' * 24, 'workspace_id': 'a' * 24}, chunk=1)
		with patch.object(api.requests, 'request', return_value=_raw_resp(504, 'Gateway Timeout')) as req:
			for _ in range(3):
				try:
					api.update_runner(runner)
				except api.ApiRequestError:
					pass
		self.assertEqual(req.call_count, 1)
		self.assertTrue(runner.context['task_chunk_id'])
		self.assertEqual(runner.context['task_id'], 'c' * 24)

"""Unit tests for the api driver hooks (secator.hooks.api)."""
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
		page = '<html>\n<head><title>502 Bad Gateway</title></head></html>'
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(502, page))
		msg = str(cm.exception)
		self.assertIn('POST runners', msg)
		self.assertIn('HTTP 502', msg)
		self.assertIn('<html> <head><title>502 Bad Gateway</title>', msg)
		self.assertEqual(cm.exception.response.status_code, 502)

	def test_json_error_detail_is_in_the_message(self):
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(403, '{"detail": "Access denied"}', json_body={'detail': 'Access denied'}))
		self.assertIn('HTTP 403: Access denied', str(cm.exception))

	def test_long_body_is_truncated(self):
		with self.assertRaises(requests.HTTPError) as cm:
			self._call(_raw_resp(500, 'x' * 5000), method='GET')
		self.assertLess(len(str(cm.exception)), 300)

	def test_empty_success_body_returns_none(self):
		self.assertIsNone(self._call(_raw_resp(204, ''), method='DELETE'))

	def test_non_json_success_body_raises_clear_error(self):
		with patch.object(api._session, 'request', return_value=_raw_resp(200, '<html>ok</html>')):
			with self.assertRaises(requests.exceptions.RequestException) as cm:
				api._make_request('GET', 'runners')
		self.assertIn('GET runners returned HTTP 200 with a non-JSON body: <html>ok</html>', str(cm.exception))


if __name__ == '__main__':
	unittest.main()

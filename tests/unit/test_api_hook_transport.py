"""Unit tests for the api driver transport (secator.hooks.api._make_request)."""
import unittest
from unittest.mock import MagicMock, patch

import requests

from secator.hooks import api


def _resp(status=200, body=None, text=None):
	r = MagicMock()
	r.status_code = status
	r.ok = status < 400
	if body is not None:
		r.json.return_value = body
	else:
		r.json.side_effect = ValueError('not json')
	r.text = text or ''

	def raise_for_status():
		if status >= 400:
			raise requests.HTTPError(f'{status} error', response=r)
	r.raise_for_status.side_effect = raise_for_status
	return r


class TestApiRequest(unittest.TestCase):

	def test_session_retries_writes(self):
		# Retries/backoff come from the shared secator.requests get_session() helper,
		# with POST added so idempotency-keyed writes are retried too.
		retry = api._SESSION.get_adapter('https://x').max_retries
		self.assertEqual(retry.total, 3)
		self.assertEqual(retry.backoff_factor, 1)
		self.assertIn('POST', retry.allowed_methods)
		self.assertIn('PUT', retry.allowed_methods)
		self.assertNotIn(404, retry.status_forcelist)

	def test_non_json_error_raises_http_error(self):
		with patch.object(api._SESSION, 'request', return_value=_resp(502, text='<html>bad gateway</html>')):
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')

	def test_client_error_raises_http_error(self):
		with patch.object(api._SESSION, 'request', return_value=_resp(404, body={'detail': 'nope'})) as req:
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')
		self.assertEqual(req.call_count, 1)

	def test_finding_create_sends_idempotency_key(self):
		with patch.object(api._SESSION, 'request', return_value=_resp(body={'id': 'x'})) as req:
			result = api._make_request('POST', 'findings', {'a': 1}, idempotency_key='u-1')
		self.assertEqual(result, {'id': 'x'})
		self.assertEqual(req.call_args.kwargs['headers']['Idempotency-Key'], 'u-1')


if __name__ == '__main__':
	unittest.main()

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

	def test_uses_shared_retry_session(self):
		# Retries/backoff are delegated to the shared secator.requests session, not a
		# bespoke one built in the api hook.
		from secator.requests import requests as shared_session
		self.assertIs(api.requests, shared_session)

	def test_non_json_error_raises_http_error(self):
		with patch.object(api.requests, 'request', return_value=_resp(502, text='<html>bad gateway</html>')):
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')

	def test_client_error_raises_http_error(self):
		with patch.object(api.requests, 'request', return_value=_resp(404, body={'detail': 'nope'})) as req:
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')
		self.assertEqual(req.call_count, 1)

	def test_finding_create_sends_idempotency_key(self):
		with patch.object(api.requests, 'request', return_value=_resp(body={'id': 'x'})) as req:
			result = api._make_request('POST', 'findings', {'a': 1}, idempotency_key='u-1')
		self.assertEqual(result, {'id': 'x'})
		self.assertEqual(req.call_args.kwargs['headers']['Idempotency-Key'], 'u-1')


if __name__ == '__main__':
	unittest.main()

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


def _mock_session(response):
	session = MagicMock()
	session.request.return_value = response
	return session


class TestApiRetryPolicy(unittest.TestCase):
	"""Retries are delegated to urllib3's Retry via a mounted HTTPAdapter."""

	def test_session_retry_policy(self):
		api._get_session.cache_clear()
		retry = api._get_session().get_adapter('https://example').max_retries
		self.assertEqual(retry.total, api.API_RETRIES)
		self.assertEqual(retry.backoff_factor, 1)  # exponential backoff 1s, 2s, 4s
		# Transient statuses are retried; client errors (e.g. 404) are not.
		self.assertTrue(set(api.API_RETRY_STATUSES).issubset(set(retry.status_forcelist)))
		self.assertNotIn(404, retry.status_forcelist)
		# POST/PUT are retried: runner/finding writes carry an Idempotency-Key.
		self.assertIn('POST', retry.allowed_methods)
		self.assertIn('PUT', retry.allowed_methods)
		# We handle status -> error ourselves (for the `detail` message), so urllib3
		# must not raise on status.
		self.assertFalse(retry.raise_on_status)


class TestApiRequest(unittest.TestCase):

	def test_non_json_error_raises_http_error(self):
		session = _mock_session(_resp(502, text='<html>bad gateway</html>'))
		with patch.object(api, '_get_session', return_value=session):
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')

	def test_client_error_raises_http_error(self):
		session = _mock_session(_resp(404, body={'detail': 'nope'}))
		with patch.object(api, '_get_session', return_value=session):
			with self.assertRaises(requests.HTTPError):
				api._make_request('GET', 'runners')
		self.assertEqual(session.request.call_count, 1)

	def test_finding_create_sends_idempotency_key(self):
		session = _mock_session(_resp(body={'id': 'x'}))
		with patch.object(api, '_get_session', return_value=session):
			result = api._make_request('POST', 'findings', {'a': 1}, idempotency_key='u-1')
		self.assertEqual(result, {'id': 'x'})
		self.assertEqual(session.request.call_args.kwargs['headers']['Idempotency-Key'], 'u-1')


if __name__ == '__main__':
	unittest.main()

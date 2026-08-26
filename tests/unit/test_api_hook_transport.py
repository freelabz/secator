"""API hook transport-security tests.

The ``api`` driver POSTs runner/finding data — including raw targets, accumulated
command output and the Bearer API key — to the configured ``addons.api.url``.
``_make_request`` must refuse to do that over cleartext HTTP to a remote host,
regardless of ``force_ssl`` (which only governs TLS certificate *verification*).
Loopback http:// stays allowed for local dev. These tests pin that guard.
"""

import unittest
from unittest import mock

from secator.hooks import api as api_hook


class TestApiHookTransportGuard(unittest.TestCase):
	def _check(self, url):
		with mock.patch.object(api_hook, 'API_URL', url):
			# Stop before any real network call: the guard runs first, so if it
			# allows the request, requests.request is reached and we short-circuit.
			with mock.patch.object(api_hook.requests, 'request') as req:
				req.side_effect = RuntimeError('reached_network')
				api_hook._make_request('GET', 'workspaces')

	def test_remote_http_rejected(self):
		with self.assertRaises(Exception) as ctx:
			self._check('http://app.secator.cloud/api')
		self.assertIn('cleartext', str(ctx.exception).lower())

	def test_remote_http_rejected_even_with_force_ssl_false(self):
		with mock.patch.object(api_hook, 'FORCE_SSL', False):
			with self.assertRaises(Exception) as ctx:
				self._check('http://10.0.0.5:8081/api')
			self.assertIn('cleartext', str(ctx.exception).lower())

	def test_https_remote_allowed(self):
		# Allowed by the guard -> proceeds to the network call (which we stub).
		with self.assertRaises(RuntimeError) as ctx:
			self._check('https://app.secator.cloud/api')
		self.assertEqual(str(ctx.exception), 'reached_network')

	def test_http_localhost_allowed(self):
		with self.assertRaises(RuntimeError) as ctx:
			self._check('http://localhost:8081/api')
		self.assertEqual(str(ctx.exception), 'reached_network')

	def test_http_loopback_ip_allowed(self):
		with self.assertRaises(RuntimeError) as ctx:
			self._check('http://127.0.0.1:8081/api')
		self.assertEqual(str(ctx.exception), 'reached_network')


if __name__ == '__main__':
	unittest.main()

"""Tests for the AI fetch_url tool — SSRF guard (the security-critical part) + extraction + handler."""

import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai import fetch_url as fu
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSSRFGuard(unittest.TestCase):
	"""fetch_url must never let the agent reach our own internal surface."""

	def test_non_http_schemes_blocked(self):
		for u in ('file:///etc/passwd', 'gopher://x/', 'ftp://x/', 'dict://localhost:11211/',
		          'jar:http://x!/', 'data:text/html,hi'):
			ok, reason = fu.is_safe_public_url(u)
			self.assertFalse(ok, u)

	def test_ip_literals_private_blocked(self):
		for host in ('127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254',
		             '0.0.0.0', '[::1]', '[fd00::1]', '[fe80::1]'):
			ok, _ = fu.is_safe_public_url(f'http://{host}/')
			self.assertFalse(ok, host)

	def test_metadata_ip_blocked(self):
		# AWS/GCP/Azure link-local metadata endpoint.
		self.assertFalse(fu.is_safe_public_url('http://169.254.169.254/latest/meta-data/')[0])

	def test_public_ip_allowed(self):
		self.assertTrue(fu.is_safe_public_url('https://1.1.1.1/')[0])

	def test_hostname_resolving_to_private_blocked(self):
		# DNS-rebinding style: a public-looking host that resolves to a private IP.
		with patch('secator.ai.fetch_url.socket.getaddrinfo',
		           return_value=[(2, 1, 6, '', ('10.1.2.3', 0))]):
			ok, reason = fu.is_safe_public_url('http://evil.example.com/')
		self.assertFalse(ok)
		self.assertIn('SSRF', reason)

	def test_hostname_resolving_to_public_allowed(self):
		with patch('secator.ai.fetch_url.socket.getaddrinfo',
		           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
			self.assertTrue(fu.is_safe_public_url('http://example.com/')[0])

	def test_unresolvable_host_blocked(self):
		import socket as _s
		with patch('secator.ai.fetch_url.socket.getaddrinfo', side_effect=_s.gaierror('nope')):
			self.assertFalse(fu.is_safe_public_url('http://nx.invalid/')[0])

	def test_ipv4_mapped_private_v6_blocked(self):
		self.assertFalse(fu.is_safe_public_url('http://[::ffff:10.0.0.1]/')[0])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFetchAndExtract(unittest.TestCase):

	def _resp(self, *, status=200, ct='text/html', body=b'', location=None):
		r = MagicMock()
		r.status_code = status
		r.is_redirect = location is not None
		r.headers = {'Content-Type': ct}
		if location:
			r.headers['Location'] = location
		r.encoding = 'utf-8'
		r.raw.read.return_value = body
		r.close.return_value = None
		return r

	def test_extracts_title_and_text_strips_scripts(self):
		html_body = (b'<html><head><title>My &amp; Page</title></head>'
		             b'<body><script>alert(1)</script><h1>Hello</h1><p>World</p></body></html>')
		with patch('secator.ai.fetch_url.is_safe_public_url', return_value=(True, '')), \
			patch('secator.ai.fetch_url.requests.get', return_value=self._resp(body=html_body)):
			res, err = fu.fetch_url('https://example.com/')
		self.assertIsNone(err)
		self.assertEqual(res['title'], 'My & Page')
		self.assertIn('Hello', res['text'])
		self.assertIn('World', res['text'])
		self.assertNotIn('alert(1)', res['text'])

	def test_binary_content_type_refused(self):
		with patch('secator.ai.fetch_url.is_safe_public_url', return_value=(True, '')), \
			patch('secator.ai.fetch_url.requests.get',
			      return_value=self._resp(ct='application/octet-stream', body=b'\x00\x01')):
			res, err = fu.fetch_url('https://example.com/x.bin')
		self.assertIsNone(res)
		self.assertIn('not text', err)

	def test_redirect_to_private_is_blocked(self):
		# First hop public (redirect), second hop points at an internal host -> blocked.
		pub = self._resp(status=302, location='http://169.254.169.254/')
		calls = {'n': 0}

		def fake_get(url, **kw):
			calls['n'] += 1
			return pub

		with patch('secator.ai.fetch_url.requests.get', side_effect=fake_get):
			res, err = fu.fetch_url('https://example.com/redir')
		self.assertIsNone(res)
		self.assertIn('SSRF', err)

	def test_truncation(self):
		body = b'<html><body>' + b'x' * 5000 + b'</body></html>'
		with patch('secator.ai.fetch_url.is_safe_public_url', return_value=(True, '')), \
			patch('secator.ai.fetch_url.requests.get', return_value=self._resp(body=body)):
			res, err = fu.fetch_url('https://example.com/', max_chars=500)
		self.assertTrue(res['truncated'])
		self.assertIn('[truncated]', res['text'])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFetchUrlTool(unittest.TestCase):

	def _ctx(self):
		return ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})

	def test_tool_exposed_and_mapped(self):
		for mode in ('attack', 'chat', 'exploit'):
			self.assertIn('fetch_url', [s['function']['name'] for s in build_tool_schemas(mode)], mode)
		self.assertEqual(tool_call_to_action('fetch_url', {'url': 'https://x'})['action'], 'fetch_url')

	def test_guardrail_auto_allow_not_target_gated(self):
		e = PermissionEngine(config={'allow': [], 'deny': [], 'ask': []}, in_scope=['only.example.com'])
		self.assertEqual(e.check_action({'action': 'fetch_url', 'url': 'https://other.com'}).decision, 'allow')

	def test_handler_success(self):
		res = {'url': 'https://x/', 'status': 200, 'title': 'T', 'content_type': 'text/html',
		       'text': 'body text', 'truncated': False}
		with patch('secator.ai.fetch_url.fetch_url', return_value=(res, None)):
			out = list(dispatch_action({'action': 'fetch_url', 'url': 'https://x/'}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai)]
		self.assertEqual(ai[0].ai_type, 'fetch_url')
		page = [o for o in out if isinstance(o, dict) and o.get('_type') == 'web_page']
		self.assertTrue(page and page[0]['_context']['ai_query_result'])

	def test_handler_error_surfaced(self):
		with patch('secator.ai.fetch_url.fetch_url', return_value=(None, 'refused: SSRF')):
			out = list(dispatch_action({'action': 'fetch_url', 'url': 'http://10.0.0.1'}, self._ctx()))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_handler_missing_url_errors(self):
		self.assertTrue(any(isinstance(o, Error) for o in dispatch_action({'action': 'fetch_url'}, self._ctx())))


if __name__ == '__main__':
	unittest.main()

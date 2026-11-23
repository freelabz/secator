"""fetch_url: optional strict SSRF mode, clearer errors, dedicated web proxy."""
import socket
import unittest
from unittest import mock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	import requests
	from secator.ai.tools import fetch_url as fu
	from secator.ai.tools.fetch_url import fetch_url, is_safe_public_url, _build_session


class _Resp:
	"""Minimal streamed response stand-in for session.get()."""
	status_code = 200
	is_redirect = False
	encoding = 'utf-8'

	def __init__(self, body=b'<html><title>T</title><body>hello</body></html>'):
		self.headers = {'Content-Type': 'text/html'}
		self.raw = mock.Mock()
		self.raw.read.return_value = body

	def close(self):
		pass


def _gai(addr):
	return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (addr, 0))]


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStrictBlocksLiterals(unittest.TestCase):

	BLOCKED = (
		'http://169.254.169.254/latest/meta-data/',
		'http://127.0.0.1/', 'http://10.0.0.5/', 'http://192.168.1.1/', 'http://172.16.0.1/',
		'http://[::1]/', 'http://[fe80::1]/', 'http://[::ffff:127.0.0.1]/', 'http://100.100.100.200/',
	)

	def test_strict_blocks_without_dns(self):
		with mock.patch('socket.getaddrinfo', side_effect=AssertionError('no DNS expected')):
			for url in self.BLOCKED:
				ok, reason = is_safe_public_url(url, strict=True)
				self.assertFalse(ok, url)
				self.assertIn('blocked to prevent SSRF', reason, url)

	def test_strict_blocks_localhost_via_resolution(self):
		with mock.patch('socket.getaddrinfo', return_value=_gai('127.0.0.1')) as gai:
			ok, reason = is_safe_public_url('http://localhost:8080/', strict=True)
		gai.assert_called_once()
		self.assertFalse(ok)
		self.assertIn('resolves to a private/non-public address 127.0.0.1', reason)

	def test_strict_off_is_open(self):
		with mock.patch('socket.getaddrinfo', side_effect=AssertionError('no DNS expected')):
			for url in self.BLOCKED + ('http://localhost/', 'http://metadata.google.internal/'):
				self.assertEqual(is_safe_public_url(url, strict=False), (True, ''), url)

	def test_scheme(self):
		for strict in (False, True):
			ok, reason = is_safe_public_url('file:///etc/passwd', strict=strict)
			self.assertFalse(ok)
			self.assertIn('http/https only', reason)

	def test_public_ip_literal_allowed(self):
		self.assertEqual(is_safe_public_url('https://8.8.8.8/', strict=False), (True, ''))

	def test_blocked_hosts_never_fetched(self):
		with mock.patch('requests.Session.get') as get, \
			mock.patch('socket.getaddrinfo', return_value=_gai('127.0.0.1')):
			for url in ('http://169.254.169.254/', 'http://127.0.0.1/', 'http://localhost:8080/'):
				result, err = fetch_url(url, strict=True, proxy_url='')
				self.assertIsNone(result)
				self.assertIn('blocked to prevent SSRF', err)
			get.assert_not_called()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStrictOff(unittest.TestCase):

	def test_public_hostname_fetched_without_dns_precheck(self):
		with mock.patch('socket.getaddrinfo', side_effect=AssertionError('no DNS precheck expected')), \
			mock.patch('requests.Session.get', return_value=_Resp()) as get:
			result, err = fetch_url('https://github.com/', strict=False, proxy_url='')
		self.assertIsNone(err)
		self.assertEqual(result['title'], 'T')
		get.assert_called_once()

	def test_no_peer_validation_adapter(self):
		s = _build_session(strict=False)
		self.assertNotIsInstance(s.get_adapter('https://x/'), fu._PeerValidatingHTTPAdapter)
		self.assertFalse(s.trust_env)

	def test_dns_failure_error_message(self):
		exc = requests.ConnectionError(socket.gaierror(-2, 'Name or service not known'))
		with mock.patch('requests.Session.get', side_effect=exc):
			result, err = fetch_url('https://nvd.nist.gov/', strict=False, proxy_url='')
		self.assertIsNone(result)
		self.assertIn('could not resolve host nvd.nist.gov', err)
		self.assertIn('addons.ai.web_proxy_url', err)
		self.assertNotIn('not a public', err)

	def test_default_reads_config(self):
		with mock.patch.object(fu, '_ai_web_settings', return_value=(False, '')), \
			mock.patch('socket.getaddrinfo', side_effect=AssertionError('no DNS')), \
			mock.patch('requests.Session.get', return_value=_Resp()):
			result, err = fetch_url('https://example.com/')
		self.assertIsNone(err)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestStrictOn(unittest.TestCase):

	def test_private_resolution_blocked(self):
		with mock.patch('socket.getaddrinfo', return_value=_gai('10.1.2.3')):
			ok, reason = is_safe_public_url('https://evil.example/', strict=True)
		self.assertFalse(ok)
		self.assertIn('resolves to a private/non-public address 10.1.2.3', reason)

	def test_public_resolution_allowed(self):
		with mock.patch('socket.getaddrinfo', return_value=_gai('140.82.112.3')):
			self.assertEqual(is_safe_public_url('https://github.com/', strict=True), (True, ''))

	def test_unresolvable_host_message(self):
		with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'nope')):
			ok, reason = is_safe_public_url('https://github.com/', strict=True)
		self.assertFalse(ok)
		self.assertIn('could not resolve host github.com', reason)
		self.assertIn('addons.ai.web_proxy_url', reason)

	def test_unresolvable_host_with_proxy_message(self):
		with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'nope')):
			ok, reason = is_safe_public_url('https://github.com/', strict=True, proxied=True)
		self.assertFalse(ok)
		self.assertIn('requires local DNS', reason)

	def test_peer_validation_adapter_without_proxy(self):
		s = _build_session(strict=True)
		self.assertIsInstance(s.get_adapter('https://x/'), fu._PeerValidatingHTTPAdapter)

	def test_no_peer_validation_through_proxy(self):
		s = _build_session(strict=True, proxy_url='http://10.0.0.1:3128')
		self.assertNotIsInstance(s.get_adapter('https://x/'), fu._PeerValidatingHTTPAdapter)

	def test_strict_proxy_fetch_when_resolvable(self):
		with mock.patch('socket.getaddrinfo', return_value=_gai('140.82.112.3')), \
			mock.patch('requests.Session.get', return_value=_Resp()):
			result, err = fetch_url('https://github.com/', strict=True, proxy_url='http://10.0.0.1:3128')
		self.assertIsNone(err)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestWebProxy(unittest.TestCase):

	def test_configured_proxy_used_and_env_ignored(self):
		seen = {}

		def fake_send(adapter, request, **kwargs):
			seen['proxies'] = kwargs.get('proxies')
			raise requests.ConnectionError('stop')

		env = {'HTTPS_PROXY': 'http://env-proxy:9999', 'HTTP_PROXY': 'http://env-proxy:9999', 'NO_PROXY': '*'}
		with mock.patch.dict('os.environ', env), \
			mock.patch('requests.adapters.HTTPAdapter.send', autospec=True, side_effect=fake_send):
			fetch_url('https://example.com/', strict=False, proxy_url='http://corp-proxy:3128')
		self.assertEqual(seen['proxies'].get('https'), 'http://corp-proxy:3128')
		self.assertNotIn('env-proxy', str(seen['proxies']))

	def test_env_proxies_ignored_without_config(self):
		seen = {}

		def fake_send(adapter, request, **kwargs):
			seen['proxies'] = kwargs.get('proxies')
			raise requests.ConnectionError('stop')

		with mock.patch.dict('os.environ', {'HTTPS_PROXY': 'http://env-proxy:9999'}), \
			mock.patch('requests.adapters.HTTPAdapter.send', autospec=True, side_effect=fake_send):
			fetch_url('https://example.com/', strict=False, proxy_url='')
		self.assertFalse(seen['proxies'].get('https'))

	def test_bad_proxy_scheme(self):
		result, err = fetch_url('https://example.com/', strict=False, proxy_url='ftp://p:21')
		self.assertIsNone(result)
		self.assertIn('not supported', err)

	def test_socks_without_pysocks(self):
		with mock.patch.dict('sys.modules', {'socks': None}):
			result, err = fetch_url('https://example.com/', strict=False, proxy_url='socks5h://p:1080')
		self.assertIsNone(result)
		self.assertIn("requests[socks]", err)

	def test_web_search_uses_proxy(self):
		from secator.ai.tools import web_search as ws
		with mock.patch.object(fu, '_ai_web_settings', return_value=(False, 'http://corp-proxy:3128')), \
			mock.patch.object(ws.requests, 'post') as post:
			post.return_value.json.return_value = {'exploits': []}
			ws.sploitus_search('log4j')
		proxy = 'http://corp-proxy:3128'
		self.assertEqual(post.call_args.kwargs['proxies'], {'http': proxy, 'https': proxy})

	def test_web_search_no_proxy_by_default(self):
		from secator.ai.tools import web_search as ws
		with mock.patch.object(fu, '_ai_web_settings', return_value=(False, '')), \
			mock.patch.object(ws.requests, 'post') as post:
			post.return_value.json.return_value = {'exploits': []}
			ws.sploitus_search('log4j')
		self.assertIsNone(post.call_args.kwargs['proxies'])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestConfigKeys(unittest.TestCase):

	def test_defaults(self):
		from secator.config import SecatorConfig
		cfg = SecatorConfig()
		self.assertFalse(cfg.addons.ai.fetch_url_ssrf_protection)
		self.assertEqual(cfg.addons.ai.web_proxy_url, '')

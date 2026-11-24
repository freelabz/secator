import unittest
from unittest import mock

import requests

from secator.output_types import Vulnerability
from secator.providers._base import cache_success


class TestVulnerabilitySeverity(unittest.TestCase):

	def _vuln(self, **kwargs):
		return Vulnerability(name='test', matched_at='example.com', **kwargs)

	def test_known_levels_lowercased(self):
		self.assertEqual(self._vuln(severity='High').severity, 'high')
		self.assertEqual(self._vuln(severity='High').severity_nb, 1)

	def test_unknown_levels_folded(self):
		for raw in ('warn', 'informational', '', None, 'FATAL'):
			vuln = self._vuln(severity=raw)
			self.assertEqual(vuln.severity, 'unknown', raw)
			self.assertEqual(vuln.severity_nb, 5, raw)

	def test_cvss_still_derives_severity(self):
		self.assertEqual(self._vuln(severity='unknown', cvss_score=7.5).severity, 'high')


class TestCacheSuccess(unittest.TestCase):

	def test_failures_not_cached(self):
		calls = []
		results = iter([None, 'ok', 'other'])

		@cache_success
		def lookup(x):
			calls.append(x)
			return next(results)

		self.assertIsNone(lookup('a'))
		self.assertEqual(lookup('a'), 'ok')   # retried after a failure
		self.assertEqual(lookup('a'), 'ok')   # success is cached
		self.assertEqual(calls, ['a', 'a'])
		lookup.cache_clear()
		self.assertEqual(lookup('a'), 'other')


class TestCirclRetry(unittest.TestCase):

	def setUp(self):
		from secator.providers.circl import circl
		self.circl = circl
		circl.lookup_cve.cache_clear()
		self.addCleanup(circl.lookup_cve.cache_clear)

	def _resp(self, status, headers=None):
		resp = mock.Mock(status_code=status, headers=headers or {})
		resp.json.return_value = {}  # empty body -> lookup returns None
		if status >= 400:
			resp.raise_for_status.side_effect = requests.HTTPError(str(status))
		return resp

	@mock.patch('secator.providers.circl.time.sleep')
	@mock.patch('secator.providers.circl.requests.get')
	def test_rate_limit_retried_once(self, get, sleep):
		get.side_effect = [self._resp(429, {'Retry-After': '30'}), self._resp(200)]
		with mock.patch('secator.providers.circl.CONFIG') as cfg:
			cfg.runners.skip_cve_search = False
			cfg.offline_mode = False
			self.circl.lookup_cve('CVE-2025-0001')
		self.assertEqual(get.call_count, 2)
		sleep.assert_called_once_with(5)  # Retry-After capped

	@mock.patch('secator.providers.circl.time.sleep')
	@mock.patch('secator.providers.circl.requests.get')
	def test_failed_lookup_is_retried_on_next_call(self, get, sleep):
		get.side_effect = requests.Timeout('slow')
		with mock.patch('secator.providers.circl.CONFIG') as cfg:
			cfg.runners.skip_cve_search = False
			cfg.offline_mode = False
			self.assertIsNone(self.circl.lookup_cve('CVE-2025-0002'))
			self.assertIsNone(self.circl.lookup_cve('CVE-2025-0002'))
		self.assertEqual(get.call_count, 2)


class TestTestsslWarn(unittest.TestCase):

	def test_warn_is_a_warning_not_a_vulnerability(self):
		import json
		import tempfile
		from secator.output_types import Warning
		from secator.tasks.testssl import testssl
		items = [
			{'id': 'HTTP_status_code', 'ip': 'example.com/192.0.2.1', 'port': '443',
			 'severity': 'WARN', 'finding': "Unexpected 502 Bad Gateway @ '/'"},
			{'id': 'LUCKY13', 'ip': 'example.com/192.0.2.1', 'port': '443',
			 'severity': 'LOW', 'finding': 'potentially vulnerable'},
			{'id': 'some_debug', 'ip': 'example.com/192.0.2.1', 'port': '443',
			 'severity': 'DEBUG', 'finding': 'internal'},
		]
		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
			json.dump(items, f)
		runner = mock.Mock(output_path=f.name)
		runner.get_opt_value.return_value = False
		out = list(testssl.on_cmd_done(runner))
		vulns = [o for o in out if isinstance(o, Vulnerability)]
		self.assertEqual([v.name for v in vulns], ['SSL/TLS LUCKY13'])
		self.assertEqual(vulns[0].severity, 'low')
		warns = [o for o in out if isinstance(o, Warning)]
		self.assertTrue(any('HTTP_status_code' in w.message for w in warns))


if __name__ == '__main__':
	unittest.main()

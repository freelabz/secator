import unittest

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.fetch_url import is_safe_public_url, _ip_is_public
	from secator.ai.runner_history import summarize_runner, filter_runners
	import ipaddress


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFetchUrlSSRF(unittest.TestCase):

	def test_cgnat_shared_space_rejected(self):
		# 100.64.0.0/10 is neither is_private nor is_reserved, but not is_global — it must be
		# rejected (contains the Alibaba metadata host 100.100.100.200 / Tailscale CGNAT hosts).
		self.assertFalse(_ip_is_public(ipaddress.ip_address('100.100.100.200')))
		self.assertFalse(_ip_is_public(ipaddress.ip_address('100.64.0.1')))

	def test_is_safe_public_url_rejects_cgnat(self):
		ok, reason = is_safe_public_url('http://100.100.100.200/')
		self.assertFalse(ok)

	def test_link_local_and_metadata_rejected(self):
		self.assertFalse(_ip_is_public(ipaddress.ip_address('169.254.169.254')))
		self.assertFalse(_ip_is_public(ipaddress.ip_address('fe80::1')))

	def test_private_and_loopback_rejected(self):
		for a in ('10.0.0.1', '192.168.1.1', '172.16.0.1', '127.0.0.1', '0.0.0.0'):
			self.assertFalse(_ip_is_public(ipaddress.ip_address(a)), a)

	def test_public_ip_allowed(self):
		self.assertTrue(_ip_is_public(ipaddress.ip_address('8.8.8.8')))

	def test_non_http_scheme_rejected(self):
		ok, _ = is_safe_public_url('file:///etc/passwd')
		self.assertFalse(ok)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRunnerHistory(unittest.TestCase):

	def test_summary_exposes_run_scope_id(self):
		runner = {
			'_type': 'scans', '_id': 'scans/0', 'name': 'recon', 'status': 'SUCCESS',
			'context': {'scan_id': 'abc-123'},
		}
		out = summarize_runner(runner)
		self.assertEqual(out['_id'], 'scans/0')         # report folder id preserved
		self.assertEqual(out['run_id'], 'abc-123')      # raw run-scope id surfaced

	def test_summary_underscore_context_fallback(self):
		runner = {'_type': 'tasks', '_id_str': 'tasks/x', '_context': {'task_id': 't-9'}}
		self.assertEqual(summarize_runner(runner)['run_id'], 't-9')

	def test_invalid_since_rejected(self):
		with self.assertRaises(ValueError):
			filter_runners([], since='1 month')

	def test_empty_since_not_rejected(self):
		self.assertEqual(filter_runners([], since=''), [])
		self.assertEqual(filter_runners([], since=None), [])

	def test_valid_window_since_accepted(self):
		self.assertEqual(filter_runners([], since='7d'), [])


if __name__ == '__main__':
	unittest.main()

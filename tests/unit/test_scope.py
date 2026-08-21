import unittest

from secator.runners._helpers import run_extractors
from secator.scope import as_scope_list, host_in_scope, target_in_scope


class TestScopeMatcher(unittest.TestCase):
	"""Semantics must mirror the platform (secator-api) mandate scope matcher."""

	def test_apex_does_not_cover_subdomain(self):
		# The bug: a scope of `claris.com` (apex only) must NOT cover discovered subdomains.
		self.assertTrue(target_in_scope('claris.com', ['claris.com']))
		self.assertFalse(target_in_scope('www.claris.com', ['claris.com']))

	def test_wildcard_covers_subdomain(self):
		self.assertTrue(target_in_scope('www.claris.com', ['*.claris.com']))
		self.assertFalse(target_in_scope('claris.com', ['*.claris.com']))

	def test_cidr_and_regex(self):
		self.assertTrue(target_in_scope('10.0.0.5', ['10.0.0.0/24']))
		self.assertFalse(target_in_scope('10.0.1.5', ['10.0.0.0/24']))
		self.assertTrue(target_in_scope('https://api.acme.com/v1/', [r'^https?://api\.acme\.com/']))

	def test_host_extracted_from_url(self):
		self.assertTrue(target_in_scope('https://www.claris.com/login', ['*.claris.com']))

	def test_deny_wins(self):
		self.assertFalse(host_in_scope('secret.claris.com', ['*.claris.com'], ['secret.claris.com']))
		self.assertTrue(host_in_scope('www.claris.com', ['*.claris.com'], ['secret.claris.com']))

	def test_empty_in_scope_allows_all(self):
		self.assertTrue(host_in_scope('anything.example', [], []))

	def test_as_scope_list_coercion(self):
		self.assertEqual(as_scope_list('a.com, b.com'), ['a.com', 'b.com'])
		self.assertEqual(as_scope_list(['a.com', ' b.com ']), ['a.com', 'b.com'])
		self.assertEqual(as_scope_list(None), [])


class TestRunExtractorsScopeFilter(unittest.TestCase):
	"""The fan-in choke point must drop out-of-scope discovered targets."""

	def test_discovered_subdomain_filtered_against_allowlist(self):
		# Simulates subdomain_recon feeding host_recon: claris.com in scope (apex only),
		# www.claris.com discovered -> must be dropped before host_recon scans it.
		discovered = ['claris.com', 'www.claris.com', 'api.claris.com']
		inputs, _opts, errors = run_extractors(
			[], {'in_scope': ['claris.com']}, inputs=discovered
		)
		self.assertEqual(errors, [])
		self.assertEqual(inputs, ['claris.com'])

	def test_wildcard_scope_keeps_subdomains(self):
		discovered = ['claris.com', 'www.claris.com', 'evil.com']
		inputs, _opts, _errors = run_extractors(
			[], {'in_scope': ['*.claris.com', 'claris.com']}, inputs=discovered
		)
		self.assertEqual(sorted(inputs), ['claris.com', 'www.claris.com'])

	def test_no_scope_option_is_noop(self):
		discovered = ['claris.com', 'www.claris.com']
		inputs, _opts, _errors = run_extractors([], {}, inputs=discovered)
		self.assertEqual(sorted(inputs), ['claris.com', 'www.claris.com'])


if __name__ == '__main__':
	unittest.main()

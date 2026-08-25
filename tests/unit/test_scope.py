import time
import unittest

from secator.runners._helpers import run_extractors
from secator.scope import as_scope_list, host_in_scope, target_in_scope


class TestScopeMatcher(unittest.TestCase):
	"""Semantics must mirror the platform (secator-api) mandate scope matcher."""

	# --- host / wildcard --------------------------------------------------

	def test_apex_does_not_cover_subdomain(self):
		# apex-only scope `claris.com` must NOT cover discovered subdomains.
		self.assertTrue(target_in_scope('claris.com', ['claris.com']))
		self.assertFalse(target_in_scope('www.claris.com', ['claris.com']))

	def test_wildcard_covers_subdomain_but_not_apex(self):
		self.assertTrue(target_in_scope('www.claris.com', ['*.claris.com']))
		self.assertTrue(target_in_scope('a.b.claris.com', ['*.claris.com']))
		# apex is NOT covered by a wildcard (documented behaviour).
		self.assertFalse(target_in_scope('claris.com', ['*.claris.com']))
		# and a wildcard must not match a lookalike suffix.
		self.assertFalse(target_in_scope('evilclaris.com', ['*.claris.com']))
		self.assertFalse(target_in_scope('www.claris.com.evil.net', ['*.claris.com']))

	def test_host_extracted_from_url_and_port(self):
		self.assertTrue(target_in_scope('https://www.claris.com/login', ['*.claris.com']))
		self.assertTrue(target_in_scope('www.claris.com:8443', ['*.claris.com']))
		self.assertTrue(target_in_scope('https://app.acme.com/x', ['app.acme.com']))

	# --- CIDR containment (v4 + v6) --------------------------------------

	def test_cidr_containment_v4(self):
		self.assertTrue(target_in_scope('10.0.0.5', ['10.0.0.0/24']))
		self.assertFalse(target_in_scope('10.0.1.5', ['10.0.0.0/24']))
		# CIDR target subnet_of a CIDR entry.
		self.assertTrue(target_in_scope('10.0.0.0/25', ['10.0.0.0/24']))
		self.assertFalse(target_in_scope('10.0.0.0/23', ['10.0.0.0/24']))

	def test_cidr_containment_v6(self):
		self.assertTrue(target_in_scope('2001:db8::1', ['2001:db8::/32']))
		self.assertTrue(target_in_scope('2001:db8:abcd::5', ['2001:db8::/32']))
		self.assertTrue(target_in_scope('[2001:db8::1]', ['2001:db8::/32']))

	def test_ipv6_escape_bug_is_fixed(self):
		# The old _host_of split(':')[0] truncated '2001:db9::1' -> '2001' and
		# wrongly matched. `2001:db8::/32` must NOT cover `2001:db9::1`.
		self.assertFalse(target_in_scope('2001:db9::1', ['2001:db8::/32']))
		self.assertFalse(host_in_scope('2001:db9::1', ['2001:db8::/32'], []))

	def test_localhost_is_a_scoped_host_not_a_crash(self):
		# `localhost` classifies as IP type but is not a parseable IP literal;
		# it must be treated as a scoped network host, not raise.
		self.assertTrue(target_in_scope('localhost', ['localhost']))
		self.assertFalse(host_in_scope('localhost', ['*.acme.com'], []))

	def test_version_mismatch_never_matches(self):
		self.assertFalse(target_in_scope('10.0.0.5', ['2001:db8::/32']))
		self.assertFalse(target_in_scope('2001:db8::1', ['10.0.0.0/8']))

	# --- anchored regex ---------------------------------------------------

	def test_regex_is_fullmatch_anchored(self):
		# `acme\.com` must match ONLY the exact string, never a substring.
		self.assertTrue(target_in_scope('acme.com', [r'acme\.com']))
		self.assertFalse(target_in_scope('evil-acme.com.attacker.net', [r'acme\.com']))
		self.assertFalse(target_in_scope('acme.com.evil.net', [r'acme\.com']))

	def test_regex_unanchored_substring_does_not_match(self):
		# Even an explicit ^...$ must be enforced at BOTH ends (fullmatch).
		self.assertTrue(target_in_scope('api.acme.com', [r'^api\.acme\.com$']))
		self.assertFalse(target_in_scope('api.acme.com.evil.net', [r'^api\.acme\.com$']))
		self.assertFalse(target_in_scope('x.api.acme.com', [r'^api\.acme\.com$']))

	def test_regex_matches_full_url(self):
		self.assertTrue(target_in_scope('https://api.acme.com/v1/', [r'https?://api\.acme\.com/.*']))
		# a prefix-only regex does NOT fullmatch a longer URL.
		self.assertFalse(target_in_scope('https://api.acme.com/v1/', [r'https?://api\.acme\.com/']))

	def test_pathological_regex_does_not_hang(self):
		# Catastrophic (a+)+ pattern must be rejected, not executed. Call returns
		# fast and simply does not match (fail-safe non-matching).
		start = time.monotonic()
		result = host_in_scope('aaaaaaaaaaaaaaaaaaaaaaaaaaaa.com', [r'(a+)+$'], [])
		elapsed = time.monotonic() - start
		self.assertFalse(result)  # bad allow entry -> nothing matches -> out of scope
		self.assertLess(elapsed, 1.0)

	def test_uncompilable_regex_is_skipped(self):
		# An un-compilable entry contributes no match (does not raise).
		self.assertFalse(target_in_scope('acme.com', [r'(unclosed']))
		# ...and a broken DENY entry does not block (allow-list stays the boundary).
		self.assertTrue(host_in_scope('acme.com', ['acme.com'], [r'(unclosed']))

	# --- deny wins / empty scope -----------------------------------------

	def test_deny_wins(self):
		self.assertFalse(host_in_scope('secret.claris.com', ['*.claris.com'], ['secret.claris.com']))
		self.assertTrue(host_in_scope('www.claris.com', ['*.claris.com'], ['secret.claris.com']))

	def test_deny_cidr_inside_allow_cidr(self):
		# deny CIDR nested inside an allow CIDR -> deny wins.
		self.assertFalse(host_in_scope('10.0.0.5', ['10.0.0.0/8'], ['10.0.0.0/24']))
		self.assertTrue(host_in_scope('10.1.0.5', ['10.0.0.0/8'], ['10.0.0.0/24']))

	def test_empty_in_scope_allows_all(self):
		self.assertTrue(host_in_scope('anything.example', [], []))
		self.assertTrue(host_in_scope('10.9.9.9', [], []))
		# ...but deny still applies with an empty allow-list.
		self.assertFalse(host_in_scope('10.0.0.5', [], ['10.0.0.0/24']))

	# --- non-network targets are never scoped ----------------------------

	def test_non_network_target_is_kept(self):
		# email / username-ish / path are not NETWORK targets -> always kept,
		# even against a restrictive allow-list or a matching-looking deny.
		self.assertTrue(host_in_scope('user@example.com', ['*.corp.internal'], []))
		self.assertTrue(host_in_scope('user@example.com', [], ['.*@example.com']))
		self.assertTrue(host_in_scope('550e8400-e29b-41d4-a716-446655440000', ['*.acme.com'], []))

	def test_as_scope_list_coercion(self):
		self.assertEqual(as_scope_list('a.com, b.com'), ['a.com', 'b.com'])
		self.assertEqual(as_scope_list(['a.com', ' b.com ']), ['a.com', 'b.com'])
		self.assertEqual(as_scope_list(None), [])


class TestRunExtractorsScopeFilter(unittest.TestCase):
	"""The fan-in choke point must drop out-of-scope discovered targets."""

	def test_discovered_subdomain_filtered_against_allowlist(self):
		# Simulates subdomain_recon feeding host_recon: claris.com in scope (apex only),
		# www.claris.com discovered -> must be dropped before host_recon scans it.
		from secator.output_types import Warning
		discovered = ['claris.com', 'www.claris.com', 'api.claris.com']
		inputs, _opts, messages = run_extractors(
			[], {'in_scope': ['claris.com']}, inputs=discovered
		)
		self.assertEqual(inputs, ['claris.com'])
		warnings = [m for m in messages if isinstance(m, Warning)]
		self.assertEqual(len(warnings), 1)
		self.assertIn('www.claris.com', warnings[0].message)
		self.assertIn('api.claris.com', warnings[0].message)

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

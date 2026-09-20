import time
import unittest
from unittest import mock

from secator.runners._helpers import run_extractors
from secator.scope import as_scope_list, host_in_scope, resolve_scope_hostnames, target_in_scope


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


class TestScopeMalformedTargetNoCrash(unittest.TestCase):
	"""A target the classifier types as IP/CIDR but ipaddress can't parse (a
	malformed string, e.g. a leaked `HOST:...` token) must NOT raise out of the
	scope check — it returns "not a network target" so the caller decides, instead
	of a ValueError crashing the whole AI run."""

	def test_target_shape_guards_valueerror(self):
		from unittest.mock import patch
		from secator.scope import _target_shape
		import secator.scope as scope
		# Force the IP branch on a value ipaddress rejects.
		fake = type("Info", (), {"type": scope.IP})()
		with patch.object(scope, "classify_target", return_value=fake), \
			patch.object(scope, "canonicalize_target", return_value="not-an-ip"), \
			patch.object(scope, "_is_ip_literal", return_value=True):
			self.assertIsNone(_target_shape("not-an-ip"))  # no raise

	def test_host_in_scope_does_not_raise_on_malformed(self):
		# Whatever the verdict, it must return a bool, never raise.
		self.assertIn(
			host_in_scope("HOST:4f2456c7dedf", in_scope=["10.0.0.0/8"], out_of_scope=[]),
			(True, False),
		)


class TestUnderscoreHostnameScope(unittest.TestCase):
	"""Underscore hostnames (RFC-1035-invalid but real, e.g. cloud reverse-DNS) must
	classify as hosts and obey scope. Regression: they classified as `str`, and the
	scope matcher fails OPEN on non-network tokens, letting out-of-scope hosts through.
	"""

	IN_SCOPE = ['vps592398.ovh.net', '*.vps592398.ovh.net']
	UNDERSCORE = 'xnkib_227077.s3.bhs.cloud.ovh.net'

	def test_underscore_hostname_classifies_as_host(self):
		from secator.utils import autodetect_type
		from secator.definitions import HOST, HOST_PORT
		self.assertEqual(autodetect_type(self.UNDERSCORE), HOST)
		self.assertEqual(autodetect_type(self.UNDERSCORE + ':34654'), HOST_PORT)

	def test_out_of_scope_underscore_host_is_rejected(self):
		# the incident: this must be False, not fail-open True.
		self.assertFalse(host_in_scope(self.UNDERSCORE, self.IN_SCOPE, []))
		self.assertFalse(host_in_scope(self.UNDERSCORE + ':34654', self.IN_SCOPE, []))

	def test_in_scope_still_kept_and_plain_out_still_dropped(self):
		self.assertTrue(host_in_scope('vps592398.ovh.net', self.IN_SCOPE, []))
		self.assertTrue(host_in_scope('a.vps592398.ovh.net', self.IN_SCOPE, []))
		self.assertFalse(host_in_scope('evil.com', self.IN_SCOPE, []))


class TestResolveScopeHostnames(unittest.TestCase):
	"""resolve_scope_hostnames widens a scope list with a hostname's IPs (DNS mocked
	so the test never touches the network)."""

	def _patch_dns(self, mapping):
		import socket

		def fake_getaddrinfo(host, *a, **k):
			if host in mapping:
				return [(None, None, None, "", (ip, 0)) for ip in mapping[host]]
			raise socket.gaierror("name resolution failed")

		return mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo)

	def test_hostname_expands_to_ip_and_matches(self):
		with self._patch_dns({"pentest-ground.com": ["178.79.134.182"]}):
			out = resolve_scope_hostnames(["pentest-ground.com"])
		self.assertEqual(out, ["pentest-ground.com", "178.79.134.182"])
		# The resolved IP (and IP:port) now match the widened scope literally.
		self.assertTrue(host_in_scope("178.79.134.182", out, []))
		self.assertTrue(host_in_scope("178.79.134.182:6379", out, []))
		self.assertFalse(host_in_scope("8.8.8.8", out, []))

	def test_non_hostname_entries_pass_through_unresolved(self):
		with self._patch_dns({}):
			entries = ["*.acme.com", "10.0.0.0/24", "1.2.3.4", r"acme\.com"]
			self.assertEqual(resolve_scope_hostnames(entries), entries)

	def test_resolution_failure_is_ignored(self):
		with self._patch_dns({}):  # every lookup raises
			self.assertEqual(resolve_scope_hostnames(["nope.invalid"]), ["nope.invalid"])

	def test_dedupes_already_present_ip(self):
		with self._patch_dns({"h.com": ["1.2.3.4"]}):
			out = resolve_scope_hostnames(["h.com", "1.2.3.4"])
		self.assertEqual(out.count("1.2.3.4"), 1)

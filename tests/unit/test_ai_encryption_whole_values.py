"""SensitiveDataEncryptor replaces whole matched values only, never part of a longer value."""
import re
import unittest

from secator.ai.encryption import SensitiveDataEncryptor

PH_RE = re.compile(r"\[(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[0-9a-f]{12}\]")


def _strip(text):
	"""Return text with every placeholder removed, to check nothing leaked around them."""
	return PH_RE.sub("", text)


class TestEncryptWholeValues(unittest.TestCase):

	def setUp(self):
		self.enc = SensitiveDataEncryptor(salt="test")

	def test_ip_prefix_of_another_ip(self):
		text = "hosts 10.10.0.1 and 10.10.0.12 are up"
		out = self.enc.encrypt(text)
		ph_short = self.enc._hash_value("10.10.0.1", "ipv4")
		ph_long = self.enc._hash_value("10.10.0.12", "ipv4")
		self.assertEqual(out, f"hosts {ph_short} and {ph_long} are up")
		self.assertNotIn(f"{ph_short}2", out)

	def test_ip_prefix_order_reversed(self):
		out = self.enc.encrypt("10.10.0.12 then 10.10.0.1")
		ph_short = self.enc._hash_value("10.10.0.1", "ipv4")
		ph_long = self.enc._hash_value("10.10.0.12", "ipv4")
		self.assertEqual(out, f"{ph_long} then {ph_short}")

	def test_host_suffix_of_another_host(self):
		text = "example.com redirects to api.example.com"
		out = self.enc.encrypt(text)
		ph_apex = self.enc._hash_value("example.com", "host")
		ph_sub = self.enc._hash_value("api.example.com", "host")
		self.assertEqual(out, f"{ph_apex} redirects to {ph_sub}")
		self.assertNotIn("api.", out)
		self.assertNotEqual(ph_apex, ph_sub)

	def test_same_value_repeated(self):
		out = self.enc.encrypt("10.0.0.5, 10.0.0.5 and again 10.0.0.5")
		ph = self.enc._hash_value("10.0.0.5", "ipv4")
		self.assertEqual(out, f"{ph}, {ph} and again {ph}")
		self.assertEqual(len(self.enc.pii_map), 1)

	def test_custom_pattern_overlapping_builtin(self):
		# The custom ip:port pattern runs first and claims its whole span; the built-in ipv4
		# pass must not re-match inside it, but still encrypts the standalone IP on its own.
		enc = SensitiveDataEncryptor(salt="test", custom_patterns=[r"\d+\.\d+\.\d+\.\d+:\d+"])
		text = "10.0.0.1:8080 and 10.0.0.1"
		out = enc.encrypt(text)
		ph_custom = enc._hash_value("10.0.0.1:8080", "custom_0")
		ph_ip = enc._hash_value("10.0.0.1", "ipv4")
		self.assertEqual(out, f"{ph_custom} and {ph_ip}")
		self.assertEqual(enc.decrypt(out), text)

	def test_custom_pattern_value_prefix_of_another(self):
		enc = SensitiveDataEncryptor(salt="test", custom_patterns=[r"ACME-\d+"])
		out = enc.encrypt("ACME-4 and ACME-42")
		ph_short = enc._hash_value("ACME-4", "custom_0")
		ph_long = enc._hash_value("ACME-42", "custom_0")
		self.assertEqual(out, f"{ph_short} and {ph_long}")

	def test_builtin_never_matches_inside_custom_placeholder(self):
		enc = SensitiveDataEncryptor(salt="test", custom_patterns=["ACME-[0-9]+"])
		text = "ticket ACME-42 on 10.0.0.1"
		out = enc.encrypt(text)
		self.assertEqual(len(PH_RE.findall(out)), 2)
		self.assertEqual(len(enc.pii_map), 2)
		self.assertEqual(enc.decrypt(out), text)

	def test_existing_placeholder_not_reencrypted(self):
		once = self.enc.encrypt("target 10.0.0.1")
		self.assertEqual(self.enc.encrypt(once), once)

	def test_round_trip(self):
		text = (
			"admin@example.com owns example.com, api.example.com and www.example.com; "
			"ips 10.10.0.1 10.10.0.12 10.10.0.123 and 192.168.1.1/24; "
			"file d41d8cd98f00b204e9800998ecf8427e.json stays"
		)
		out = self.enc.encrypt(text)
		self.assertNotIn("example", _strip(out))
		self.assertNotIn("10.10", _strip(out))
		self.assertIn("d41d8cd98f00b204e9800998ecf8427e.json", out)
		self.assertEqual(self.enc.decrypt(out), text)


class TestDecryptWholeTokens(unittest.TestCase):

	def setUp(self):
		self.enc = SensitiveDataEncryptor(salt="test")
		self.ph = self.enc._hash_value("10.0.0.1", "ipv4")
		self.hash = self.ph[1:-1].split(":")[1]

	def test_bare_hash_only_on_word_boundary(self):
		text = f"sha {self.hash}ff and x{self.hash} stay, {self.hash} restores"
		self.assertEqual(
			self.enc.decrypt(text),
			f"sha {self.hash}ff and x{self.hash} stay, 10.0.0.1 restores")

	def test_bracket_stripped_and_full_forms(self):
		stripped = self.ph[1:-1]
		self.assertEqual(self.enc.decrypt(f"{self.ph} / {stripped}"), "10.0.0.1 / 10.0.0.1")

	def test_restored_value_not_rescanned(self):
		# A restored value containing another token's hash must not be decrypted again,
		# whatever order the map entries were added in.
		other_hash = SensitiveDataEncryptor(salt="test")._hash_value("10.0.0.2", "ipv4")[1:-1].split(":")[1]
		enc = SensitiveDataEncryptor(salt="test")
		enc.hash_map["deadbeef0000"] = f"value-{other_hash}"
		enc._hash_value("10.0.0.2", "ipv4")
		self.assertEqual(enc.decrypt("deadbeef0000"), f"value-{other_hash}")

	def test_decrypt_sees_maps_updated_externally(self):
		self.assertEqual(self.enc.decrypt(self.ph), "10.0.0.1")
		self.enc.pii_map["[HOST:aaaaaaaaaaaa]"] = "h.example.com"
		self.assertEqual(self.enc.decrypt("[HOST:aaaaaaaaaaaa]"), "h.example.com")

	def test_empty(self):
		self.assertEqual(self.enc.decrypt(""), "")
		self.assertIsNone(self.enc.decrypt(None))
		self.assertEqual(SensitiveDataEncryptor().decrypt("[HOST:abc]"), "[HOST:abc]")


if __name__ == "__main__":
	unittest.main()

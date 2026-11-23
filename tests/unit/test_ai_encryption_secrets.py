"""SensitiveDataEncryptor encrypts secrets, URL credentials and auth headers, and nothing else."""
import re
import unittest

from secator.ai.encryption import SensitiveDataEncryptor, find_placeholders

PH_RE = re.compile(r"\[(?:EMAIL|IPV4|IPV6|HOST|SECRET|PASSWORD|CUSTOM_\d+):[0-9a-f]{12}\]")

JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PEM_BODY = "\nMIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi+ZKlCyNCI0gUlNM4z6JxFGPnz\nk9rOUi0Mu+aB4cZQf2nm4lJJV6s0/w==\n"


def _strip(text):
	return PH_RE.sub("", text)


class TestEncryptSecrets(unittest.TestCase):

	def setUp(self):
		self.enc = SensitiveDataEncryptor(salt="test")

	def assertEncrypted(self, text, secret, ph_type):
		out = self.enc.encrypt(text)
		self.assertNotIn(secret, out)
		self.assertIn(self.enc._hash_value(secret, ph_type), out)
		self.assertEqual(self.enc.decrypt(out), text)
		return out

	def test_api_tokens(self):
		# Fake tokens, split so they are not token-shaped literals in the source.
		tokens = [
			"AKIA" + "IOSFODNN7EXAMPLE",
			"ASIA" + "Y34FZKBOKMUTVV7A",
			"ghp_" + "A1b2C3d4E5" * 4,
			"gho_" + "z" * 36,
			"ghs_" + "0" * 36,
			"github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123",
			"xoxb-" + "123456789012-1234567890123-abcdefghijklmnop",
			"xoxp-" + "1234567890-abcdef",
			"AIza" + "SyA-1234567890abcdefghijklmnopqrstu",
			"sk_live_" + "51H8abcdefghijklmnop",
			"rk_live_" + "0123456789abcdef",
			JWT,
		]
		for token in tokens:
			with self.subTest(token=token[:12]):
				out = self.assertEncrypted(f"found {token} in app.js", token, "secret")
				self.assertTrue(out.startswith("found [SECRET:"))

	def test_jwt_not_split_by_host_rule(self):
		out = self.assertEncrypted(f"cookie session={JWT}; path=/", JWT, "secret")
		self.assertNotIn("[HOST:", out)

	def test_private_key_block(self):
		text = f"leak:\n-----BEGIN RSA PRIVATE KEY-----{PEM_BODY}-----END RSA PRIVATE KEY-----\nend"
		out = self.assertEncrypted(text, PEM_BODY, "secret")
		self.assertIn("-----BEGIN RSA PRIVATE KEY-----[SECRET:", out)
		for kind in ("", "EC ", "OPENSSH ", "ENCRYPTED "):
			with self.subTest(kind=kind):
				block = f"-----BEGIN {kind}PRIVATE KEY-----{PEM_BODY}-----END {kind}PRIVATE KEY-----"
				self.assertEncrypted(block, PEM_BODY, "secret")

	def test_public_key_and_certificate_left_alone(self):
		for kind in ("PUBLIC KEY", "CERTIFICATE"):
			text = f"-----BEGIN {kind}-----{PEM_BODY}-----END {kind}-----"
			self.assertEqual(self.enc.encrypt(text), text)

	def test_key_value_pairs_encrypt_value_only(self):
		cases = [
			("password=hunter2", "hunter2", "password"),
			("DB_PASSWORD=hunter2", "hunter2", "password"),
			("--passwd=hunter2", "hunter2", "password"),
			("secret = 'my secret'", "my secret", "secret"),
			("client_secret=abc123", "abc123", "secret"),
			("/cb?access_token=abc123&state=1", "abc123", "secret"),
			("api_key=abc123", "abc123", "secret"),
			("X-Api-Key=abc123", "abc123", "secret"),
			("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "wJalrXUtnFEMI/K7MDENG", "secret"),
			('{"password": "p@ss w0rd"}', "p@ss w0rd", "password"),
			('{"api_key": "abc123"}', "abc123", "secret"),
		]
		for text, secret, ph_type in cases:
			with self.subTest(text=text):
				out = self.assertEncrypted(text, secret, ph_type)
				key = re.split(r"[\"'\s:=]", text.lstrip('/cb?-{"'))[0]
				self.assertIn(key, out)

	def test_key_value_forms(self):
		# The value is fully encrypted (nothing of it left after the placeholder) and the key stays.
		cases = [
			("[22][ssh] login: root password: toor", "toor", "password"),
			('password: "hunter2"', "hunter2", "password"),
			("secret_key: abcd1234", "abcd1234", "secret"),
			("X-Api-Key: abc123", "abc123", "secret"),
			('{"accessToken":"abc123xyz"}', "abc123xyz", "secret"),
			('{"clientSecret":"s3c"}', "s3c", "secret"),
			('{"dbPassword":"p4ss"}', "p4ss", "password"),
			('{"password": "it\'s-secret"}', "it's-secret", "password"),
			('{"password": "a\\"bcd"}', 'a\\"bcd', "password"),
			("password=abc,def", "abc,def", "password"),
		]
		for text, secret, ph_type in cases:
			with self.subTest(text=text):
				out = self.enc.encrypt(text)
				ph = self.enc._hash_value(secret, ph_type)
				self.assertIn(ph, out)
				self.assertEqual(out, text.replace(secret, ph, 1))
				self.assertEqual(self.enc.decrypt(out), text)

	def test_key_value_not_matched(self):
		for text in (
			"if (password == confirm)",
			"password=\nnext_line",
			"tokenType=bearer",
			"mytoken=abc",
			"the password policy: strict",
			"SECRET:0123456789ab",
		):
			with self.subTest(text=text):
				self.assertEqual(self.enc.encrypt(text), text)

	def test_url_credentials(self):
		text = "mongodb://admin:s3cr3t@db.example.com:27017/app"
		out = self.assertEncrypted(text, "s3cr3t", "password")
		host_ph = self.enc._hash_value("db.example.com", "host")
		self.assertEqual(out, f"mongodb://admin:{self.enc._hash_value('s3cr3t', 'password')}@{host_ph}:27017/app")

	def test_url_credentials_with_dots_and_ip(self):
		text = "ftp://root:p.a.ss@10.0.0.5/"
		out = self.assertEncrypted(text, "p.a.ss", "password")
		self.assertNotIn("10.0.0.5", out)
		self.assertNotIn("[HOST:", out)

	def test_url_credentials_empty_user_and_at_in_password(self):
		out = self.assertEncrypted("redis://:s3cret@10.0.0.1:6379", "s3cret", "password")
		self.assertTrue(out.startswith("redis://:[PASSWORD:"))
		out = self.assertEncrypted("http://u:p@ss@host.example.com/x", "p@ss", "password")
		self.assertNotIn("[EMAIL:", out)

	def test_private_key_without_end_line(self):
		# A key body cut off by output truncation must still be encrypted.
		text = f"-----BEGIN RSA PRIVATE KEY-----{PEM_BODY}(truncated)"
		out = self.enc.encrypt(text)
		self.assertNotIn("MIIEpAIBAAKCAQEA", out)
		self.assertEqual(self.enc.decrypt(out), text)

	def test_auth_header_without_scheme(self):
		for text, value in (
			("Authorization: rawtoken123", "rawtoken123"),
			("Authorization: AWS4-HMAC-SHA256 Credential=AKID/2026, Signature=abc",
				"AWS4-HMAC-SHA256 Credential=AKID/2026, Signature=abc"),
		):
			with self.subTest(text=text):
				out = self.assertEncrypted(text, value, "secret")
				self.assertEqual(out, f"Authorization: {self.enc._hash_value(value, 'secret')}")
		text = "Access-Control-Allow-Headers: Authorization, Content-Type"
		self.assertEqual(self.enc.encrypt(text), text)

	def test_custom_pattern_named_group_encrypts_whole_match(self):
		enc = SensitiveDataEncryptor(salt="test", custom_patterns=[r"id-(?P<v>\d+)"])
		self.assertEqual(enc.encrypt("id-42"), enc._hash_value("id-42", "custom_0"))

	def test_auth_headers(self):
		for text, value in (
			("Authorization: Bearer abcdef123456", "abcdef123456"),
			("authorization: basic YWRtaW46cGFzc3dvcmQ=", "YWRtaW46cGFzc3dvcmQ="),
			("Proxy-Authorization: Basic YWRtaW46cGFzcw==", "YWRtaW46cGFzcw=="),
			('{"Authorization": "Bearer abc.def.ghi"}', "abc.def.ghi"),
			(f"curl -H 'Authorization: Bearer {JWT}' https://x.test", JWT),
		):
			with self.subTest(text=text):
				out = self.assertEncrypted(text, value, "secret")
				self.assertRegex(out, r"(?i)authorization")

	def test_email_tld_class_has_no_pipe(self):
		self.assertEqual(self.enc.encrypt("a@b.c|m"), "a@b.c|m")
		self.assertIn("[EMAIL:", self.enc.encrypt("admin@example.com"))

	def test_email_leading_punctuation_kept_outside(self):
		out = self.enc.encrypt("see ...admin@example.com")
		self.assertEqual(out, f"see ...{self.enc._hash_value('admin@example.com', 'email')}")

	def test_placeholders_recognized(self):
		out = self.enc.encrypt("password=hunter2 token=ghp_" + "a" * 36)
		self.assertEqual(len(find_placeholders(out)), 2)
		self.assertEqual(find_placeholders(self.enc.decrypt(out)), [])


class TestNoFalsePositives(unittest.TestCase):

	def setUp(self):
		self.enc = SensitiveDataEncryptor(salt="test")

	def test_ordinary_data_left_alone(self):
		for text in (
			"sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709",
			"md5 d41d8cd98f00b204e9800998ecf8427e",
			"sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"git commit 8b1b2a68c0ffee0123456789abcdef0123456789",
			"uuid 123e4567-e89b-12d3-a456-426614174000",
			"blob SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IGJsb2IgdGhhdCBpcyBsb25n==",
			"blob aGVsbG8vd29ybGQrZm9vL2Jhcg/c29tZXRoaW5nZWxzZQ==",
			"etag W/\"5e1f-AKIAnotakeyhere\"",
			"the password policy requires 12 chars and a token is issued",
			"Basic authentication is enabled; use a Bearer token",
			"token_type=bearer password_policy=strict",
			"PWD=/home/user SHELL=/bin/bash",
			"https://example.test:8443/path?x=1",
			"ghp_short sk_test_abcdefghijklmnop",
			"version 1.2.3 and file report.json",
		):
			with self.subTest(text=text):
				out = self.enc.encrypt(text)
				self.assertNotIn("[SECRET:", out)
				self.assertNotIn("[PASSWORD:", out)


class TestLinearTime(unittest.TestCase):
	"""Long runs with no match must not trigger a per-position rescan (tool outputs can be large)."""

	def test_long_runs(self):
		import time
		for text in ("a-" * 200_000, "xoxb-" * 80_000, "-----BEGIN RSA PRIVATE KEY-----\n" * 12_000, "Z" * 400_000):
			with self.subTest(text=text[:10]):
				start = time.perf_counter()
				SensitiveDataEncryptor().encrypt(text)
				self.assertLess(time.perf_counter() - start, 5)


class TestToolArgsDecryptToCommand(unittest.TestCase):
	"""A credential the model only saw as a placeholder is restored in the shell command it runs."""

	def test_placeholders_decrypted_before_execution(self):
		from secator.ai.actions import ActionContext, dispatch_action
		from secator.ai.tools import coerce_stringified_args, tool_call_to_action
		from secator.ai.utils import _decrypt_dict

		enc = SensitiveDataEncryptor(salt="test")
		tool_output = f"found ftp://admin:S3cr.t!@10.0.0.5/ and Authorization: Bearer {JWT}"
		seen_by_model = enc.encrypt(tool_output)
		self.assertNotIn("S3cr.t!", seen_by_model)
		self.assertNotIn(JWT, seen_by_model)
		pw, ip, tok = PH_RE.findall(seen_by_model)

		# The model reuses the placeholders in a tool call; mirror the task's tool-call loop.
		args = {"command": f"curl -H 'Authorization: Bearer {tok}' ftp://admin:{pw}@{ip}/"}
		args = coerce_stringified_args("run_shell", args)
		args = _decrypt_dict(args, enc)
		self.assertEqual(find_placeholders(args), [])
		action = tool_call_to_action("run_shell", args)
		expected = f"curl -H 'Authorization: Bearer {JWT}' ftp://admin:S3cr.t!@10.0.0.5/"
		self.assertEqual(action["command"], expected)

		ctx = ActionContext(targets=["10.0.0.5"], model="gpt-4", dry_run=True, encryptor=enc)
		results = list(dispatch_action(action, ctx))
		self.assertEqual(results[-1].message, f"[DRY RUN] Would run: {expected}")


if __name__ == "__main__":
	unittest.main()

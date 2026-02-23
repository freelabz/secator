# tests/unit/test_ai_safety.py
"""Tests for AI encryption module."""

import unittest


class TestSensitiveDataEncryptor(unittest.TestCase):
    """Tests for the SensitiveDataEncryptor class."""

    def test_encrypt_and_decrypt_host(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://testphp.vulnweb.com/page"
        encrypted = encryptor.encrypt(original)

        # Should contain placeholder
        self.assertIn("[HOST:", encrypted)
        self.assertNotIn("vulnweb.com", encrypted)

        # Decrypt should restore original
        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_decrypt_placeholder_without_brackets(self):
        """Test LLM stripping brackets from placeholders."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "testphp.vulnweb.com"
        encrypted = encryptor.encrypt(original)

        # Extract the placeholder without brackets (simulate LLM behavior)
        # [HOST:a07963bdcb1f] -> HOST:a07963bdcb1f
        no_brackets = encrypted[1:-1]

        # Decrypt should handle this format
        decrypted = encryptor.decrypt(no_brackets)
        self.assertEqual(decrypted, original)

    def test_decrypt_bare_hash(self):
        """Test decrypting bare hash without type prefix."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "testphp.vulnweb.com"
        encrypted = encryptor.encrypt(original)

        # Extract just the hash (e.g., from [HOST:a07963bdcb1f] get a07963bdcb1f)
        import re
        match = re.search(r'\[HOST:([a-f0-9]+)\]', encrypted)
        self.assertIsNotNone(match)
        bare_hash = match.group(1)

        # Decrypt should handle bare hash
        decrypted = encryptor.decrypt(bare_hash)
        self.assertEqual(decrypted, original)

    def test_encrypt_preserves_url_structure(self):
        """Test that URL structure is preserved after encryption/decryption."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://example.com:8080/path?query=value"
        encrypted = encryptor.encrypt(original)
        decrypted = encryptor.decrypt(encrypted)

        self.assertEqual(decrypted, original)

    def test_encrypt_ipv4(self):
        """Test encryption of IPv4 addresses."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "Connect to 192.168.1.100 on port 8080"
        encrypted = encryptor.encrypt(original)

        self.assertIn("[IPV4:", encrypted)
        self.assertNotIn("192.168.1.100", encrypted)

        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_email(self):
        """Test encryption of email addresses."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "Contact admin@example.com for details"
        encrypted = encryptor.encrypt(original)

        self.assertIn("[EMAIL:", encrypted)
        self.assertNotIn("admin@example.com", encrypted)

        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_multiple_values(self):
        """Test encryption of multiple sensitive values."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "Scan example.com and test.org, then check 10.0.0.1"
        encrypted = encryptor.encrypt(original)

        self.assertNotIn("example.com", encrypted)
        self.assertNotIn("test.org", encrypted)
        self.assertNotIn("10.0.0.1", encrypted)

        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_custom_patterns(self):
        """Test encryption with custom patterns."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        custom = ["SECRET_[A-Z0-9]+"]
        encryptor = SensitiveDataEncryptor(custom_patterns=custom)
        original = "API key is SECRET_ABC123XYZ"
        encrypted = encryptor.encrypt(original)

        self.assertIn("[CUSTOM_0:", encrypted)
        self.assertNotIn("SECRET_ABC123XYZ", encrypted)

        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_empty_text(self):
        """Test encryption of empty text."""
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        self.assertEqual(encryptor.encrypt(""), "")
        self.assertEqual(encryptor.decrypt(""), "")


if __name__ == '__main__':
    unittest.main()

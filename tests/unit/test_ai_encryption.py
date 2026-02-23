# tests/unit/test_ai_encryption.py
import unittest


class TestSensitiveDataEncryptor(unittest.TestCase):

    def test_encrypt_host(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://testphp.vulnweb.com/page"
        encrypted = encryptor.encrypt(original)

        self.assertIn("[HOST:", encrypted)
        self.assertNotIn("vulnweb.com", encrypted)

    def test_decrypt_restores_original(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://example.com:8080/path?query=value"
        encrypted = encryptor.encrypt(original)
        decrypted = encryptor.decrypt(encrypted)

        self.assertEqual(decrypted, original)

    def test_decrypt_bare_hash(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor
        import re

        encryptor = SensitiveDataEncryptor()
        original = "testphp.vulnweb.com"
        encrypted = encryptor.encrypt(original)

        match = re.search(r'\[HOST:([a-f0-9]+)\]', encrypted)
        self.assertIsNotNone(match)
        bare_hash = match.group(1)

        decrypted = encryptor.decrypt(bare_hash)
        self.assertEqual(decrypted, original)


if __name__ == '__main__':
    unittest.main()

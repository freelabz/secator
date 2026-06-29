import unittest


class TestShodanConfig(unittest.TestCase):
    def test_addon_defaults(self):
        from secator.config import CONFIG
        self.assertFalse(CONFIG.addons.shodan.enabled)
        self.assertEqual(CONFIG.addons.shodan.api_key, '')

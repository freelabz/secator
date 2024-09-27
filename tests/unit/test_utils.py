import unittest
from secator.utils import extract_domain_info

class TestExtractRootDomain(unittest.TestCase):
	def test_root_domain_extraction(self):
		domains = [
			("subdomain.example.com", "example.com"),
			("www.subdomain.example.co.uk", "example.co.uk"),
			("example.com", "example.com"),
			("ex-ample.co", "ex-ample.co"),
			("test--domain.com", 'test--domain.com'),
			("-example.com", None),
			("example-.com", None),
			("exa_mple.com", None),
			("exa--mple.com", 'exa--mple.com'),
			("example.longtld", None),
			("", None),
			("localhost", None),
			("192.168.1.1", None),
			("test.domain-.com", None),
			("test.-domain.com", None),
			("test_domain.com", None),
			("sub.domain_goes.com", None),
			("okay.domain.gov", "domain.gov"),
			# Adding Unicode domain examples
			("täst.example.org", "example.org"),  # Normal IDN
			("münchen.de", "münchen.de"),  # City domain name in German
			("пример.рф", "пример.рф"),  # Example in Cyrillic
			("中文网.中国", "中文网.中国"),  # Chinese characters
			("xn--fiq228c5hs.xn--fiq64b", "xn--fiq228c5hs.xn--fiq64b"),  # Punycode representation of Chinese domain
			("test.みんな", "test.みんな"),  # Using Japanese TLD
			("http://sub.domain.пример.рф", "пример.рф"),
			("https://suрф.みんな.пример.рф", "пример.рф"),
			("http://mydomain.localhost", None),
		]

		for domain, expected in domains:
			with self.subTest(domain=domain):
				result = extract_domain_info(domain, domain_only=True)
				self.assertEqual(result, expected, f"Failed for domain: {domain}")

import unittest
from secator.utils import extract_domain_info, autodetect_type, parse_raw_http_request
from secator.definitions import HOST, IP, HOST_PORT, URL, CIDR_RANGE, SLUG, EMAIL
from secator.definitions import UUID, PATH
from secator.definitions import MAC_ADDRESS
from secator.definitions import IBAN
from secator.definitions import GCS_URL
from secator.definitions import GIT_REPOSITORY
from secator.definitions import STRING


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

	def test_autodetect_type(self):
		targets = [
			("example.com", HOST),
			("example.co.uk", HOST),
			("example.tata", HOST),
			("localhost", IP),
			("127.0.0.1", IP),
			("192.168.1.1", IP),
			("localhost:22", HOST_PORT),
			("192.168.1.1:8080", HOST_PORT),
			("example.com:8080", HOST_PORT),
			("example.co.uk:80", HOST_PORT),
			("example.tata:443", HOST_PORT),
			("http://localhost", URL),
			("https://localhost", URL),
			("http://localhost:8080", URL),
			("https://localhost:8080", URL),
			("192.168.1.0/24", CIDR_RANGE),
			("test1234567890", SLUG),
			("test@example.com", EMAIL),
			("/tmp", PATH),
			("1234567890", SLUG),
			("testuniformstring", SLUG),
			("test uniform string with spaces", STRING),
			("https://github.com/example/example.git", URL),
			("github.com/example/example.git", STRING),
			("gs://example/example.txt", GCS_URL),
		]
		for target, expected in targets:
			with self.subTest(target=target):
				result = autodetect_type(target)
				self.assertEqual(result, expected, f"Failed for target: {target}")


class TestParseRawHttpRequest(unittest.TestCase):
	def test_parse_simple_post_request(self):
		raw_request = """POST /test HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

search=example"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result['method'], 'POST')
		self.assertEqual(result['url'], 'https://example.com/test')
		self.assertEqual(result['headers']['Host'], 'example.com')
		self.assertEqual(result['headers']['Content-Type'], 'application/x-www-form-urlencoded')
		self.assertEqual(result['data'], 'search=example')

	def test_parse_get_request(self):
		raw_request = """GET /api/users?id=123 HTTP/1.1
Host: api.example.com
User-Agent: Mozilla/5.0
Accept: application/json"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result['method'], 'GET')
		self.assertEqual(result['url'], 'https://api.example.com/api/users?id=123')
		self.assertEqual(result['headers']['Host'], 'api.example.com')
		self.assertEqual(result['headers']['User-Agent'], 'Mozilla/5.0')
		self.assertEqual(result['data'], '')

	def test_parse_request_with_multiple_headers(self):
		raw_request = """POST /login HTTP/1.1
Host: secure.example.com
Cookie: PHPSESSID=abc123; sessionid=xyz789
Content-Type: application/json
Authorization: Bearer token123
Content-Length: 27

{"user":"admin","pass":"***"}"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result['method'], 'POST')
		self.assertEqual(result['url'], 'https://secure.example.com/login')
		self.assertEqual(result['headers']['Cookie'], 'PHPSESSID=abc123; sessionid=xyz789')
		self.assertEqual(result['headers']['Authorization'], 'Bearer token123')
		self.assertEqual(result['data'], '{"user":"admin","pass":"***"}')

	def test_parse_request_with_port_80(self):
		raw_request = """GET / HTTP/1.1
Host: example.com:80"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result['method'], 'GET')
		self.assertEqual(result['url'], 'http://example.com:80/')
		self.assertEqual(result['headers']['Host'], 'example.com:80')

	def test_parse_request_no_body(self):
		raw_request = """DELETE /api/resource/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer token"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result['method'], 'DELETE')
		self.assertEqual(result['url'], 'https://api.example.com/api/resource/123')
		self.assertEqual(result['data'], '')

	def test_parse_empty_request(self):
		raw_request = ""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result, {})

	def test_parse_request_missing_host(self):
		raw_request = """GET /test HTTP/1.1
Content-Type: text/html"""
		result = parse_raw_http_request(raw_request)
		self.assertEqual(result, {})

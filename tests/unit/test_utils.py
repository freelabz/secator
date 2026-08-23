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
			("a" * 255, SLUG),
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


from unittest import mock
import dns.resolver
from secator.utils import canonicalize_target, split_targets, classify_target


class TestCanonicalizeTarget(unittest.TestCase):
	def test_canonicalize_and_classify_network_forms(self):
		# (raw, expected canonical, expected type) -- all must canonicalize to the real host
		# and classify as a network type. Covers the smuggling vectors + IDN + bracketed IPv6.
		cases = [
			(' 1.2.3.4', '1.2.3.4', IP),          # whitespace
			('2130706433', '127.0.0.1', IP),      # decimal inet_aton
			('0177.0.0.1', '127.0.0.1', IP),      # octal
			('127.1', '127.0.0.1', IP),           # short form
			('0x7f.0.0.1', '127.0.0.1', IP),      # hex
			('täst.de', 'xn--tst-qla.de', HOST),  # IDN host -> punycode
			('[2001:db8::1]', '2001:db8::1', IP),  # bracketed IPv6
		]
		for raw, canon, ttype in cases:
			with self.subTest(raw=raw):
				self.assertEqual(canonicalize_target(raw), canon)
				# resolve=False keeps it pure; type detection still sees the canonical (network) form.
				self.assertEqual(classify_target(raw, resolve=False).type, ttype)

	def test_canonicalize_empty(self):
		self.assertEqual(canonicalize_target('  '), '')
		self.assertEqual(canonicalize_target(None), '')


class TestSplitTargets(unittest.TestCase):
	def test_split_on_comma_and_newline(self):
		self.assertEqual(
			split_targets('a.com,b.com\n1.2.3.4 , \n c.com'),
			['a.com', 'b.com', '1.2.3.4', 'c.com'],
		)
		self.assertEqual(split_targets(['a.com,b.com', 'c.com']), ['a.com', 'b.com', 'c.com'])
		self.assertEqual(split_targets(''), [])


class TestClassifyTarget(unittest.TestCase):
	def test_type_detection(self):
		# type mirrors autodetect_type across network + one non-network example
		cases = [
			('1.2.3.4', IP),
			('192.168.1.0/24', CIDR_RANGE),
			('example.com', HOST),               # registrable domain -> HOST
			('sub.example.com', HOST),           # bare hostname -> HOST
			('https://example.com/path', URL),
			('test@example.com', EMAIL),         # non-network
		]
		for token, ttype in cases:
			with self.subTest(token=token):
				self.assertEqual(classify_target(token, resolve=False).type, ttype)

	def test_ip_cidr_network_by_construction_no_dns(self):
		# ip/cidr are network+reachable WITHOUT any DNS call, even with resolve=True.
		with mock.patch.object(dns.resolver.Resolver, 'resolve', side_effect=AssertionError('DNS called')):
			ip = classify_target('1.2.3.4', resolve=True)
			self.assertTrue(ip.is_network and ip.reachable)
			self.assertEqual(ip.root, '1.2.3.4')
			cidr = classify_target('10.0.0.0/8', resolve=True)
			self.assertTrue(cidr.is_network and cidr.reachable)
			self.assertEqual(cidr.root, '10.0.0.0')  # cidr root = network address

	def test_is_network_dns_resolves(self):
		with mock.patch.object(dns.resolver.Resolver, 'resolve', return_value=mock.MagicMock()) as m:
			info = classify_target('example.com', resolve=True)
			self.assertTrue(info.is_network and info.reachable)
			m.assert_called()

	def test_is_network_dns_nxdomain(self):
		with mock.patch.object(dns.resolver.Resolver, 'resolve', side_effect=dns.resolver.NXDOMAIN):
			info = classify_target('nope.invalid', resolve=True)
			self.assertFalse(info.is_network)
			self.assertFalse(info.reachable)

	def test_url_root_is_hostname_and_resolves(self):
		with mock.patch.object(dns.resolver.Resolver, 'resolve', return_value=mock.MagicMock()):
			info = classify_target('https://sub.example.com:8443/a?b=c', resolve=True)
			self.assertEqual(info.root, 'sub.example.com')
			self.assertTrue(info.is_network)

	def test_resolve_false_is_pure_no_io(self):
		# The pure path must NOT touch DNS: a resolver that raises if called proves it.
		with mock.patch.object(dns.resolver.Resolver, 'resolve', side_effect=AssertionError('DNS called')):
			host = classify_target('example.com', resolve=False)
			self.assertEqual(host.type, HOST)
			self.assertFalse(host.is_network)  # unverified without DNS
			# autodetect_type itself is pure regex -> also must not call DNS
			self.assertEqual(autodetect_type('example.com'), HOST)

	def test_scope_and_near_miss_forms_never_network(self):
		# Adversarial: wildcard/regex scope entries and near-miss junk must classify non-network,
		# never smuggled in as a network target.
		with mock.patch.object(dns.resolver.Resolver, 'resolve', return_value=mock.MagicMock()):
			for token in [
				'*.example.com',      # wildcard scope
				'.*\\.corp$',         # regex scope
				'example.*',
				'[a-z].example.com',  # char-class
				'exa mple.com',       # space
				'[::1]:443',          # bracketed IPv6 + port -> ambiguous, fail closed
			]:
				with self.subTest(token=token):
					self.assertFalse(classify_target(token, resolve=True).is_network,
						f'{token} slipped through as network')


from secator.utils import remove_duplicates
from secator.output_types import Vulnerability


def test_remove_duplicates_removes_equal_items():
	v1 = Vulnerability(name='CVE-2021-1234', severity='high', cvss_score=8.0, matched_at='http://example.com', ip='1.2.3.4')
	v2 = Vulnerability(name='CVE-2021-1234', severity='high', cvss_score=8.0, matched_at='http://example.com', ip='1.2.3.4')
	result = remove_duplicates([v1, v2])
	assert len(result) == 1


def test_remove_duplicates_keeps_distinct_items():
	v1 = Vulnerability(name='CVE-2021-1234', severity='high', cvss_score=8.0, matched_at='http://example.com', ip='1.2.3.4')
	v2 = Vulnerability(name='CVE-2021-9999', severity='low', cvss_score=2.0, matched_at='http://other.com', ip='1.2.3.4')
	result = remove_duplicates([v1, v2])
	assert len(result) == 2


def test_remove_duplicates_empty_list():
	assert remove_duplicates([]) == []


def test_remove_duplicates_dicts():
	d1 = {'_type': 'domain', 'name': 'example.com'}
	d2 = {'_type': 'domain', 'name': 'example.com'}
	d3 = {'_type': 'domain', 'name': 'other.com'}
	result = remove_duplicates([d1, d2, d3])
	assert len(result) == 2

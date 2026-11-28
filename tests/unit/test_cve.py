import json
import os
import unittest
from unittest import mock

from secator.utils_test import load_fixture, FIXTURES_DIR
from secator.tasks._categories import Vuln
from secator.providers._base import CVEProvider
from secator.providers.circl import circl
from secator.providers.vulners import vulners
from secator.config import CONFIG
from secator.cve import extract_software_and_version
from secator.output_types import Url


class TestCveHelpers(unittest.TestCase):

	def test_lookup_cve_circle(self):
		actual = circl.lookup_cve('CVE-2023-5568', convert=False)
		self.assertIsNone(actual)

	def test_lookup_cve(self):
		fixture = load_fixture('cve_circle_output', FIXTURES_DIR)
		fixture = circl.convert_cve_info(fixture)
		cve_dir = CONFIG.dirs.cves
		os.makedirs(cve_dir, exist_ok=True)
		cve_path = cve_dir / 'CVE-2023-5568.json'
		with open(cve_path, 'w') as f:
			f.write(json.dumps(fixture.toDict(), indent=2))
		vuln = Vuln.lookup_cve('CVE-2023-5568', 'cpe:/o:redhat:enterprise_linux:9')
		vuln2 = Vuln.lookup_cve('CVE-2023-5568', 'cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*')
		self.assertIn('cpe-match', vuln.tags)
		self.assertIn('cpe-match', vuln2.tags)


class TestVulnersProvider(unittest.TestCase):

	def setUp(self):
		vulners.lookup_cve.cache_clear()
		CVEProvider.lookup_external_cve.cache_clear()
		self.client = mock.MagicMock()
		self.client.VulnersApi.return_value.search.get_bulletin.return_value = {'id': 'CVE-2023-5568'}
		for patcher in (
				mock.patch.dict('sys.modules', {'vulners': self.client}),
				mock.patch.object(CONFIG.runners, 'skip_cve_search', False),
				mock.patch.object(CONFIG, 'offline_mode', False)):
			patcher.start()
			self.addCleanup(patcher.stop)

	def test_lookup_cve_with_api_key(self):
		with mock.patch.object(CONFIG.addons.vulners, 'api_key', 'test-key'):
			data = CVEProvider.lookup_external_cve('CVE-2023-5568', provider='vulners')
		self.assertEqual(data, {'id': 'CVE-2023-5568'})
		self.client.VulnersApi.assert_called_once_with(api_key='test-key')
		self.client.VulnersApi.return_value.search.get_bulletin.assert_called_once_with('CVE-2023-5568', fields=['*'])

	def test_lookup_cve_without_api_key(self):
		with mock.patch.object(CONFIG.addons.vulners, 'api_key', ''):
			with self.assertRaises(ValueError):
				vulners.lookup_cve('CVE-2023-5568')
		self.client.VulnersApi.assert_not_called()

	def test_lookup_cve_offline(self):
		with mock.patch.object(CONFIG.addons.vulners, 'api_key', 'test-key'), mock.patch.object(CONFIG, 'offline_mode', True):
			self.assertIsNone(vulners.lookup_cve('CVE-2023-5568'))
		self.client.VulnersApi.assert_not_called()


class TestSoftwareVersionExtraction(unittest.TestCase):

	def test_extract_software_and_version(self):
		cases = {
			'Underscore.js 1.13.8': ('underscore.js', '1.13.8'),
			'Socket.io 4.5.1': ('socket.io', '4.5.1'),
			'core-js 3.6.5': ('core-js', '3.6.5'),
			'D3 7.0': ('d3', '7.0'),
			'Nginx 1.18.0': ('nginx', '1.18.0'),
			'Apache HTTP Server 2.4.41': ('apache http server', '2.4.41'),
			'Clipboard.js': (None, None),
			'1.2.3': (None, '1.2.3'),
		}
		for value, expected in cases.items():
			with self.subTest(value=value):
				self.assertEqual(extract_software_and_version(value), expected)

	def test_url_get_techs(self):
		url = Url(url='http://example.com', tech=[
			'Underscore.js:1.13.8',
			'Clipboard.js',
			'Nginx:1.18.0',
			'Apache HTTP Server:2.4.41',
			'PHP:8.1.2',
			'jQuery UI:1.12.1',
			'Bootstrap:4.5.2',
		])
		techs = [(t.product, t.version) for t in url.get_techs()]
		self.assertEqual(techs, [
			('Underscore.js', '1.13.8'),
			('Clipboard.js', None),
			('nginx', '1.18.0'),
			('Apache HTTP Server', '2.4.41'),
			('PHP', '8.1.2'),
			('jQuery UI', '1.12.1'),
			('Bootstrap', '4.5.2'),
		])

import json
import unittest

from pathlib import Path
from unittest import mock

from secator.utils_test import load_fixture, FIXTURES_DIR
from secator.tasks._categories import Vuln
from secator.config import CONFIG


class TestCveHelpers(unittest.TestCase):

	@mock.patch('secator.config.CONFIG.runners.skip_cve_search', False)
	def test_lookup_cve_circle(self):
		fixture = json.dumps(load_fixture('cve_circle_output', FIXTURES_DIR), sort_keys=True)
		cve_path = f'{CONFIG.dirs.data}/cves/CVE-2023-5568.json'
		if Path(cve_path).exists():
			Path(cve_path).unlink()  # make sure we don't use cache data
		actual = Vuln.lookup_cve_from_cve_circle('CVE-2023-5568')
		actual = json.dumps(actual, sort_keys=True)
		self.assertEqual(actual, fixture)

	@mock.patch('secator.config.CONFIG.runners.skip_cve_search', False)
	def test_lookup_cve_from_ghsa_no_cve_id(self):
		actual = Vuln.lookup_cve_from_ghsa('GHSA-ggpf-24jw-3fcw')
		self.assertIsNone(actual)

	@mock.patch('secator.config.CONFIG.runners.skip_cve_search', False)
	def test_lookup_cve_from_ghsa(self):
		actual = Vuln.lookup_cve_from_ghsa('GHSA-w596-4wvx-j9j6')
		self.assertIsNotNone(actual)
		self.assertEqual(actual['id'], 'CVE-2022-42969')

	@mock.patch('secator.config.CONFIG.runners.skip_cve_search', False)
	def test_lookup_cve(self):
		fixture = load_fixture('cve_circle_output', FIXTURES_DIR)
		cve_path = f'{CONFIG.dirs.data}/cves/CVE-2023-5568.json'
		with open(cve_path, 'w') as f:
			f.write(json.dumps(fixture, indent=2))
		vuln = Vuln.lookup_cve('CVE-2023-5568', 'cpe:/o:redhat:enterprise_linux:9')
		vuln2 = Vuln.lookup_cve('CVE-2023-5568', 'cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*')
		self.assertIn('cpe-match', vuln['tags'])
		self.assertIn('cpe-match', vuln2['tags'])

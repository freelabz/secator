import json
import os
import unittest

from secator.utils_test import load_fixture, FIXTURES_DIR
from secator.tasks._categories import Vuln
from secator.providers.circl import circl
from secator.config import CONFIG


class TestCveHelpers(unittest.TestCase):

	def test_lookup_cve_circle(self):
		actual = circl.lookup_cve('CVE-2023-5568', convert=False)
		self.assertIsNone(actual)

	def test_lookup_cve(self):
		fixture = load_fixture('cve_circle_output', FIXTURES_DIR)
		fixture = circl.convert_cve_info(fixture)
		cve_dir = CONFIG.dirs.data / 'cves'
		os.makedirs(cve_dir, exist_ok=True)
		cve_path = cve_dir / 'CVE-2023-5568.json'
		with open(cve_path, 'w') as f:
			f.write(json.dumps(fixture.toDict(), indent=2))
		vuln = Vuln.lookup_cve('CVE-2023-5568', 'cpe:/o:redhat:enterprise_linux:9')
		vuln2 = Vuln.lookup_cve('CVE-2023-5568', 'cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*')
		self.assertIn('cpe-match', vuln.tags)
		self.assertIn('cpe-match', vuln2.tags)

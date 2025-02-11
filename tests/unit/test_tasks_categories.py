import json
import unittest

from secator.utils_test import load_fixture, FIXTURES_DIR
from secator.tasks._categories import Vuln
from secator.config import CONFIG


class TestSerializers(unittest.TestCase):

	def test_lookup_cve_circle(self):
		fixture = json.dumps(load_fixture('cve_circle_output', FIXTURES_DIR), sort_keys=True)
		actual = json.dumps(Vuln.lookup_cve_from_cve_circle('CVE-2023-5568'), sort_keys=True)
		self.assertEqual(actual, fixture)

	def test_lookup_cve(self):
		fixture = load_fixture('cve_circle_output', FIXTURES_DIR)
		cve_path = f'{CONFIG.dirs.data}/cves/CVE-2023-5568.json'
		with open(cve_path, 'w') as f:
			f.write(json.dumps(fixture, indent=2))
		vuln = Vuln.lookup_cve('CVE-2023-5568', 'cpe:/o:redhat:enterprise_linux:9')
		vuln2 = Vuln.lookup_cve('CVE-2023-5568', 'cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*')
		self.assertIn('cpe-match', vuln['tags'])
		self.assertIn('cpe-match', vuln2['tags'])

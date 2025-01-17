import json
import unittest

from pathlib import Path

from secator.utils_test import load_fixture, FIXTURES_DIR
from secator.tasks._categories import Vuln
from secator.config import CONFIG


class TestSerializers(unittest.TestCase):

	def test_lookup_cve_circle(self):
		fixture = json.dumps(load_fixture('cve_circle_output', FIXTURES_DIR), sort_keys=True)
		cve_path = f'{CONFIG.dirs.data}/cves/CVE-2023-5568.json'
		if Path(cve_path).exists():
			Path(cve_path).unlink()  # make sure we don't use cache data
		actual = json.dumps(Vuln.lookup_cve_from_cve_circle('CVE-2023-5568'), sort_keys=True)
		self.assertEqual(actual, fixture)

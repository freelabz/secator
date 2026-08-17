import unittest
from unittest.mock import patch

import secator.kev as kev
from secator.output_types import Vulnerability


class TestKevTagging(unittest.TestCase):
	def setUp(self):
		# Reset the process-wide cache before each test so patches take effect.
		kev._KEV_CVE_IDS = None

	def tearDown(self):
		kev._KEV_CVE_IDS = None

	@patch('secator.kev._load_kev_cve_ids', return_value={'CVE-2021-44228'})
	def test_kev_tag_added_when_cve_in_catalog(self, _):
		vuln = Vulnerability(name='Log4Shell', id='CVE-2021-44228')
		self.assertIn('kev', vuln.tags)

	@patch('secator.kev._load_kev_cve_ids', return_value={'CVE-2021-44228'})
	def test_kev_tag_case_insensitive(self, _):
		vuln = Vulnerability(name='Log4Shell', id='cve-2021-44228')
		self.assertIn('kev', vuln.tags)

	@patch('secator.kev._load_kev_cve_ids', return_value={'CVE-2021-44228'})
	def test_kev_tag_not_added_when_cve_absent(self, _):
		vuln = Vulnerability(name='Some vuln', id='CVE-2000-0001')
		self.assertNotIn('kev', vuln.tags)

	@patch('secator.kev._load_kev_cve_ids', return_value={'CVE-2021-44228'})
	def test_kev_tag_not_duplicated(self, _):
		vuln = Vulnerability(name='Log4Shell', id='CVE-2021-44228', tags=['kev'])
		self.assertEqual(vuln.tags.count('kev'), 1)

	@patch('secator.kev._load_kev_cve_ids', return_value=set())
	def test_no_tag_when_catalog_unavailable(self, _):
		vuln = Vulnerability(name='Log4Shell', id='CVE-2021-44228')
		self.assertNotIn('kev', vuln.tags)

	def test_no_id_is_noop(self):
		# No CVE id => no network / catalog access at all.
		with patch('secator.kev._load_kev_cve_ids') as mock_load:
			vuln = Vulnerability(name='Generic finding')
			self.assertNotIn('kev', vuln.tags)
			mock_load.assert_not_called()


if __name__ == '__main__':
	unittest.main()

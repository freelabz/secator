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


class TestKevLoading(unittest.TestCase):
	"""_load_kev_cve_ids / bundled-mirror fallback / refresh — all offline (no network)."""

	def setUp(self):
		kev._KEV_CVE_IDS = None

	def tearDown(self):
		kev._KEV_CVE_IDS = None

	def test_parse_uppercases_and_skips_missing_cveid(self):
		data = {'vulnerabilities': [
			{'cveID': 'cve-2021-44228'},
			{'cveID': 'CVE-2000-0001'},
			{'notes': 'no cveId'},
		]}
		self.assertEqual(kev._parse_kev_cve_ids(data), {'CVE-2021-44228', 'CVE-2000-0001'})
		self.assertEqual(kev._parse_kev_cve_ids(None), set())

	def test_bundled_mirror_used_when_live_feed_unavailable(self):
		# download_file returns None (offline / cisa.gov unreachable) => bundled mirror.
		with patch('secator.kev.download_file', return_value=None):
			ids = kev._load_kev_cve_ids()
		self.assertGreater(len(ids), 0)
		self.assertTrue(all(i.startswith('CVE-') and i.isupper() for i in ids))
		# Log4Shell has been in the CISA KEV catalog since 2021.
		self.assertIn('CVE-2021-44228', ids)

	def test_live_feed_preferred_over_bundled(self):
		import json
		import os
		import tempfile
		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tf:
			json.dump({'vulnerabilities': [{'cveID': 'CVE-1999-9999'}]}, tf)
			tmp = tf.name
		try:
			with patch('secator.kev.download_file', return_value=tmp):
				ids = kev._load_kev_cve_ids()
			self.assertEqual(ids, {'CVE-1999-9999'})  # live feed, not the bundled mirror
		finally:
			os.unlink(tmp)

	def test_refresh_kev_busts_memo_and_reloads(self):
		kev._KEV_CVE_IDS = {'STALE'}
		# offline_mode True skips the cache unlink (no filesystem side effect); the
		# feed is unavailable so it reloads from the bundled mirror.
		with patch.object(kev.CONFIG, 'offline_mode', True):
			with patch('secator.kev.download_file', return_value=None):
				ids = kev.refresh_kev()
		self.assertNotIn('STALE', ids)
		self.assertGreater(len(ids), 0)


if __name__ == '__main__':
	unittest.main()

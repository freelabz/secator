import shutil
import tempfile
import unittest
from pathlib import Path
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
		# No CVE id => no catalog access at all.
		with patch('secator.kev._load_kev_cve_ids') as mock_load:
			vuln = Vulnerability(name='Generic finding')
			self.assertNotIn('kev', vuln.tags)
			mock_load.assert_not_called()


class TestKevLoading(unittest.TestCase):
	"""Cache seeding, cache-first reads, and refresh — all offline (no network)."""

	def setUp(self):
		kev._KEV_CVE_IDS = None
		# Isolate from the committed files: copy the real bundle into a throwaway dir and
		# point both the bundle and cache paths there, so refresh() can't touch the mirror.
		self._tmp = Path(tempfile.mkdtemp())
		self._bundle = self._tmp / 'bundle.json'
		shutil.copyfile(kev.BUNDLED_KEV_PATH, self._bundle)
		self._cache = self._tmp / 'cves' / kev.KEV_FILENAME
		self._patches = [
			patch.object(kev, 'BUNDLED_KEV_PATH', self._bundle),
			patch.object(kev, '_cache_path', lambda: self._cache),
		]
		for p in self._patches:
			p.start()
		# Snapshot offline_mode and restore it by hand — patch.object on the pydantic CONFIG
		# restores to the field default (False) instead of the live value, leaking into later
		# tests (e.g. test_offline). `secator test unit` runs with offline_mode=True.
		self._orig_offline = kev.CONFIG.offline_mode

	def tearDown(self):
		kev._KEV_CVE_IDS = None
		kev.CONFIG.offline_mode = self._orig_offline
		for p in self._patches:
			p.stop()
		shutil.rmtree(self._tmp, ignore_errors=True)

	def test_parse_uppercases_and_skips_missing_cveid(self):
		data = {'vulnerabilities': [
			{'cveID': 'cve-2021-44228'},
			{'cveID': 'CVE-2000-0001'},
			{'notes': 'no cveID here'},
		]}
		self.assertEqual(kev._parse_kev_cve_ids(data), {'CVE-2021-44228', 'CVE-2000-0001'})
		self.assertEqual(kev._parse_kev_cve_ids(None), set())

	def test_ensure_seeds_cache_from_bundle(self):
		self.assertFalse(self._cache.exists())
		kev.ensure_kev_cache()
		self.assertTrue(self._cache.exists())  # copied from the bundled mirror

	def test_load_reads_from_cache_no_network(self):
		ids = kev._load_kev_cve_ids()
		self.assertTrue(self._cache.exists())  # seeded on first use
		self.assertTrue(all(i.startswith('CVE-') and i.isupper() for i in ids))
		self.assertIn('CVE-2021-44228', ids)  # Log4Shell, in KEV since 2021

	def test_refresh_downloads_and_writes_bundle_and_cache(self):
		kev.CONFIG.offline_mode = False  # force the download path (CI runs offline by default)
		feed = {'vulnerabilities': [{'cveID': 'CVE-1999-9999'}]}

		class FakeResp:
			def raise_for_status(self):
				pass

			def json(self):
				return feed

		with patch('requests.get', return_value=FakeResp()):
			ids = kev.refresh_kev()
		self.assertEqual(ids, {'CVE-1999-9999'})  # memo busted, reloaded from fresh feed
		self.assertIn('CVE-1999-9999', self._cache.read_text())    # cache updated
		self.assertIn('CVE-1999-9999', self._bundle.read_text())   # bundled mirror updated

	def test_refresh_offline_is_noop(self):
		kev.CONFIG.offline_mode = True
		ids = kev.refresh_kev()  # no download, falls back to the seeded cache
		self.assertIn('CVE-2021-44228', ids)


if __name__ == '__main__':
	unittest.main()

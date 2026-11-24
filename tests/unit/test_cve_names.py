import gzip
import io
import json
import shutil
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

import secator.cve_names as cve_names
from secator.hooks._dedup import compute_duplicate_updates
from secator.output_types import Vulnerability

ROWS = [
	{'id': 'CVE-2020-1350', 'name': 'Microsoft Windows DNS Server Remote Code Execution', 'public_name': 'SIGRed'},
	{'id': 'CVE-2021-44228', 'name': 'Apache Log4j2 Remote Code Execution', 'public_name': 'Log4Shell'},
	{'id': 'CVE-2023-4863', 'name': 'Google Chromium WebP Heap-Based Buffer Overflow'},
	{'id': 'cve-2004-1493', 'name': 'Master of Orion III\t- Buffer\nOverflow'},  # lower-case id, tab/newline
	{'id': 'CVE-2020-13500', 'name': 'Prefix Sibling - Flaw'},  # shares a prefix with CVE-2020-1350
	{'id': 'CVE-1999-0001', 'name': ''},  # no name at all: dropped
	{'id': 'GHSA-xxxx-yyyy-zzzz', 'name': 'Not a CVE'},  # not a CVE: dropped
]
SIGRED = 'SIGRed - Microsoft Windows DNS Server Remote Code Execution'
LOG4SHELL = 'Log4Shell - Apache Log4j2 Remote Code Execution'


def _dataset(rows):
	buf = io.BytesIO()
	with gzip.open(buf, 'wt', encoding='utf-8') as f:
		for row in rows:
			f.write(json.dumps(row) + '\n')
	return buf.getvalue()


class CveNamesTestCase(unittest.TestCase):

	def setUp(self):
		cve_names.reset()
		self._tmp = Path(tempfile.mkdtemp())
		self.path = self._tmp / 'cves' / cve_names.CVE_NAMES_FILENAME
		self._patches = [
			patch.object(cve_names, '_candidate_paths', lambda: [self.path]),
			patch.object(cve_names, 'MIN_ROWS', 1),
		]
		for p in self._patches:
			p.start()
		self._orig_offline = cve_names.CONFIG.offline_mode

	def tearDown(self):
		cve_names.reset()
		cve_names.CONFIG.offline_mode = self._orig_offline
		for p in self._patches:
			p.stop()
		shutil.rmtree(self._tmp, ignore_errors=True)

	def write(self, rows=ROWS):
		tsv, _ = cve_names.build_tsv(_dataset(rows))
		self.path.parent.mkdir(parents=True, exist_ok=True)
		self.path.write_bytes(tsv)
		cve_names.reset()


class TestBuildAndLookup(CveNamesTestCase):

	def test_build_tsv_sorted_clean_and_filtered(self):
		tsv, count = cve_names.build_tsv(_dataset(ROWS))
		lines = tsv.decode().splitlines()
		self.assertEqual(count, 5)
		self.assertEqual(lines, sorted(lines))
		self.assertIn('CVE-2004-1493\tMaster of Orion III - Buffer Overflow\t', lines)
		self.assertFalse(any(line.startswith(('CVE-1999-0001', 'GHSA')) for line in lines))

	def test_build_tsv_rejects_small_dataset(self):
		with patch.object(cve_names, 'MIN_ROWS', 10):
			with self.assertRaises(ValueError):
				cve_names.build_tsv(_dataset(ROWS))

	def test_lookup_combines_public_name(self):
		self.write()
		self.assertEqual(
			cve_names.get_cve_name('CVE-2020-1350'), SIGRED)
		self.assertEqual(cve_names.get_cve_name('cve-2021-44228'), LOG4SHELL)
		self.assertEqual(cve_names.get_cve_name('CVE-2023-4863'), 'Google Chromium WebP Heap-Based Buffer Overflow')
		self.assertEqual(cve_names.get_cve_name('CVE-2020-13500'), 'Prefix Sibling - Flaw')
		self.assertEqual(cve_names.get_cve_name('CVE-2004-1493'), 'Master of Orion III - Buffer Overflow')
		self.assertEqual(cve_names.lookup('CVE-2020-1350')['name'], 'Microsoft Windows DNS Server Remote Code Execution')

	def test_lookup_misses(self):
		self.write()
		for cve_id in ('CVE-2099-0001', 'CVE-1999-0001', 'CVE-0000-0000', 'CVE-9999-99999', '', 'GHSA-xxxx-yyyy-zzzz'):
			self.assertEqual(cve_names.get_cve_name(cve_id), '', cve_id)

	def test_lookup_every_row_of_a_large_file(self):
		rows = [
			{'id': f'CVE-20{y:02d}-{n}', 'name': f'Product {y} {n} - Flaw'}
			for y in range(0, 25) for n in range(1000, 1400)
		]
		self.write(rows)
		for row in rows:
			self.assertEqual(cve_names.get_cve_name(row['id']), row['name'])
		self.assertEqual(cve_names.count(), len(rows))

	def test_lookup_does_not_load_the_file_in_memory(self):
		rows = [{'id': f'CVE-20{y:02d}-{n}', 'name': f'Some Vendor Product {n} - Remote Code Execution'} for y in range(10, 25) for n in range(10000, 20000)]  # noqa: E501
		self.write(rows)
		self.assertGreater(self.path.stat().st_size, 5_000_000)
		tracemalloc.start()
		try:
			for n in range(10000, 12000):
				self.assertTrue(cve_names.get_cve_name(f'CVE-2020-{n}'))
			_, peak = tracemalloc.get_traced_memory()
		finally:
			tracemalloc.stop()
		self.assertLess(peak, 512 * 1024)  # file is memory-mapped, never read into the heap

	def test_no_file_is_noop(self):
		self.assertFalse(self.path.exists())
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), '')
		self.assertEqual(cve_names.count(), 0)

	def test_missing_file_is_retried_later(self):
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), '')  # no file: remembered
		self.write()
		cve_names._INDEX = False  # write() resets; simulate the remembered failure
		cve_names._INDEX_FAILED_AT = cve_names.time.monotonic()
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), '')  # not retried yet
		cve_names._INDEX_FAILED_AT -= cve_names.RETRY_SECONDS
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), SIGRED)

	def test_crlf_file(self):
		self.path.parent.mkdir(parents=True)
		self.path.write_bytes(b'CVE-2020-1350\tName\t\r\nCVE-2020-1351\tOther\tAlias\r\n')
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), 'Name')
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1351'), 'Alias - Other')

	def test_empty_file_is_noop(self):
		self.path.parent.mkdir(parents=True)
		self.path.write_bytes(b'')
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), '')


class TestRefresh(CveNamesTestCase):

	def test_refresh_downloads_converts_and_replaces(self):
		cve_names.CONFIG.offline_mode = False
		self.write([{'id': 'CVE-2020-1350', 'name': 'Old'}])
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), 'Old')  # opens the old file
		with patch('secator.data_files.download_bytes', return_value=_dataset(ROWS)):
			self.assertEqual(cve_names.refresh_cve_names(), (5, ''))
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), SIGRED)  # memo reset, new file

	def test_refresh_keeps_file_on_bad_download(self):
		cve_names.CONFIG.offline_mode = False
		self.write()
		with patch('secator.data_files.download_bytes', side_effect=OSError('network down')):
			self.assertEqual(cve_names.refresh_cve_names(), (5, 'network down'))
		with patch('secator.data_files.download_bytes', return_value=b'not gzip'):
			nb, error = cve_names.refresh_cve_names()
			self.assertEqual(nb, 5)
			self.assertTrue(error)
		too_small = patch.object(cve_names, 'MIN_ROWS', 100)
		with too_small, patch('secator.data_files.download_bytes', return_value=_dataset(ROWS)):
			self.assertEqual(cve_names.refresh_cve_names()[0], 5)  # too small: rejected
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), SIGRED)

	def test_refresh_offline_does_not_download(self):
		cve_names.CONFIG.offline_mode = True
		with patch('secator.data_files.download_bytes') as download:
			self.assertEqual(cve_names.refresh_cve_names(), (0, 'offline mode'))
			download.assert_not_called()


class TestBundleAndCache(unittest.TestCase):

	def setUp(self):
		cve_names.reset()
		self._tmp = Path(tempfile.mkdtemp())
		self.bundle = self._tmp / 'pkg' / 'data' / cve_names.CVE_NAMES_FILENAME
		self.cache = self._tmp / 'cves' / cve_names.CVE_NAMES_FILENAME
		self._patches = [
			patch.object(cve_names, 'BUNDLED_CVE_NAMES_PATH', self.bundle),
			patch.object(cve_names, 'MIN_ROWS', 1),
		]
		for p in self._patches:
			p.start()
		config = cve_names.CONFIG
		self._orig = (config.cve_names.path, config.dirs.cves, config.offline_mode)
		config.cve_names.path, config.dirs.cves, config.offline_mode = '', str(self.cache.parent), False

	def tearDown(self):
		cve_names.reset()
		config = cve_names.CONFIG
		config.cve_names.path, config.dirs.cves, config.offline_mode = self._orig
		for p in reversed(self._patches):
			p.stop()
		shutil.rmtree(self._tmp, ignore_errors=True)

	def _write(self, path, rows):
		path.parent.mkdir(parents=True, exist_ok=True)
		path.write_bytes(cve_names.build_tsv(_dataset(rows))[0])

	def test_reads_the_bundled_file(self):
		self._write(self.bundle, ROWS)
		self.assertEqual(cve_names.cve_names_path(), self.bundle)
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), SIGRED)

	def test_reads_the_larger_file(self):
		self._write(self.bundle, ROWS[:1])
		self._write(self.cache, ROWS)  # refreshed later: append-only, so larger
		self.assertEqual(cve_names.cve_names_path(), self.cache)
		self.assertEqual(cve_names.get_cve_name('CVE-2021-44228'), LOG4SHELL)
		self._write(self.bundle, ROWS + [{'id': 'CVE-2024-0001', 'name': 'Newer - Flaw'}])  # newer release
		self.assertEqual(cve_names.cve_names_path(), self.bundle)

	def test_path_config_is_the_only_file(self):
		self._write(self.bundle, ROWS)
		other = self._tmp / 'other.tsv'
		cve_names.CONFIG.cve_names.path = str(other)
		self.assertEqual(cve_names.cve_names_path(), other)
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), '')

	def test_refresh_writes_the_bundled_file(self):
		with patch('secator.data_files.download_bytes', return_value=_dataset(ROWS)):
			self.assertEqual(cve_names.refresh_cve_names(), (5, ''))
		self.assertTrue(self.bundle.exists())
		self.assertFalse(self.cache.exists())

	def test_refresh_falls_back_to_the_cache_when_bundle_is_read_only(self):
		from secator import data_files
		real_write = data_files.atomic_write_bytes

		def write(path, data):
			if Path(path) == self.bundle:
				raise PermissionError('read-only')
			return real_write(path, data)

		download = patch('secator.data_files.download_bytes', return_value=_dataset(ROWS))
		with download, patch('secator.data_files.atomic_write_bytes', side_effect=write):
			self.assertEqual(cve_names.refresh_cve_names(), (5, ''))
		self.assertFalse(self.bundle.exists())
		self.assertEqual(cve_names.cve_names_path(), self.cache)
		self.assertEqual(cve_names.get_cve_name('CVE-2020-1350'), SIGRED)


class TestUpdateDataOnly(unittest.TestCase):

	def setUp(self):
		self._orig_offline = cve_names.CONFIG.offline_mode

	def tearDown(self):
		cve_names.CONFIG.offline_mode = self._orig_offline

	def test_offline_warns_and_succeeds(self):
		from click.testing import CliRunner
		from secator.cli import cli
		cve_names.CONFIG.offline_mode = True
		with patch('secator.cve_names.refresh_cve_names') as refresh:
			result = CliRunner().invoke(cli, ['update', '--data-only'])
		self.assertEqual(result.exit_code, 0, result.output)
		self.assertIn('Offline mode', result.output)
		refresh.assert_not_called()

	def test_failed_refresh_exits_non_zero(self):
		from click.testing import CliRunner
		from secator.cli import cli
		cve_names.CONFIG.offline_mode = False
		kev_ok = patch('secator.kev.refresh_kev', return_value=(set(), ''))
		with kev_ok, patch('secator.cve_names.refresh_cve_names', return_value=(5, 'network down')):
			result = CliRunner().invoke(cli, ['update', '--data-only'])
		self.assertEqual(result.exit_code, 1, result.output)
		self.assertIn('network down', result.output)


class TestVulnerabilityNaming(CveNamesTestCase):

	def setUp(self):
		super().setUp()
		self.write()

	def test_names_when_name_equals_id(self):
		self.assertEqual(Vulnerability(name='CVE-2020-1350', id='CVE-2020-1350').name, SIGRED)
		self.assertEqual(Vulnerability(name='cve-2023-4863', id='CVE-2023-4863').name,
			'Google Chromium WebP Heap-Based Buffer Overflow')

	def test_names_when_name_empty(self):
		self.assertEqual(Vulnerability(name='', id='CVE-2021-44228').name, LOG4SHELL)

	def test_keeps_a_readable_name(self):
		vuln = Vulnerability(name='Apache Log4j RCE', id='CVE-2021-44228')
		self.assertEqual(vuln.name, 'Apache Log4j RCE')
		self.assertEqual(vuln.id, 'CVE-2021-44228')

	def test_keeps_unlisted_and_non_cve(self):
		self.assertEqual(Vulnerability(name='CVE-2099-0001', id='CVE-2099-0001').name, 'CVE-2099-0001')
		self.assertEqual(Vulnerability(name='GHSA-xxxx-yyyy-zzzz', id='GHSA-xxxx-yyyy-zzzz').name, 'GHSA-xxxx-yyyy-zzzz')
		self.assertEqual(Vulnerability(name='Weak cipher').name, 'Weak cipher')

	def test_reload_is_stable(self):
		vuln = Vulnerability(name='CVE-2020-1350', id='CVE-2020-1350', matched_at='host:53')
		reloaded = Vulnerability.load(vuln.toDict())
		self.assertEqual(reloaded.name, SIGRED)
		self.assertEqual(reloaded, vuln)

	def test_no_file_keeps_id_as_name(self):
		self.path.unlink()
		cve_names.reset()
		self.assertEqual(Vulnerability(name='CVE-2020-1350', id='CVE-2020-1350').name, 'CVE-2020-1350')


class TestDedupUnchanged(CveNamesTestCase):

	def setUp(self):
		super().setUp()
		self.write()

	def _vuln(self, uuid, name, **kwargs):
		return Vulnerability(name=name, id='CVE-2020-1350', matched_at='host:53', _uuid=uuid, **kwargs)

	def test_already_named_finding_dedups_with_new_one(self):
		prev = self._vuln('prev', SIGRED, status='ACKNOWLEDGED')
		new = self._vuln('new', 'CVE-2020-1350')  # a tool reporting the bare id
		self.assertEqual(new.name, SIGRED)
		self.assertEqual(prev._compare_key(), new._compare_key())
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		self.assertEqual(updates['new']['status'], 'ACKNOWLEDGED')
		self.assertIn('prev', updates['new']['_related'])

	def test_readable_tool_name_stays_a_separate_finding(self):
		named = self._vuln('a', 'Windows DNS Server RCE')
		bare = self._vuln('b', 'CVE-2020-1350')
		self.assertEqual(named.name, 'Windows DNS Server RCE')
		self.assertNotEqual(named._compare_key(), bare._compare_key())


if __name__ == '__main__':
	unittest.main()

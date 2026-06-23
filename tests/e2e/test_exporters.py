"""End-to-end tests for secator exporters.

Runs httpx against a live target and verifies that each exporter produces
correctly structured output files.  Console and Table exporters write to
stdout only, so those tests just verify no exception is raised.

Notes:
    - 'gdrive' exporter requires Google Drive credentials and is skipped.
    - 'markdown' is not a supported exporter name; 'table' uses Markdown
      headings and is the functional equivalent.
"""

import csv as _csv
import json
import os
import shutil
import tempfile
import unittest
import warnings
from pathlib import Path

from secator.utils_test import TEST_TASKS

TEST_URL = 'https://wikipedia.org'
TEST_HOST = 'wikipedia.org'
RUN_OPTS = {'tls_grab': True}


class TestExporters(unittest.TestCase):
	"""Test every built-in exporter produces correct output for a live httpx run."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx
		cls.httpx_cls = httpx
		cls.skip_all = httpx not in TEST_TASKS
		cls.tmpdir = tempfile.mkdtemp(prefix='secator_e2e_exporters_')

	@classmethod
	def tearDownClass(cls):
		if hasattr(cls, 'tmpdir') and os.path.exists(cls.tmpdir):
			shutil.rmtree(cls.tmpdir, ignore_errors=True)

	# ------------------------------------------------------------------ #
	# Helpers                                                              #
	# ------------------------------------------------------------------ #

	def _run_with_exporter(self, exporter_name):
		"""Run httpx with *exporter_name* and return ``(results, output_folder)``.

		Args:
			exporter_name (str): Comma-separated exporter name(s).

		Returns:
			tuple[list, str]: Runner results and path to the output folder.
		"""
		if self.__class__.skip_all:
			self.skipTest('httpx not in TEST_TASKS')
		output_folder = os.path.join(self.tmpdir, f'test_{exporter_name.replace(",", "_")}')
		os.makedirs(output_folder, exist_ok=True)
		run_opts = {
			'sync': True,
			'enable_reports': True,
			'output': exporter_name,
			'reports_folder': output_folder,
			**RUN_OPTS,
		}
		runner = self.__class__.httpx_cls(TEST_URL, **run_opts)
		results = runner.run()
		return results, output_folder

	# ------------------------------------------------------------------ #
	# Individual exporter tests                                            #
	# ------------------------------------------------------------------ #

	def test_csv_exporter_creates_files(self):
		"""CSV exporter creates report_<type>.csv with a header and at least one data row."""
		results, folder = self._run_with_exporter('csv')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		csv_files = list(Path(folder).glob('report_*.csv'))
		self.assertGreater(len(csv_files), 0, f'No CSV files found in {folder}')
		for csv_path in csv_files:
			with open(csv_path, newline='') as f:
				rows = list(_csv.reader(f))
			self.assertGreater(
				len(rows), 1,
				f'{csv_path.name}: expected header + data rows, got {len(rows)} rows',
			)
			self.assertGreater(len(rows[0]), 0, f'{csv_path.name}: header row is empty')

	def test_json_exporter_creates_report(self):
		"""JSON exporter creates report.json with valid ``info`` and ``results`` keys."""
		results, folder = self._run_with_exporter('json')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		json_path = Path(folder) / 'report.json'
		self.assertTrue(json_path.exists(), f'report.json not found in {folder}')
		data = json.loads(json_path.read_text())
		self.assertIn('info', data, 'report.json must contain an "info" key')
		self.assertIn('results', data, 'report.json must contain a "results" key')
		self.assertIsInstance(data['results'], dict)
		total = sum(len(v) for v in data['results'].values())
		self.assertGreater(total, 0, 'report.json "results" must contain at least one entry')

	def test_txt_exporter_creates_files(self):
		"""TXT exporter creates report_<type>.txt files with at least one line each."""
		results, folder = self._run_with_exporter('txt')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		txt_files = list(Path(folder).glob('report_*.txt'))
		self.assertGreater(len(txt_files), 0, f'No TXT files found in {folder}')
		for txt_path in txt_files:
			self.assertGreater(
				len(txt_path.read_text().strip()), 0,
				f'{txt_path.name} is empty',
			)

	def test_table_exporter_no_exception(self):
		"""Table exporter (Markdown-style) renders to console without exceptions."""
		results, _ = self._run_with_exporter('table')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

	def test_console_exporter_no_exception(self):
		"""Console exporter prints items to stdout without exceptions."""
		results, _ = self._run_with_exporter('console')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

	# ------------------------------------------------------------------ #
	# Multi-exporter test                                                  #
	# ------------------------------------------------------------------ #

	def test_multiple_exporters_all_files_created(self):
		"""Running with csv,json,txt creates all expected file types in a single pass."""
		results, folder = self._run_with_exporter('csv,json,txt')
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		self.assertTrue(
			(Path(folder) / 'report.json').exists(),
			f'report.json not found in {folder}',
		)
		self.assertGreater(
			len(list(Path(folder).glob('report_*.csv'))), 0,
			f'No CSV files found in {folder}',
		)
		self.assertGreater(
			len(list(Path(folder).glob('report_*.txt'))), 0,
			f'No TXT files found in {folder}',
		)

	# ------------------------------------------------------------------ #
	# Skipped exporter                                                     #
	# ------------------------------------------------------------------ #

	@unittest.skip('Requires Google Drive credentials (SECATOR_ADDONS_GDRIVE_CREDENTIALS_PATH)')
	def test_gdrive_exporter(self):
		"""GDrive exporter uploads results to Google Sheets (requires credentials)."""
		pass


if __name__ == '__main__':
	unittest.main()

import os
import unittest
from unittest import mock

devnull = open(os.devnull, 'w')
mock_stderr = mock.patch('sys.stderr', devnull)
with mock_stderr:
	from secator.config import download_files, CONFIG
	from secator.utils_test import clear_modules


@mock_stderr
class TestOffline(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		clear_modules()

	def test_cve_lookup(self):
		from secator.tasks._categories import Vuln
		result = Vuln.lookup_cve('CVE-2022-23491')
		self.assertEqual(result, None)

	def test_downloads(self):
		download_files(
			{'pyproject.toml': 'https://raw.githubusercontent.com/freelabz/secator/main/pyproject.toml'},
			CONFIG.dirs.payloads,
			CONFIG.offline_mode,
			'toml file'
		)
		path = CONFIG.dirs.payloads / 'pyproject.toml'
		self.assertFalse(path.exists())

	def test_cli_install(self):
		# TODO: https://github.com/ewels/rich-click/issues/188
		# from secator.config import download_files, CONFIG
		# from secator.cli import cli
		# import click
		# from click.testing import CliRunner
		# result = CliRunner.invoke(cli, None, None)
		pass

	def test_cli(self):
		# TODO: https://github.com/freelabz/secator/issues/319
		# from secator.config import download_files, CONFIG
		pass

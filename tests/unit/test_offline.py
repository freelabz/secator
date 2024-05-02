import os
import unittest

from secator.utils_test import clear_modules


class TestOffline(unittest.TestCase):
	def setUp(self):
		clear_modules()
		os.environ['SECATOR_OFFLINE_MODE'] = '1'

	def test_offline_cve_lookup(self):
		from secator.tasks._categories import Vuln
		result = Vuln.lookup_cve('CVE-2022-23491')
		self.assertEqual(result, None)

	def test_offline_downloads(self):
		from secator.config import download_files, CONFIG
		download_files(
			{'pyproject.toml': 'https://raw.githubusercontent.com/freelabz/secator/main/pyproject.toml'},
			CONFIG.dirs.data,
			CONFIG.offline_mode,
			'toml file'
		)
		path = CONFIG.dirs.data / 'pyproject.toml'
		self.assertFalse(path.exists())

	def test_offline_cli_install(self):
		# TODO: https://github.com/ewels/rich-click/issues/188
		# from secator.cli import cli
		# import click
		# from click.testing import CliRunner
		# result = CliRunner.invoke(cli, None, None)
		pass

	def test_offline_cli(self):
		# TODO: https://github.com/freelabz/secator/issues/319
		pass

"""get_version_info must degrade gracefully when a remote version source is unreachable (#1365)."""
import unittest
from unittest import mock

import requests

from secator.config import CONFIG
from secator.installer import get_version_info


# CI runs with SECATOR_OFFLINE_MODE=1, which skips the remote lookup entirely.
@mock.patch.object(CONFIG, 'offline_mode', False)
class TestGetVersionInfoUnreachable(unittest.TestCase):

	@mock.patch('secator.installer.get_version', return_value='1.2.3')
	@mock.patch('secator.installer.which')
	@mock.patch('secator.installer.requests.get', side_effect=requests.exceptions.SSLError('CERTIFICATE_VERIFY_FAILED'))
	def test_pypi_unreachable_does_not_raise(self, mock_get, mock_which, mock_version):
		mock_which.return_value.output = '/usr/bin/python3'  # any existing path
		info = get_version_info('manspider', version_flag='--version', install_cmd='pipx install manspider')
		self.assertTrue(info['installed'])
		self.assertEqual(info['version'], '1.2.3')
		self.assertIsNone(info['latest_version'])
		self.assertTrue(info['status'].startswith('latest unknown'))
		self.assertIn('unreachable', info['status'])
		self.assertTrue(any('Cannot reach pypi' in e for e in info['errors']))

	@mock.patch('secator.installer.get_version', return_value='0.4.3')
	@mock.patch('secator.installer.which')
	@mock.patch('secator.installer.requests.get')
	def test_pypi_lookup_does_not_clobber_current_version(self, mock_get, mock_which, mock_version):
		mock_which.return_value.output = '/usr/bin/python3'
		mock_get.return_value.status_code = 200
		mock_get.return_value.encoding = 'utf-8'
		mock_get.return_value.text = '{"releases": {"0.4.3": [], "0.5.0": [], "0.6.0rc1": []}}'
		info = get_version_info('dirsearch', version_flag='--version', install_cmd='pipx install dirsearch')
		self.assertEqual(info['version'], '0.4.3')         # current version WAS fetched
		self.assertEqual(info['latest_version'], '0.5.0')  # pre-releases skipped
		self.assertEqual(info['status'], 'outdated')

"""get_version_info must degrade gracefully when a remote version source is unreachable (#1365)."""
import unittest
from unittest import mock

import requests

from secator.config import CONFIG
from secator.installer import get_version_info


class TestGetVersionInfoUnreachable(unittest.TestCase):

	# CI runs with SECATOR_OFFLINE_MODE=1, which skips the remote lookup entirely. Save/restore by
	# hand: mock.patch.object on the pydantic CONFIG restores a bogus value and leaks to other tests.
	def setUp(self):
		self._offline = CONFIG.offline_mode
		CONFIG.offline_mode = False

	def tearDown(self):
		CONFIG.offline_mode = self._offline

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


_CRASH_OUTPUT = '''Traceback (most recent call last):
  File "/usr/lib/python3.12/site-packages/cement/core/foundation.py", line 8, in <module>
    from imp import reload
ModuleNotFoundError: No module named 'imp'
'''


class TestGetVersionInfoCrashedTool(unittest.TestCase):
	"""A tool whose version command dies with a traceback must be reported broken, not installed."""

	def setUp(self):
		self._offline = CONFIG.offline_mode
		CONFIG.offline_mode = True

	def tearDown(self):
		CONFIG.offline_mode = self._offline

	@mock.patch('secator.runners.Command.execute')
	@mock.patch('secator.installer.which')
	def test_traceback_reports_broken(self, mock_which, mock_execute):
		mock_which.return_value.output = __file__
		mock_execute.return_value.output = _CRASH_OUTPUT
		mock_execute.return_value.return_code = 1
		info = get_version_info('droopescan', version_flag='--version', install_version='1.45.1')
		self.assertTrue(info['installed'])
		self.assertTrue(info['broken'])
		self.assertEqual(info['status'], 'broken')
		# The interpreter path in the traceback must NOT be mistaken for the tool version.
		self.assertIsNone(info['version'])
		self.assertTrue(any("No module named 'imp'" in e for e in info['errors']))

	@mock.patch('secator.runners.Command.execute')
	@mock.patch('secator.installer.which')
	def test_clean_version_output_not_broken(self, mock_which, mock_execute):
		mock_which.return_value.output = __file__
		mock_execute.return_value.output = 'tool v1.45.1'
		mock_execute.return_value.return_code = 0
		info = get_version_info('tool', version_flag='--version', install_version='1.45.1')
		self.assertFalse(info['broken'])
		self.assertEqual(info['version'], 'v1.45.1')
		self.assertEqual(info['status'], 'latest')

	@mock.patch('secator.runners.Command.execute')
	@mock.patch('secator.installer.which')
	def test_handled_traceback_with_success_exit_not_broken(self, mock_which, mock_execute):
		# A tool that logs a handled traceback but exits 0 and prints its version is healthy.
		mock_which.return_value.output = __file__
		mock_execute.return_value.output = _CRASH_OUTPUT + 'tool v1.45.1\n'
		mock_execute.return_value.return_code = 0
		info = get_version_info('tool', version_flag='--version', install_version='1.45.1')
		self.assertFalse(info['broken'])
		self.assertNotEqual(info['status'], 'broken')

	def test_broken_row_formatting(self):
		from secator.installer import fmt_health_table_row
		info = {'name': 'droopescan', 'version': None, 'status': 'broken', 'installed': True, 'latest_version': '1.45.1'}
		_, version_col = fmt_health_table_row(info)
		self.assertIn('broken', version_col)


class TestDroopescanInstallCmd(unittest.TestCase):

	def test_cement_inject_is_forced(self):
		# cement is already a droopescan dependency: without --force, `pipx inject` is a no-op and
		# the cement 2.6.x that imports the removed `imp` module stays installed.
		from secator.tasks.droopescan import droopescan
		self.assertIn('pipx inject --force droopescan cement==2.10.14', droopescan.install_cmd)

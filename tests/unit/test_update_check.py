import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from secator.cli import cli
from secator.config import CONFIG
import secator.kev as kev
from secator.installer import check_updates, warn_github_unreachable
from secator.kev import KEV_FILENAME
from secator.requests import requests


def _resp(payload):
	resp = MagicMock()
	resp.json.return_value = payload
	return resp


class TestCheckUpdates(unittest.TestCase):
	"""check_updates() hints, with the GitHub API mocked."""

	def setUp(self):
		self._tmp = Path(tempfile.mkdtemp())
		self._orig_data = CONFIG.dirs.data
		CONFIG.dirs.data = self._tmp  # holds the once-a-day stamp file
		self._session = MagicMock()
		self._patches = [
			patch('secator.installer.get_session', return_value=self._session),
			patch('secator.installer.get_kev_sha', return_value='local-sha'),
			patch('secator.installer.VERSION', '1.0.0'),
			patch('secator.installer.console'),
		]
		self._console = [p.start() for p in self._patches][-1]
		warn_github_unreachable.cache_clear()  # the warning is printed once per process

	def tearDown(self):
		for p in self._patches:
			p.stop()
		CONFIG.dirs.data = self._orig_data
		shutil.rmtree(self._tmp, ignore_errors=True)

	def _github(self, latest='1.0.0', kev_sha='local-sha'):
		self._session.get.side_effect = [
			_resp({'tag_name': f'v{latest}'}),
			_resp([{'name': KEV_FILENAME, 'sha': kev_sha}, {'name': 'technologies.yaml', 'sha': 'x'}]),
		]

	def _output(self):
		return ' '.join(str(c.args[0].message) for c in self._console.print.call_args_list)

	def test_unreachable_warns_and_suggests_offline_mode(self):
		self._session.get.side_effect = requests.ConnectionError('proxy refused')
		check_updates()
		self.assertIn('GitHub is unreachable', self._output())
		self.assertIn('secator config set offline_mode true', self._output())

	def test_new_version_suggests_update(self):
		self._github(latest='1.1.0', kev_sha='remote-sha')
		check_updates()
		self.assertIn('secator 1.1.0 is available', self._output())
		self.assertIn('secator update', self._output())
		self.assertNotIn('--data-only', self._output())

	def test_data_file_change_suggests_data_only(self):
		self._github(kev_sha='remote-sha')
		check_updates()
		self.assertIn('secator update --data-only', self._output())

	def test_unparsable_version_prints_nothing(self):
		self._github(latest='not-a-version')
		check_updates()
		self._console.print.assert_not_called()

	def test_up_to_date_prints_nothing(self):
		self._github()
		check_updates()
		self._console.print.assert_not_called()

	def test_checks_at_most_once_a_day(self):
		self._github()
		check_updates()
		check_updates()
		self.assertEqual(self._session.get.call_count, 2)  # one release + one data dir request


class TestDataFiles(unittest.TestCase):

	def test_kev_sha_is_git_blob_sha(self):
		data = b'hello\n'
		expected = 'ce013625030ba8dba906f756967f9e9ca394464a'  # git hash-object of 'hello\n'
		self.assertEqual(hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest(), expected)
		with tempfile.TemporaryDirectory() as tmp:
			path = Path(tmp) / KEV_FILENAME
			path.write_bytes(data)
			with patch.object(kev, '_cache_path', lambda: path), patch.object(kev, 'ensure_kev_cache'):
				self.assertEqual(kev.get_kev_sha(), expected)

	def test_refresh_kev_warns_when_unreachable(self):
		orig = CONFIG.offline_mode
		CONFIG.offline_mode = False
		warn_github_unreachable.cache_clear()
		try:
			with patch('requests.get', side_effect=requests.ConnectionError('proxy refused')):
				with patch('secator.installer.console') as console, patch.object(kev, 'get_kev_cve_ids', return_value=set()):
					kev.refresh_kev()
		finally:
			CONFIG.offline_mode = orig
		self.assertIn('GitHub is unreachable', console.print.call_args.args[0].message)

	@patch('secator.cve_names.refresh_cve_names', return_value=(1, ''))
	@patch('secator.kev.refresh_kev', return_value=({'CVE-2021-44228'}, ''))
	@patch('secator.cli.get_version_info')
	def test_update_data_only_skips_secator_update(self, mock_version_info, mock_refresh, _mock_names):
		orig = CONFIG.offline_mode
		CONFIG.offline_mode = False
		try:
			result = CliRunner().invoke(cli, ['update', '--data-only'])
		finally:
			CONFIG.offline_mode = orig
		self.assertEqual(result.exit_code, 0, result.output)
		mock_refresh.assert_called_once()
		mock_version_info.assert_not_called()


class TestStartupCheck(unittest.TestCase):
	"""The CLI runs check_updates() at startup unless disabled by config or offline mode."""

	def setUp(self):
		self._orig = (CONFIG.offline_mode, CONFIG.cli.check_updates)

	def tearDown(self):
		CONFIG.offline_mode, CONFIG.cli.check_updates = self._orig

	def _invoke(self, args=('workspace', '--help')):
		tty_sys = MagicMock(wraps=sys)
		tty_sys.stdout.isatty.return_value = True  # CliRunner output is not a tty: fake one
		with patch('secator.cli.sys', tty_sys), patch('secator.cli.DEV_PACKAGE', False):
			with patch('secator.cli.check_updates') as mock_check:
				CliRunner().invoke(cli, list(args))
		return mock_check

	def test_runs_by_default(self):
		CONFIG.offline_mode, CONFIG.cli.check_updates = False, True
		self._invoke().assert_called_once()

	def test_disabled_by_config(self):
		CONFIG.offline_mode, CONFIG.cli.check_updates = False, False
		self._invoke().assert_not_called()

	def test_disabled_in_offline_mode(self):
		CONFIG.offline_mode, CONFIG.cli.check_updates = True, True
		self._invoke().assert_not_called()

	def test_skipped_for_update(self):
		CONFIG.offline_mode, CONFIG.cli.check_updates = False, True
		self._invoke(('update', '--help')).assert_not_called()


if __name__ == '__main__':
	unittest.main()

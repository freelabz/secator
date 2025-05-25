import tempfile
from click.testing import CliRunner
import os
import unittest
from unittest import mock

from secator.cli import cli
from secator.definitions import VERSION
from secator.installer import InstallerStatus


class TestCli(unittest.TestCase):

	def setUp(self):
		self.runner = CliRunner()
		# Mock installer methods to prevent actual installation
		self.package_installer_patcher = mock.patch('secator.installer.PackageInstaller.install')
		self.source_installer_patcher = mock.patch('secator.installer.SourceInstaller.install')
		
		self.mock_package_installer = self.package_installer_patcher.start()
		self.mock_source_installer = self.source_installer_patcher.start()
		
		# Configure mocks to return success
		self.mock_package_installer.return_value = InstallerStatus.SUCCESS
		self.mock_source_installer.return_value = InstallerStatus.SUCCESS

	def tearDown(self):
		self.package_installer_patcher.stop()
		self.source_installer_patcher.stop()

	def test_cli_version(self):
		result = self.runner.invoke(cli, ['--version'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Current version' in result.output
		assert VERSION in result.output

	def test_task_command(self):
		result = self.runner.invoke(cli, ['task'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Run a task.' in result.output

	def test_workflow_command(self):
		result = self.runner.invoke(cli, ['workflow'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Run a workflow.' in result.output

	def test_scan_command(self):
		result = self.runner.invoke(cli, ['scan'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Run a scan.' in result.output

	# def test_worker_command(self):
	# 	result = self.runner.invoke(cli, ['worker', '--check'])
	# 	assert not result.exception
	# 	assert result.exit_code == 0
	# 	assert 'No Celery worker available' in result.output

	def test_util_proxy_command(self):
		result = self.runner.invoke(cli, ['util', 'proxy', '--timeout', '0.5', '--number', '2'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_util_revshell_command(self):
		result = self.runner.invoke(cli, ['util', 'revshell', '--host', '127.0.0.1', '--port', '9001'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	# @mock.patch('secator.cli.detect_host')
	# def test_util_serve_command(self, mock_detect_host):
	# 	mock_detect_host.return_value = '127.0.0.1'
	# 	with mock.patch('os.listdir', return_value=[]):
	# 		result = self.runner.invoke(cli, ['util', 'serve', '--directory', '.', '--port', '8000'])
	# 		assert not result.exception
	# 		assert result.exit_code == 0
	# 		assert 'Started HTTP server on port 8000' in result.output

	# def test_util_record_command(self):
	# 	with mock.patch('secator.cli.Command.execute', return_value=mock.MagicMock(return_code=0)):
	# 		result = self.runner.invoke(cli, ['util', 'record', 'test_record', '--script', 'test_script.sh'])
	# 		assert not result.exception
	# 		assert result.exit_code == 0

	@mock.patch('secator.cli.DEV_PACKAGE', True)
	def test_util_build_command(self):
		with mock.patch('secator.cli.ADDONS_ENABLED', {'build': True}):
			with mock.patch('secator.cli.Command.execute', return_value=mock.MagicMock(return_code=0)):
				result = self.runner.invoke(cli, ['util', 'build'])
				assert not result.exception
				assert result.exit_code == 0

	@mock.patch('secator.cli.DEV_PACKAGE', True)
	def test_util_publish_command(self):
		with mock.patch('secator.cli.ADDONS_ENABLED', {'build': True}):
			with mock.patch('secator.cli.Command.execute', return_value=mock.MagicMock(return_code=0)):
				with mock.patch.dict(os.environ, {'HATCH_INDEX_AUTH': 'test_token'}):
					result = self.runner.invoke(cli, ['util', 'publish'])
					assert not result.exception
					assert result.exit_code == 0

	def test_config_get_command(self):
		result = self.runner.invoke(cli, ['config', 'get', '--full'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'cli' in result.output
		assert 'dirs' in result.output
		assert 'celery' in result.output
		assert 'runners' in result.output

	def test_config_get_command_deep(self):
		result = self.runner.invoke(cli, ['config', 'get', 'celery.broker_url'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'celery.broker_url' in result.output

	# @mock.patch('secator.config.CONFIG.set')
	# @mock.patch('secator.config.CONFIG.validate')
	# @mock.patch('secator.config.CONFIG.save')
	# def test_config_set_command(self, mock_save, mock_validate, mock_set):
	# 	mock_set.return_value = True
	# 	mock_validate.return_value = True
	# 	mock_save.return_value = True
	# 	result = self.runner.invoke(cli, ['config', 'set', 'debug', 'test'])
	# 	assert not result.exception
	# 	assert result.exit_code == 0
	# 	mock_set.assert_called_once_with('debug', 'test')

	# @mock.patch('click.edit')
	# def test_config_edit_command(self, mock_edit):
	# 	with mock.patch('pathlib.Path.exists', return_value=False):
	# 		with mock.patch('shutil.copyfile', return_value=None):
	# 			result = self.runner.invoke(cli, ['config', 'edit'])
	# 			assert not result.exception
	# 			assert result.exit_code == 0
	# 			mock_edit.assert_called_once()

	def test_config_default_command(self):
		result = self.runner.invoke(cli, ['config', 'default'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'celery' in result.output
		assert 'runners' in result.output
		assert 'cli' in result.output
		assert 'dirs' in result.output

	@mock.patch('secator.cli.list_reports')
	def test_workspace_list_command(self, mock_list_reports):
		mock_list_reports.return_value = []
		result = self.runner.invoke(cli, ['workspace', 'list'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Workspace name' in result.output

	def test_profile_list_command(self):
		result = self.runner.invoke(cli, ['profile', 'list'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Profile name' in result.output

	def test_alias_list_command(self):
		result = self.runner.invoke(cli, ['alias', 'list'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Aliases:' in result.output

	def test_alias_enable_command(self):
		with mock.patch('builtins.open', mock.mock_open()) as mock_file:
			result = self.runner.invoke(cli, ['alias', 'enable'])
			assert not result.exception
			assert result.exit_code == 0
			assert 'Alias file written' in result.output
			mock_file.assert_called_once()

	def test_alias_disable_command(self):
		with mock.patch('builtins.open', mock.mock_open()) as mock_file:
			result = self.runner.invoke(cli, ['alias', 'disable'])
			assert not result.exception
			assert result.exit_code == 0
			assert 'Unalias file written' in result.output
			mock_file.assert_called_once()

	@mock.patch('secator.cli.list_reports')
	def test_report_show_command(self, mock_list_reports):
		mock_list_reports.return_value = []
		tf = tempfile.NamedTemporaryFile(delete=False)
		with open(tf.name, 'w') as f:
			f.write('{"info":{"name":"test", "title": "test"}, "results":{}}')
		result = self.runner.invoke(cli, ['report', 'show', tf.name])
		os.remove(tf.name)
		assert not result.exception
		assert result.exit_code == 0

	@mock.patch('secator.cli.list_reports')
	def test_report_list_command(self, mock_list_reports):
		mock_list_reports.return_value = []
		result = self.runner.invoke(cli, ['report', 'list'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'No reports found' in result.output

	def test_report_export_command(self):
		# Since this would need an actual JSON file, we'll mock the file opening
		with mock.patch('builtins.open', mock.mock_open(read_data='{"info":{"name":"test", "title": "test"}, "results":{}}')), \
			 mock.patch('secator.cli.loads_dataclass', return_value={"info": {"name": "test", "title": "test"}, "results": {}}):
				result = self.runner.invoke(cli, ['report', 'export', 'test.json', '--output', 'console'])
				assert not result.exception
				assert result.exit_code == 0

	@mock.patch('secator.loader.get_configs_by_type')
	def test_install_tools_command(self, mock_get_configs_by_type):
		mock_get_configs_by_type.return_value = []
		result = self.runner.invoke(cli, ['install', 'tools'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_worker_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'worker'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_gdrive_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'gdrive'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_gcs_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'gcs'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_mongodb_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'mongodb'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_redis_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'redis'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_dev_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'dev'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_trace_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'trace'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_addons_build_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'build'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_langs_go_command(self):
		result = self.runner.invoke(cli, ['install', 'langs', 'go'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_install_langs_ruby_command(self):
		result = self.runner.invoke(cli, ['install', 'langs', 'ruby'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	@mock.patch('secator.cli.get_version_info')
	def test_update_command(self, mock_get_version_info):
		mock_get_version_info.return_value = {
			'status': 'latest',
			'latest_version': VERSION
		}
		result = self.runner.invoke(cli, ['update'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

	def test_health_command(self):
		result = self.runner.invoke(cli, ['health'])
		assert result.exit_code == 1
		assert 'Cannot run this command in offline mode' in result.output

if __name__ == '__main__':
	unittest.main()

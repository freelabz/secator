import tempfile
from click.testing import CliRunner
import os
import unittest
from unittest import mock

from secator.cli import cli, _apply_format
from secator.definitions import VERSION
from secator.installer import InstallerStatus


class TestApplyFormat(unittest.TestCase):

	def _make_port(self, ip='1.2.3.4', port=80, service_name='http'):
		return {'ip': ip, 'port': port, 'service_name': service_name, 'host': 'example.com', 'state': 'open'}

	def test_brace_style_no_collision(self):
		"""Test {type.field} format when type name does not collide with a field name."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200}]}
		out = _apply_format(results, '{url.url}')
		self.assertEqual(out, {'url': ['https://example.com']})

	def test_brace_style_type_name_collides_with_field(self):
		"""{port.ip} must return the ip value even though Port has a 'port' int field."""
		results = {'port': [self._make_port(ip='1.2.3.4', port=443)]}
		out = _apply_format(results, '{port.ip}')
		self.assertEqual(out, {'port': ['1.2.3.4']})

	def test_brace_style_accesses_port_number_field(self):
		"""Accessing the 'port' field itself via {port.port} should still work."""
		results = {'port': [self._make_port(ip='1.2.3.4', port=8080)]}
		out = _apply_format(results, '{port.port}')
		self.assertEqual(out, {'port': ['8080']})

	def test_dotpath_style(self):
		"""Legacy dot-path style (port.ip) must continue to work."""
		results = {'port': [self._make_port(ip='10.0.0.1', port=22)]}
		out = _apply_format(results, 'port.ip')
		self.assertEqual(out, {'port': ['10.0.0.1']})

	def test_dotpath_style_field_name_collides_with_type(self):
		"""Dot-path style url.url must return the url string, not a DotMap repr."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200, 'webserver': 'nginx'}]}
		out = _apply_format(results, 'url.url')
		self.assertEqual(out, {'url': ['https://example.com']})

	def test_dotpath_style_non_colliding_field(self):
		"""Dot-path style url.webserver must return the webserver field value."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200, 'webserver': 'nginx'}]}
		out = _apply_format(results, 'url.webserver')
		self.assertEqual(out, {'url': ['nginx']})

	def test_type_only_spec_uses_str_repr(self):
		"""--format url (no dot) should use Url.__str__ (returns the url field), not dict repr."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200, 'host': 'example.com'}]}
		out = _apply_format(results, 'url')
		self.assertEqual(out, {'url': ['https://example.com']})

	def test_type_only_spec_port_uses_str_repr(self):
		"""--format port (no dot) should use Port.__str__ (returns host:port), not dict repr."""
		results = {'port': [self._make_port(ip='1.2.3.4', port=8080)]}
		out = _apply_format(results, 'port')
		# Port.__str__ returns 'host:port'
		self.assertEqual(out, {'port': ['example.com:8080']})

	def test_brace_style_field_only_single_type(self):
		"""Brace-style with direct field names works when only one type is present."""
		results = {'url': [{'url': 'https://example.com', 'host': 'example.com', 'status_code': 200}]}
		out = _apply_format(results, '{url} {host} {status_code}')
		self.assertEqual(out, {'url': ['https://example.com example.com 200']})

	def test_brace_style_field_only_multi_type_warns(self):
		"""Brace-style with direct field names produces no output when multiple types present."""
		results = {
			'url': [{'url': 'https://example.com', 'host': 'example.com', 'status_code': 200}],
			'port': [self._make_port()],
		}
		out = _apply_format(results, '{url} {host} {status_code}')
		self.assertEqual(out, {})

	def test_brace_style_field_only_single_nonempty_type(self):
		"""Brace-style with direct field names works when only one type has non-empty results (simulates -q filter)."""
		results = {
			'url': [{'url': 'https://example.com', 'host': 'example.com', 'port': 443}],
			'port': [],
			'subdomain': [],
			'ip': [],
		}
		out = _apply_format(results, '{url}:{port}')
		self.assertEqual(out, {'url': ['https://example.com:443']})

	def test_plain_field_spec_single_nonempty_type(self):
		"""--format status_code (no dot, no braces) should look up the field on the single non-empty type."""
		results = {
			'url': [{'url': 'https://example.com', 'status_code': 200, 'host': 'example.com'}],
			'port': [],
			'subdomain': [],
		}
		out = _apply_format(results, 'status_code')
		self.assertEqual(out, {'url': ['200']})

	def test_plain_field_spec_multi_nonempty_types_warns(self):
		"""--format status_code warns when multiple non-empty types present (ambiguous)."""
		results = {
			'url': [{'url': 'https://example.com', 'status_code': 200}],
			'port': [{'port': 80, 'status_code': None}],
		}
		out = _apply_format(results, 'status_code')
		self.assertEqual(out, {})

	def test_unknown_type_returns_empty(self):
		results = {'port': [self._make_port()]}
		out = _apply_format(results, '{vulnerability.matched_at}')
		self.assertEqual(out, {})

	def test_pipe_separated_specs(self):
		"""Multiple specs separated by || should each be applied independently."""
		results = {
			'port': [self._make_port(ip='1.2.3.4', port=80)],
			'url': [{'url': 'https://example.com', 'status_code': 200}],
		}
		out = _apply_format(results, '{port.ip} || {url.url}')
		self.assertEqual(out.get('port'), ['1.2.3.4'])
		self.assertEqual(out.get('url'), ['https://example.com'])

	def test_newline_escape_in_format_string(self):
		r"""Literal \n in format string should be converted to actual newlines in output."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200}]}
		out = _apply_format(results, '{url.url}\\nStatus: {url.status_code}')
		self.assertEqual(out, {'url': ['https://example.com\nStatus: 200']})

	def test_tab_escape_in_format_string(self):
		r"""Literal \t in format string should be converted to actual tabs in output."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200}]}
		out = _apply_format(results, '{url.url}\\t{url.status_code}')
		self.assertEqual(out, {'url': ['https://example.com\t200']})

	def test_format_from_file(self):
		"""--format accepts a file path and loads the template from disk."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200}]}
		with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
			f.write('{url.url}')
			tmp_path = f.name
		try:
			out = _apply_format(results, tmp_path)
			self.assertEqual(out, {'url': ['https://example.com']})
		finally:
			os.remove(tmp_path)

	def test_format_from_file_with_newlines(self):
		"""Template files may contain real newlines which should be preserved."""
		results = {'url': [{'url': 'https://example.com', 'status_code': 200}]}
		with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
			f.write('{url.url}\nStatus: {url.status_code}')
			tmp_path = f.name
		try:
			out = _apply_format(results, tmp_path)
			self.assertEqual(out, {'url': ['https://example.com\nStatus: 200']})
		finally:
			os.remove(tmp_path)


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

	# def test_workflow_default_inputs(self):
	# 	"""Test that workflows with default_inputs use them when no input is provided."""
	# 	result = self.runner.invoke(cli, ['workflow', 'cidr_recon', '--dry-run'])
	# 	assert not result.exception
	# 	assert result.exit_code == 0
	# 	assert 'No inputs provided, using default inputs:' in result.output
	# 	assert 'discover' in result.output

	def test_workflow_explicit_input_overrides_default(self):
		"""Test that explicit inputs override default_inputs."""
		result = self.runner.invoke(cli, ['workflow', 'cidr_recon', '10.10.10.0/24', '--dry-run'])
		assert not result.exception
		assert result.exit_code == 0
		assert not 'No inputs provided, using default inputs:' in result.output

	def test_cheatsheet_command(self):
		result = self.runner.invoke(cli, ['cheatsheet'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Some basics' in result.output
		assert 'Aliases' in result.output
		assert 'Configuration' in result.output
		assert 'Quick wins' in result.output

	def test_util_completion_command(self):
		result = self.runner.invoke(cli, ['util', 'completion', '--shell', 'bash'])
		assert not result.exception
		assert result.exit_code == 0
		assert '_secator_completion' in result.output

	def test_util_completion_install_command(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			bashrc_path = os.path.join(tmpdir, '.bashrc')
			with mock.patch('os.path.expanduser', return_value=bashrc_path):
				result = self.runner.invoke(cli, ['util', 'completion', '--shell', 'bash', '--install'])
				assert not result.exception
				assert result.exit_code == 0
				assert 'Completion installed' in result.output
				
				# Verify the completion was actually written
				assert os.path.exists(bashrc_path)
				with open(bashrc_path, 'r') as f:
					content = f.read()
					assert '_SECATOR_COMPLETE=bash_source secator' in content

	def test_util_completion_already_installed(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			bashrc_path = os.path.join(tmpdir, '.bashrc')
			# Pre-populate the bashrc with completion
			with open(bashrc_path, 'w') as f:
				f.write('eval "$(_SECATOR_COMPLETE=bash_source secator)"\n')
			
			with mock.patch('os.path.expanduser', return_value=bashrc_path):
				result = self.runner.invoke(cli, ['util', 'completion', '--shell', 'bash', '--install'])
				assert not result.exception
				assert result.exit_code == 0
				assert 'already installed' in result.output

if __name__ == '__main__':
	unittest.main()

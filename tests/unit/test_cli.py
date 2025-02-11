from click.testing import CliRunner

from secator.cli import cli

import unittest


class TestCli(unittest.TestCase):

	def setUp(self):
		self.runner = CliRunner()

	def test_cli_version(self):
		result = self.runner.invoke(cli, ['--version'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'Current version' in result.output

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
	# 	# Add more assertions based on expected output

	def test_util_proxy_command(self):
		result = self.runner.invoke(cli, ['util', 'proxy', '--timeout', '0.5', '--number', '2'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	def test_util_revshell_command(self):
		result = self.runner.invoke(cli, ['util', 'revshell', '--host', '127.0.0.1', '--port', '9001'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	# def test_util_serve_command(self):
	# 	result = self.runner.invoke(cli, ['util', 'serve', '--directory', '.', '--port', '8000'])
	# 	assert not result.exception
	# 	assert result.exit_code == 0
	# 	# Add more assertions based on expected output

	def test_config_get_command(self):
		result = self.runner.invoke(cli, ['config', 'get'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	def test_config_set_command(self):
		result = self.runner.invoke(cli, ['config', 'set', 'key', 'value'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	def test_report_show_command(self):
		result = self.runner.invoke(cli, ['report', 'show'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	def test_install_addons_worker_command(self):
		result = self.runner.invoke(cli, ['install', 'addons', 'worker'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	def test_health_command(self):
		result = self.runner.invoke(cli, ['health'])
		assert not result.exception
		assert result.exit_code == 0
		# Add more assertions based on expected output

	# Add more tests for other commands as needed

if __name__ == '__main__':
	unittest.main()

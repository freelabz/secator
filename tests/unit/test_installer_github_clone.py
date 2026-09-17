"""SourceInstaller: authenticated GitHub clones + actionable hint on anonymous-clone refusal (#1370)."""
import unittest
from unittest import mock

from secator.installer import InstallerStatus, SourceInstaller


class TestSourceInstallerGithub(unittest.TestCase):

	@mock.patch('secator.installer.console')
	@mock.patch('secator.installer.CONFIG')
	@mock.patch('secator.installer.Command.execute')
	def test_anonymous_clone_refused_prints_hint(self, mock_exec, mock_config, mock_console):
		mock_config.cli.github_token = ''
		mock_exec.return_value.return_code = 128
		mock_exec.return_value.output = "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
		status = SourceInstaller.install('pipx install git+https://github.com/freelabz/MANSPIDER', install_prereqs=False)
		self.assertEqual(status, InstallerStatus.INSTALL_FAILED)
		printed = ' '.join(str(c.args[0].message) for c in mock_console.print.call_args_list)
		self.assertIn('rate limit', printed)
		self.assertIn('SECATOR_CLI_GITHUB_TOKEN', printed)
		self.assertNotIn('extra_env', mock_exec.call_args.kwargs['cls_attributes'])

	@mock.patch('secator.installer.CONFIG')
	@mock.patch('secator.installer.Command.execute')
	def test_github_token_is_passed_via_git_env(self, mock_exec, mock_config):
		mock_config.cli.github_token = 'ghp_secret'
		mock_exec.return_value.return_code = 0
		status = SourceInstaller.install('pipx install git+https://github.com/freelabz/MANSPIDER', install_prereqs=False)
		self.assertEqual(status, InstallerStatus.SUCCESS)
		env = mock_exec.call_args.kwargs['cls_attributes']['extra_env']
		self.assertIn('ghp_secret', env['GIT_CONFIG_KEY_0'])
		self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'https://github.com/')
		self.assertNotIn('ghp_secret', mock_exec.call_args.args[0])  # token never in the printed command

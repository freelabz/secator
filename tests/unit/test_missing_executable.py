"""A task whose executable is missing fails explicitly, before any sudo / privilege check."""
import unittest
from unittest import mock

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command

MISSING_BINARY = 'secator-test-missing-binary-xyz'


@task()
class _missing_privileged_tool(Command):
	"""Tool needing sudo whose binary is not installed, packaged only as an OS package."""
	cmd = MISSING_BINARY
	input_types = None
	install_optional = True
	requires_sudo = True
	install_pre = {
		'apt': ['secator-test-pkg'],
	}


@task()
class _missing_tool_with_installer(Command):
	"""Tool whose binary is not installed, installed by secator from source."""
	cmd = MISSING_BINARY
	input_types = None
	install_cmd = 'true'
	install_pre = {
		'*': ['some-build-dep'],
	}


class TestMissingExecutable(unittest.TestCase):

	def _run(self, cls, auto_install=False):
		with mock.patch.object(CONFIG.security, 'auto_install_commands', auto_install), \
				mock.patch.object(CONFIG.security, 'prompt_sudo_password', True), \
				mock.patch.object(cls, 'is_installed', return_value=False), \
				mock.patch.object(cls, '_prompt_sudo') as prompt_sudo, \
				mock.patch('secator.runners.command.subprocess.Popen') as popen:
			runner = cls('example.com', sync=True, print_item=False, print_line=False)
			list(runner)
		return runner, prompt_sudo, popen

	def _error_messages(self, runner):
		return [e.message for e in runner.errors]

	def test_missing_tool_fails_before_sudo_check(self):
		runner, prompt_sudo, popen = self._run(_missing_privileged_tool)
		prompt_sudo.assert_not_called()
		popen.assert_not_called()
		self.assertEqual(runner.status, 'FAILURE')
		self.assertFalse(runner.skipped)
		messages = self._error_messages(runner)
		self.assertEqual(len(messages), 1, messages)
		self.assertNotIn('password', messages[0].lower())
		self.assertNotIn('tty', messages[0].lower())

	def test_missing_tool_error_names_binary_and_install_hints(self):
		runner, _, _ = self._run(_missing_privileged_tool)
		message = self._error_messages(runner)[0]
		self.assertIn(f'Executable "{MISSING_BINARY}" not found', message)
		self.assertIn('secator install tools _missing_privileged_tool', message)
		self.assertIn('apt: secator-test-pkg', message)

	def test_os_package_hint_only_for_os_package_tools(self):
		runner, _, _ = self._run(_missing_tool_with_installer)
		message = self._error_messages(runner)[0]
		self.assertIn('secator install tools _missing_tool_with_installer', message)
		self.assertNotIn('OS package', message)

	def test_missing_tool_is_not_skipped_or_warned(self):
		runner, _, _ = self._run(_missing_privileged_tool)
		self.assertNotEqual(runner.status, 'SKIPPED')
		self.assertFalse([w for w in runner.warnings if MISSING_BINARY in w.message])

	def test_failed_auto_install_fails_before_sudo_check(self):
		status = mock.Mock(is_ok=mock.Mock(return_value=False))
		with mock.patch('secator.installer.ToolInstaller.install', return_value=status) as install:
			runner, prompt_sudo, popen = self._run(_missing_privileged_tool, auto_install=True)
		install.assert_called_once()
		prompt_sudo.assert_not_called()
		popen.assert_not_called()
		self.assertEqual(runner.status, 'FAILURE')
		message = self._error_messages(runner)[0]
		self.assertIn(f'Failed installing {MISSING_BINARY}', message)
		self.assertIn('secator install tools _missing_privileged_tool', message)

	def test_auto_install_os_error_fails_with_clear_message(self):
		with mock.patch('secator.installer.ToolInstaller.install', side_effect=PermissionError('denied')):
			runner, prompt_sudo, _ = self._run(_missing_privileged_tool, auto_install=True)
		prompt_sudo.assert_not_called()
		self.assertEqual(runner.status, 'FAILURE')
		message = self._error_messages(runner)[0]
		self.assertIn('PermissionError: denied', message)
		self.assertIn(f'Executable "{MISSING_BINARY}" not found', message)

	def test_dublin_traceroute_install_hint(self):
		from secator.tasks import dublin_traceroute
		runner, prompt_sudo, _ = self._run(dublin_traceroute)
		prompt_sudo.assert_not_called()
		message = self._error_messages(runner)[0]
		self.assertIn('Executable "dublin-traceroute" not found', message)
		self.assertIn('secator install tools dublin_traceroute', message)
		self.assertIn('apt: dublin-traceroute', message)

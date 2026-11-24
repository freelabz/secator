"""A task whose executable is missing fails explicitly, before any sudo / privilege check."""
import os
import shutil
import tempfile
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
class _missing_unprivileged_tool(Command):
	"""Tool run without sudo whose binary is not on the user's PATH."""
	cmd = MISSING_BINARY
	input_types = None


@task()
class _missing_tool_with_installer(Command):
	"""Tool whose binary is not installed, installed by secator from source."""
	cmd = MISSING_BINARY
	input_types = None
	install_cmd = 'true'
	install_pre = {
		'*': ['some-build-dep'],
	}


@task()
class _missing_pypi_tool(Command):
	"""Tool whose binary is installed from PyPI, with an OS build dependency."""
	cmd = MISSING_BINARY
	input_types = None
	pypi_dependencies = ['secator-test-pkg']
	install_pre = {
		'apt': ['some-build-dep'],
	}


class TestMissingExecutable(unittest.TestCase):

	def setUp(self):
		patcher = mock.patch.object(Command, '_get_package_manager', return_value='apt')
		self.get_package_manager = patcher.start()
		self.addCleanup(patcher.stop)

	def _run(self, cls, auto_install=False, installed=(False,)):
		with mock.patch.object(CONFIG.security, 'auto_install_commands', auto_install), \
				mock.patch.object(CONFIG.security, 'prompt_sudo_password', True), \
				mock.patch.object(cls, 'is_installed', side_effect=list(installed) * 3), \
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

	def test_failed_auto_install_fails_before_task_sudo_check(self):
		# Scope: the task's own sudo check for launching the tool. The installer is mocked here; what it
		# does to install packages (which may itself use sudo) is the installer's concern.
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

	def test_os_package_hint_not_given_for_pypi_tools(self):
		runner, _, _ = self._run(_missing_pypi_tool)
		message = self._error_messages(runner)[0]
		self.assertIn('secator install tools _missing_pypi_tool', message)
		self.assertNotIn('OS package', message)

	def test_no_package_for_this_platform(self):
		self.get_package_manager.return_value = 'apk'
		runner, prompt_sudo, _ = self._run(_missing_privileged_tool)
		prompt_sudo.assert_not_called()
		self.assertEqual(runner.status, 'FAILURE')
		message = self._error_messages(runner)[0]
		self.assertIn(f'Executable "{MISSING_BINARY}" not found', message)
		self.assertIn('none is configured for this platform\'s package manager (apk)', message)
		self.assertIn('apt: secator-test-pkg', message)
		self.assertNotIn('secator install tools', message)

	def test_no_package_manager_detected(self):
		self.get_package_manager.return_value = None
		runner, _, _ = self._run(_missing_privileged_tool)
		message = self._error_messages(runner)[0]
		self.assertIn('package manager (not detected)', message)
		self.assertIn('apt: secator-test-pkg', message)
		self.assertNotIn('secator install tools', message)

	def test_failed_install_with_binary_present_does_not_claim_not_found(self):
		status = mock.Mock(is_ok=mock.Mock(return_value=False))
		with mock.patch('secator.installer.ToolInstaller.install', return_value=status):
			runner, prompt_sudo, popen = self._run(_missing_privileged_tool, auto_install=True, installed=(False, True))
		prompt_sudo.assert_not_called()
		popen.assert_not_called()
		self.assertEqual(runner.status, 'FAILURE')
		messages = self._error_messages(runner)
		self.assertEqual(messages, [f'Failed installing {MISSING_BINARY}'])


class TestIsInstalled(unittest.TestCase):

	def test_uses_task_env_and_cwd(self):
		runner = _missing_privileged_tool('example.com', sync=True, print_item=False, print_line=False,
			env={'PATH': '/opt/custom/bin'})
		runner.cwd = '/'
		with mock.patch('secator.runners.command.subprocess.Popen') as popen:
			popen.return_value.returncode = 0
			self.assertTrue(runner.is_installed())
		kwargs = popen.call_args.kwargs
		which, binary = popen.call_args.args[0]
		self.assertEqual(os.path.basename(which), 'which')
		self.assertEqual(binary, MISSING_BINARY)
		self.assertEqual(kwargs['env']['PATH'], '/opt/custom/bin')
		self.assertEqual(kwargs['cwd'], '/')

	@unittest.skipUnless(shutil.which('which'), 'needs `which`')
	def test_finds_binary_on_task_path_without_which(self):
		# The task's PATH holds only the tool, not `which`: the lookup must still find it.
		with tempfile.TemporaryDirectory() as bin_dir:
			binary = os.path.join(bin_dir, MISSING_BINARY)
			with open(binary, 'w') as f:
				f.write('#!/bin/sh\n')
			os.chmod(binary, 0o755)
			runner = _missing_privileged_tool('example.com', sync=True, print_item=False, print_line=False,
				env={'PATH': bin_dir})
			self.assertTrue(runner.is_installed())
			runner.run_opts['env'] = {'PATH': tempfile.gettempdir()}
			self.assertFalse(runner.is_installed())


@unittest.skipUnless(shutil.which('which'), 'needs `which`')
class TestIsInstalledWithSudo(unittest.TestCase):
	"""A binary only on sudo's PATH (e.g. /usr/sbin/arp for a standard user) counts as installed for a sudo task."""

	def setUp(self):
		tmp = tempfile.TemporaryDirectory()
		self.addCleanup(tmp.cleanup)
		self.user_bin = os.path.join(tmp.name, 'bin')
		self.sbin = os.path.join(tmp.name, 'sbin')
		os.makedirs(self.user_bin)
		os.makedirs(self.sbin)
		binary = os.path.join(self.sbin, MISSING_BINARY)
		with open(binary, 'w') as f:
			f.write('#!/bin/sh\n')
		os.chmod(binary, 0o755)
		patcher = mock.patch.object(Command, '_sudo_search_path', return_value=self.sbin)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _runner(self, cls):
		return cls('example.com', sync=True, print_item=False, print_line=False, env={'PATH': self.user_bin})

	def test_sudo_task_finds_binary_on_sudo_path(self):
		self.assertTrue(self._runner(_missing_privileged_tool).is_installed())

	def test_non_sudo_task_does_not_use_sudo_path(self):
		self.assertFalse(self._runner(_missing_unprivileged_tool).is_installed())

	def test_sudo_task_missing_everywhere_is_not_installed(self):
		os.remove(os.path.join(self.sbin, MISSING_BINARY))
		self.assertFalse(self._runner(_missing_privileged_tool).is_installed())

	def test_sudo_task_with_binary_on_sudo_path_reaches_sudo_check(self):
		runner = self._runner(_missing_privileged_tool)
		no_tty = mock.patch.object(_missing_privileged_tool, '_prompt_sudo', return_value=(None, 'no tty'))
		with mock.patch.object(CONFIG.security, 'prompt_sudo_password', True), no_tty as prompt_sudo:
			list(runner)
		prompt_sudo.assert_called_once()
		self.assertFalse([e for e in runner.errors if 'not found' in e.message])


class TestSudoSearchPath(unittest.TestCase):

	def test_reads_secure_path_from_sudoers(self):
		sudoers = 'Defaults\tenv_reset\nDefaults\tsecure_path="/opt/sbin:/usr/bin"\n'
		with mock.patch('builtins.open', mock.mock_open(read_data=sudoers)):
			self.assertEqual(Command._sudo_search_path(), '/opt/sbin:/usr/bin')

	def test_unreadable_sudoers_uses_default(self):
		from secator.runners.command import SUDO_DEFAULT_SECURE_PATH
		with mock.patch('builtins.open', side_effect=PermissionError):
			self.assertEqual(Command._sudo_search_path(), SUDO_DEFAULT_SECURE_PATH)
		self.assertIn('/usr/sbin', SUDO_DEFAULT_SECURE_PATH)

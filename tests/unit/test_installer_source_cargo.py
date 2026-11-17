"""SourceInstaller: musl RUSTFLAGS passed via env (not by rewriting the command), and no self-symlink."""
import os
import tempfile
import unittest
from unittest import mock

from secator.installer import InstallerStatus, SourceInstaller

NXC_LIKE_CMD = (
	'sh -c \'if ! command -v cargo >/dev/null 2>&1; then curl https://sh.rustup.rs | sh -s -- -y; fi; '
	'pipx install --force git+https://github.com/Pennyw0rth/NetExec@v1.0.0\''
)
CARGO_CMD = 'cargo install --git https://github.com/freelabz/NFSWolf --tag v1.2.0 nfswolf'


class TestMuslRustflags(unittest.TestCase):

	def test_adds_flag_to_empty(self):
		self.assertEqual(SourceInstaller._musl_rustflags(''), '-Ctarget-feature=-crt-static')

	def test_keeps_existing_flags(self):
		self.assertEqual(SourceInstaller._musl_rustflags('-Copt-level=3'), '-Copt-level=3 -Ctarget-feature=-crt-static')

	def test_does_not_duplicate_flag(self):
		flags = '-Copt-level=3 -Ctarget-feature=-crt-static'
		self.assertEqual(SourceInstaller._musl_rustflags(flags), flags)


@mock.patch.dict(os.environ, {}, clear=False)
@mock.patch('secator.installer.PackageInstaller.install')
@mock.patch('secator.installer.get_distro_config')
@mock.patch('secator.installer.CONFIG')
@mock.patch('secator.installer.Command.execute')
class TestSourceInstallerCargoEnv(unittest.TestCase):

	def _run(self, cmd, pm_name, mock_exec, mock_config, mock_distro, mock_pkg):
		os.environ.pop('RUSTFLAGS', None)
		mock_config.cli.github_token = ''
		mock_distro.return_value.pm_name = pm_name
		mock_distro.return_value.pm_installer = 'installer'
		mock_pkg.return_value.is_ok.return_value = True
		mock_exec.return_value.return_code = 0
		status = SourceInstaller.install(cmd)
		self.assertEqual(status, InstallerStatus.SUCCESS)
		return mock_exec.call_args  # last call: the tool's install command (after the rustup bootstrap)

	def test_apk_command_string_is_not_rewritten(self, *mocks):
		call = self._run(NXC_LIKE_CMD, 'apk', *mocks)
		self.assertEqual(call.args[0], NXC_LIKE_CMD)
		self.assertNotIn('RUSTFLAGS', call.args[0])
		self.assertEqual(call.kwargs['cls_attributes']['extra_env']['RUSTFLAGS'], '-Ctarget-feature=-crt-static')

	def test_apk_cargo_install_gets_rustflags_via_env(self, *mocks):
		call = self._run(CARGO_CMD, 'apk', *mocks)
		self.assertEqual(call.args[0], CARGO_CMD)
		self.assertEqual(call.kwargs['cls_attributes']['extra_env']['RUSTFLAGS'], '-Ctarget-feature=-crt-static')

	def test_non_apk_sets_no_rustflags(self, *mocks):
		call = self._run(CARGO_CMD, 'apt', *mocks)
		self.assertEqual(call.args[0], CARGO_CMD)
		self.assertNotIn('RUSTFLAGS', call.kwargs['cls_attributes'].get('extra_env', {}))

	def test_rustflags_merged_with_github_token_env(self, mock_exec, mock_config, *rest):
		mock_config.cli.github_token = 'ghp_secret'
		# _run resets the token, so drive it inline
		os.environ.pop('RUSTFLAGS', None)
		mock_distro, mock_pkg = rest
		mock_distro.return_value.pm_name = 'apk'
		mock_distro.return_value.pm_installer = 'installer'
		mock_pkg.return_value.is_ok.return_value = True
		mock_exec.return_value.return_code = 0
		SourceInstaller.install(CARGO_CMD)
		env = mock_exec.call_args.kwargs['cls_attributes']['extra_env']
		self.assertEqual(env['RUSTFLAGS'], '-Ctarget-feature=-crt-static')
		self.assertIn('ghp_secret', env['GIT_CONFIG_KEY_0'])


@mock.patch('secator.installer.console')
class TestSymlinkBinary(unittest.TestCase):

	def setUp(self):
		self.tmp = tempfile.TemporaryDirectory()
		self.bin = os.path.join(self.tmp.name, 'nfswolf')
		with open(self.bin, 'w') as f:
			f.write('binary')

	def tearDown(self):
		self.tmp.cleanup()

	def test_same_path_keeps_binary(self, _console):
		SourceInstaller._symlink_binary(self.bin, self.bin)
		self.assertFalse(os.path.islink(self.bin))
		with open(self.bin) as f:
			self.assertEqual(f.read(), 'binary')

	def test_equivalent_path_keeps_binary(self, _console):
		other = os.path.join(self.tmp.name, '.', 'nfswolf')
		SourceInstaller._symlink_binary(self.bin, other)
		self.assertFalse(os.path.islink(self.bin))

	def test_existing_link_to_source_is_left_alone(self, _console):
		link = os.path.join(self.tmp.name, 'link')
		os.symlink(self.bin, link)
		SourceInstaller._symlink_binary(self.bin, link)
		self.assertEqual(os.readlink(link), self.bin)

	def test_different_target_is_symlinked(self, _console):
		target = os.path.join(self.tmp.name, 'target')
		SourceInstaller._symlink_binary(self.bin, target)
		self.assertTrue(os.path.islink(target))
		self.assertEqual(os.readlink(target), self.bin)

	def test_stale_target_is_replaced(self, _console):
		target = os.path.join(self.tmp.name, 'target')
		with open(target, 'w') as f:
			f.write('old')
		SourceInstaller._symlink_binary(self.bin, target)
		self.assertEqual(os.readlink(target), self.bin)

"""Installer override correctness tests (issue #1496).

Three behaviours exercised against the real ``apply_install_overrides`` helper in ``secator.cli``:

1. The ``v`` prefix is only prepended to a bare semver string (digits + dots). Branch names
   (e.g. ``main``), commit SHAs, and already ``v``-prefixed versions are left untouched
   (the ``@vmain`` failure from #1496).
2. ``secator config set tasks.overrides.<tool>.install_version <ver>`` is honoured by
   ``secator install tools`` (the per-class override is applied before installation), with a
   CLI-supplied version (``<tool>==<ver>``) still taking priority.
3. ``secator config set tasks.overrides.<tool>.install_cmd "<cmd>"`` is honoured the same way:
   the overridden command replaces the built-in ``install_cmd`` before installation.
"""
import unittest
from unittest import mock

from secator.cli import apply_install_overrides


def _make_cls(name='FakeTool', install_version='v1.0.0', install_cmd='go install example.com/tool@[install_version]'):
	"""Return a minimal fake task class with the attributes the installer reads."""
	return type(name, (), {
		'install_version': install_version,
		'install_cmd': install_cmd,
	})


class _FakeOverrides:
	"""Minimal stand-in for CONFIG.tasks.overrides (only ``.get`` is used by the helper)."""
	def __init__(self, data):
		self._data = data

	def get(self, name, default=None):
		return self._data.get(name, default if default is not None else {})


def _patch_overrides(overrides):
	"""Patch ``secator.cli.CONFIG`` so ``CONFIG.tasks.overrides`` returns the given per-tool dict.

	``CONFIG.tasks.overrides`` is a nested Config object that returns a fresh instance on each
	attribute access, so we swap the whole ``CONFIG`` for a lightweight namespace.
	"""
	from types import SimpleNamespace
	fake_config = SimpleNamespace(tasks=SimpleNamespace(overrides=_FakeOverrides(overrides)))
	return mock.patch('secator.cli.CONFIG', fake_config)


# ---------------------------------------------------------------------------
# Bug 1 - v-prepend logic
# ---------------------------------------------------------------------------

class TestVersionPrepend(unittest.TestCase):

	def _resolve(self, cli_version, class_version):
		cls = _make_cls(install_version=class_version)
		with _patch_overrides({}):
			apply_install_overrides(cls, cli_version=cli_version)
		return cls.install_version

	def test_bare_semver_gets_v_when_class_version_prefixed(self):
		self.assertEqual(self._resolve('1.2.3', 'v1.0.0'), 'v1.2.3')

	def test_bare_semver_no_v_when_class_version_not_prefixed(self):
		self.assertEqual(self._resolve('1.2.3', '1.0.0'), '1.2.3')

	def test_v_prefixed_version_is_not_double_prefixed(self):
		self.assertEqual(self._resolve('v1.2.3', 'v1.0.0'), 'v1.2.3')

	def test_branch_name_main_is_not_prefixed(self):
		self.assertEqual(self._resolve('main', 'v1.0.0'), 'main')

	def test_branch_name_develop_is_not_prefixed(self):
		self.assertEqual(self._resolve('develop', 'v1.0.0'), 'develop')

	def test_commit_sha_is_not_prefixed(self):
		sha = 'a' * 40
		self.assertEqual(self._resolve(sha, 'v1.0.0'), sha)

	def test_short_commit_sha_is_not_prefixed(self):
		self.assertEqual(self._resolve('abc1234', 'v1.0.0'), 'abc1234')

	def test_no_class_version_bare_semver_unchanged(self):
		self.assertEqual(self._resolve('2.0.0', None), '2.0.0')


# ---------------------------------------------------------------------------
# Bug 2 - install_version config override honoured during install
# ---------------------------------------------------------------------------

class TestInstallVersionConfigOverride(unittest.TestCase):

	def test_config_override_sets_install_version_on_class(self):
		cls = _make_cls(install_version='v1.0.0')
		with _patch_overrides({'FakeTool': {'install_version': 'main'}}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_version, 'main')

	def test_config_override_bare_semver_gets_v_prefix(self):
		cls = _make_cls(install_version='v1.0.0')
		with _patch_overrides({'FakeTool': {'install_version': '2.5.0'}}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_version, 'v2.5.0')

	def test_cli_version_takes_priority_over_config_override(self):
		cls = _make_cls(install_version='v1.0.0')
		with _patch_overrides({'FakeTool': {'install_version': 'main'}}):
			apply_install_overrides(cls, cli_version='develop')
		self.assertEqual(cls.install_version, 'develop')

	def test_no_override_leaves_class_version_untouched(self):
		cls = _make_cls(install_version='v3.1.4')
		with _patch_overrides({}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_version, 'v3.1.4')


# ---------------------------------------------------------------------------
# install_cmd config override honoured during install
# ---------------------------------------------------------------------------

class TestInstallCmdConfigOverride(unittest.TestCase):

	def test_config_override_sets_install_cmd_on_class(self):
		"""tasks.overrides.<tool>.install_cmd replaces the built-in install_cmd."""
		cls = _make_cls(install_cmd='go install example.com/tool@[install_version]')
		custom = 'pipx install my-fork-of-tool'
		with _patch_overrides({'FakeTool': {'install_cmd': custom}}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_cmd, custom)

	def test_no_override_leaves_install_cmd_untouched(self):
		original = 'go install example.com/tool@[install_version]'
		cls = _make_cls(install_cmd=original)
		with _patch_overrides({}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_cmd, original)

	def test_custom_install_cmd_without_placeholder_still_applies_version(self):
		"""A custom install_cmd that ignores [install_version] must not break version pinning."""
		cls = _make_cls(install_cmd='apt-get install -y mytool', install_version='v1.0.0')
		with _patch_overrides({'FakeTool': {'install_cmd': 'apt-get install -y mytool', 'install_version': '2.0.0'}}):
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_cmd, 'apt-get install -y mytool')
		self.assertEqual(cls.install_version, 'v2.0.0')

	def test_install_cmd_and_version_override_together(self):
		cls = _make_cls(install_cmd='go install old@[install_version]', install_version='v1.0.0')
		with _patch_overrides({'FakeTool': {'install_cmd': 'go install new@[install_version]', 'install_version': 'main'}}):  # noqa: E501
			apply_install_overrides(cls, cli_version=None)
		self.assertEqual(cls.install_cmd, 'go install new@[install_version]')
		self.assertEqual(cls.install_version, 'main')


if __name__ == '__main__':
	unittest.main()

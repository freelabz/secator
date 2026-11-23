"""Config environment overrides: list values and SECATOR_* variables read outside the config model.

Each test builds a fresh ``Config`` (defaults + env overrides) so it never depends on, or changes,
the shared ``CONFIG`` other tests use.
"""
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from secator.config import Config, NON_CONFIG_ENV_VARS


def _fresh(env=None, print_errors=False):
	with mock.patch.dict(os.environ, env or {}):
		return Config.parse(print_errors=print_errors)


class TestListValues(unittest.TestCase):
	"""A list config key accepts a JSON array, a bracketed list, a comma-separated string or one value."""

	KEY = 'addons.ai.extra_tools'

	def _set(self, value):
		config = _fresh()
		config.set(self.KEY, value)
		return list(config.addons.ai.extra_tools)

	def test_json_array(self):
		self.assertEqual(self._set('["word_count"]'), ['word_count'])
		self.assertEqual(self._set('["a", "b"]'), ['a', 'b'])

	def test_other_forms_unchanged(self):
		self.assertEqual(self._set('[a, b]'), ['a', 'b'])
		self.assertEqual(self._set('a,b'), ['a', 'b'])
		self.assertEqual(self._set('a'), ['a'])

	def test_json_array_from_env(self):
		config = _fresh({'SECATOR_ADDONS_AI_EXTRA_TOOLS': '["word_count", "other"]'})
		self.assertEqual(list(config.addons.ai.extra_tools), ['word_count', 'other'])


class TestNonConfigEnvVars(unittest.TestCase):
	"""SECATOR_* variables read directly from the environment don't trigger the unknown-key notice."""

	def _notices(self, env):
		with mock.patch('secator.config.console') as console:
			_fresh(env, print_errors=True)
		return ' '.join(str(c.args[0]) for c in console.print.call_args_list if c.args)

	def test_no_notice_for_known_direct_env_vars(self):
		printed = self._notices({'SECATOR_AI_TOOLS_DIRS': '/tmp', 'SECATOR_AI_SANDBOX_MEMORY': '2g'})
		self.assertNotIn('SECATOR_AI_TOOLS_DIRS', printed)
		self.assertNotIn('SECATOR_AI_SANDBOX_MEMORY', printed)

	def test_unknown_key_still_reported(self):
		printed = self._notices({'SECATOR_NOT_A_REAL_KEY_XYZ': '1'})
		self.assertIn('SECATOR_NOT_A_REAL_KEY_XYZ (unknown config key, ignored)', printed)

	def test_every_direct_env_read_is_a_config_key_or_listed(self):
		"""Any SECATOR_* variable the code reads from os.environ must be a config key or be listed in
		NON_CONFIG_ENV_VARS, so setting it never prints a misleading unknown-key notice."""
		root = Path(__file__).resolve().parents[2] / 'secator'
		pattern = re.compile(r"""os\.(?:environ(?:\.get)?\(?\[?|getenv\()\s*['"](SECATOR_[A-Z0-9_]+)['"]""")
		names = set()
		for path in root.rglob('*.py'):
			names |= set(pattern.findall(path.read_text()))
		self.assertTrue(names)
		config = _fresh()
		missing = sorted(
			n for n in names if n not in NON_CONFIG_ENV_VARS and config._resolve_env_key(n[len('SECATOR_'):]) is None)
		self.assertEqual(missing, [], f'add these to NON_CONFIG_ENV_VARS (or make them config keys): {missing}')

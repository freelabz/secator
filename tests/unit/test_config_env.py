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


class TestBoolValues(unittest.TestCase):
	"""Boolean keys accept the usual true/false spellings; anything else is rejected."""

	def test_truthy(self):
		for value in ('true', 'True', '1', 't', 'yes', 'Y', 'on', 'ON'):
			config = _fresh({'SECATOR_OFFLINE_MODE': value})
			self.assertIs(config.offline_mode, True, value)

	def test_falsy(self):
		for value in ('false', '0', 'f', 'no', 'N', 'off', ''):
			config = _fresh({'SECATOR_CLI_CHECK_UPDATES': value})
			self.assertIs(config.cli.check_updates, False, value)

	def test_invalid_rejected(self):
		with mock.patch('secator.config.console') as console:
			config = _fresh({'SECATOR_CLI_CHECK_UPDATES': 'maybe'}, print_errors=True)
		self.assertIs(config.cli.check_updates, True)  # default kept
		printed = ' '.join(str(c.args[0]) for c in console.print.call_args_list if c.args)
		self.assertIn('SECATOR_CLI_CHECK_UPDATES (override failed, ignored)', printed)


class TestOverrideValidation(unittest.TestCase):
	"""Env overrides are validated against the schema: invalid values are rejected, valid ones coerced."""

	def _notices(self, env):
		with mock.patch('secator.config.console') as console:
			config = _fresh(env, print_errors=True)
		return config, ' '.join(str(c.args[0]) for c in console.print.call_args_list if c.args)

	def test_invalid_int_rejected(self):
		config, printed = self._notices({'SECATOR_RUNNERS_THREADS': 'lots'})
		self.assertEqual(config.runners.threads, 50)
		self.assertIn('SECATOR_RUNNERS_THREADS (override failed, ignored)', printed)

	def test_valid_int(self):
		config = _fresh({'SECATOR_RUNNERS_THREADS': '7'})
		self.assertEqual(config.runners.threads, 7)

	def test_non_json_dict_rejected(self):
		config, printed = self._notices({'SECATOR_WORDLISTS_DEFAULTS': 'not-a-dict'})
		self.assertIsInstance(config.wordlists.defaults.toDict(), dict)
		self.assertIn('http', config.wordlists.defaults)
		self.assertIn('SECATOR_WORDLISTS_DEFAULTS (override failed, ignored)', printed)

	def test_optional_int_coerced(self):
		config, printed = self._notices({'SECATOR_ADDONS_API_ORG_ID': '42'})
		self.assertEqual(config.addons.api.org_id, 42)
		self.assertNotIn('does not exist', printed)

	def test_directory_home_expanded(self):
		config = _fresh({'SECATOR_DIRS_WORDLISTS': '~/my-wordlists'})
		self.assertEqual(config.dirs.wordlists, Path.home() / 'my-wordlists')

	def test_unexpandable_directory_rejected(self):
		config, printed = self._notices({'SECATOR_DIRS_WORDLISTS': '~secator_no_such_user_xyz/wordlists'})
		self.assertEqual(config.dirs.wordlists, config.dirs.data / 'wordlists')
		self.assertIn('SECATOR_DIRS_WORDLISTS (override failed, ignored)', printed)

	def test_dynamic_dict_key(self):
		config = _fresh({'SECATOR_TASKS_OVERRIDES_NMAP_MAX_TIMEOUT': '500'})
		self.assertEqual(config.tasks.overrides['nmap']['max_timeout'], 500)


class TestResultBackendDefault(unittest.TestCase):
	"""The default file result backend follows dirs.celery_results, including from the environment."""

	def test_env_celery_results_dir(self):
		env = {k: v for k, v in os.environ.items() if k != 'SECATOR_CELERY_RESULT_BACKEND'}
		env['SECATOR_DIRS_CELERY_RESULTS'] = '/tmp/custom-celery-results'
		with mock.patch.dict(os.environ, env, clear=True):
			config = Config.parse(print_errors=False)
		self.assertEqual(config.celery.result_backend, 'file:///tmp/custom-celery-results')

	def test_explicit_result_backend_kept(self):
		config = _fresh({'SECATOR_CELERY_RESULT_BACKEND': 'redis://localhost:6379/1'})
		self.assertEqual(config.celery.result_backend, 'redis://localhost:6379/1')

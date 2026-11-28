"""Removed config keys: a config file or env var that still sets one keeps loading, with a notice."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import secator.config as config_mod
from secator.config import Config, DEPRECATED_ENV_VARS, DEPRECATED_KEYS


def _printed(mock_print):
	return ' '.join(str(c.args[0]) for c in mock_print.call_args_list if c.args)


class TestDeprecatedKeys(unittest.TestCase):

	def setUp(self):
		patcher = mock.patch.object(config_mod, '_DEPRECATED_WARNED', set())
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_removed_from_schema(self):
		config = Config.parse(print_errors=False)
		for key in DEPRECATED_KEYS:
			*parents, leaf = key.split('.')
			node = config
			for part in parents:
				node = node[part]
			self.assertNotIn(leaf, node, key)

	def test_yaml_with_deprecated_keys_still_loads(self):
		data = {
			'runners': {'threads': 7, 'skip_exploit_search': True},
			'addons': {
				'gcs': {'enabled': True, 'bucket_name': 'b'},
				'worker': {'enabled': True},
				'ai': {'enabled': True, 'max_tokens': 1, 'max_results': 2, 'default_model': 'm'},
			},
			'dirs': {'performance': '/tmp/perf'},
		}
		with mock.patch.object(config_mod.console, 'print') as mock_print:
			config = Config.parse(data=data)
		self.assertIsNotNone(config)
		self.assertEqual(config.runners.threads, 7)
		self.assertEqual(config.addons.gcs.bucket_name, 'b')
		self.assertEqual(config.addons.ai.default_model, 'm')
		self.assertNotIn('enabled', config.addons.gcs)
		self.assertNotIn('worker', config._partial.addons)
		printed = _printed(mock_print)
		keys = (
			'runners.skip_exploit_search', 'addons.gcs.enabled', 'addons.worker',
			'addons.ai.enabled', 'addons.ai.max_tokens', 'addons.ai.max_results', 'dirs.performance')
		for key in keys:
			self.assertIn(f'Config key "{key}"', printed)

	def test_yaml_file_saved_without_deprecated_keys(self):
		with tempfile.TemporaryDirectory() as tmp:
			path = Path(tmp) / 'config.yml'
			path.write_text(yaml.dump({'cli': {'record': True, 'date_format': '%d/%m/%Y'}}))
			with mock.patch.object(config_mod.console, 'print'):
				config = Config.parse(path=path)
			self.assertIsNotNone(config)
			self.assertEqual(config.cli.date_format, '%d/%m/%Y')
			config.save()
			saved = yaml.safe_load(path.read_text())
		self.assertEqual(saved['cli'], {'date_format': '%d/%m/%Y'})

	def test_warned_once(self):
		with mock.patch.object(config_mod.console, 'print') as mock_print:
			Config.parse(data={'addons': {'api': {'enabled': True}}})
			Config.parse(data={'addons': {'api': {'enabled': True}}})
		self.assertEqual(_printed(mock_print).count('Config key "addons.api.enabled"'), 1)

	def test_vulners_enabled(self):
		with mock.patch.object(config_mod.console, 'print') as mock_print:
			config = Config.parse(data={'addons': {'vulners': {'enabled': True, 'api_key': 'k'}}})
		self.assertIsNotNone(config)
		self.assertEqual(config.addons.vulners.api_key, 'k')
		self.assertNotIn('enabled', config.addons.vulners)
		self.assertIn('Config key "addons.vulners.enabled" is deprecated and ignored', _printed(mock_print))
		self.assertEqual(DEPRECATED_ENV_VARS['SECATOR_ADDONS_VULNERS_ENABLED'], 'addons.vulners.enabled')

	def test_env_var(self):
		self.assertEqual(DEPRECATED_ENV_VARS['SECATOR_ADDONS_GCS_ENABLED'], 'addons.gcs.enabled')
		self.assertEqual(DEPRECATED_ENV_VARS['SECATOR_ADDONS_WORKER_ENABLED'], 'addons.worker')
		with mock.patch.dict(os.environ, {'SECATOR_ADDONS_GCS_ENABLED': 'true'}):
			with mock.patch.object(config_mod.console, 'print') as mock_print:
				config = Config.parse()
		self.assertIsNotNone(config)
		printed = _printed(mock_print)
		self.assertIn('Config key "addons.gcs.enabled" (SECATOR_ADDONS_GCS_ENABLED) is deprecated and ignored', printed)
		self.assertNotIn('unknown config key', printed)


if __name__ == '__main__':
	unittest.main()

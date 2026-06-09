import os
import shutil
import unittest
import yaml

from pathlib import Path
from unittest import mock

devnull = open(os.devnull, 'w')

@mock.patch('sys.stderr', devnull)
class TestConfig(unittest.TestCase):

	def setUp(self):
		self.env_dirs_data = os.environ['SECATOR_DIRS_DATA']
		del os.environ['SECATOR_DIRS_DATA']
		self.home = Path.home()
		self.valid_config = {
			'addons': {'gdrive': {'enabled': True}}
		}
		self.invalid_config = {
			'addons': {'gdrive': {'enabled': 'non-boolean'}}
		}
		self.config_home_dir = {
			'dirs': {'data': '~/test'}
		}
		self.config_home_dir_reduce = {
			'dirs': {'data': f'{self.home}/test'}
		}
		self.config_test = Path('test.yml')
		self.config_test.touch()

	def tearDown(self):
		self.config_test.unlink()
		os.environ['SECATOR_DIRS_DATA'] = self.env_dirs_data

	def test_parse_empty_config(self):
		from secator.config import Config
		config = Config.parse()
		self.assertIsNotNone(config)
		self.assertIsInstance(config, Config)
		self.assertIsInstance(config.addons.gdrive.enabled, bool)

	def test_parse_valid_config(self):
		from secator.config import Config
		config = Config.parse(self.valid_config)
		self.assertIsNotNone(config)
		self.assertIsInstance(config, Config)
		self.assertEqual(config.addons.gdrive.enabled, True)

	def test_parse_invalid_config(self):
		from secator.config import Config
		config = Config.parse(self.invalid_config)
		self.assertIsNone(config)

	def test_parse_home_dir_expand(self):
		from secator.config import Config
		user_data_dir = self.config_home_dir['dirs']['data']
		config = Config.parse(self.config_home_dir)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())
		config.save(self.config_test)
		config = Config.parse(path=self.config_test)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())

	def test_set_config_key(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('addons.gdrive.enabled', True)
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['addons']['gdrive']['enabled'], True)
		self.assertEqual(config.get('addons.gdrive.enabled'), True)
		config = Config.parse(path=self.config_test)
		self.assertEqual(config.addons.gdrive.enabled, True)
		self.assertEqual(config._partial.addons.gdrive.enabled, True)

	def test_set_list_field_replace(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('drivers.defaults', 'mongodb')
		self.assertEqual(config.drivers.defaults, ['mongodb'])
		config.set('drivers.defaults', 'redis')
		self.assertEqual(config.drivers.defaults, ['redis'])

	def test_set_list_field_append(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('drivers.defaults', 'mongodb', strategy='append')
		self.assertEqual(config.drivers.defaults, ['mongodb'])
		config.set('drivers.defaults', 'redis', strategy='append')
		self.assertEqual(config.drivers.defaults, ['mongodb', 'redis'])
		# Duplicate should not be added
		config.set('drivers.defaults', 'redis', strategy='append')
		self.assertEqual(config.drivers.defaults, ['mongodb', 'redis'])

	def test_unset_list_field_item(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('drivers.defaults', 'mongodb', strategy='append')
		config.set('drivers.defaults', 'redis', strategy='append')
		self.assertEqual(config.drivers.defaults, ['mongodb', 'redis'])
		config.unset('drivers.defaults', value='mongodb')
		self.assertEqual(config.drivers.defaults, ['redis'])
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['drivers']['defaults'], ['redis'])

	def test_set_dict_subkey(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		# Set a new key in wordlists.defaults (dict field)
		config.set('wordlists.defaults.mylist', 'myurl')
		self.assertEqual(config.wordlists.defaults['mylist'], 'myurl')
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['wordlists']['defaults']['mylist'], 'myurl')

	def test_unset_dict_subkey(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('wordlists.defaults.mylist', 'myurl')
		self.assertIn('mylist', config.wordlists.defaults)
		config.unset('wordlists.defaults.mylist')
		self.assertNotIn('mylist', config.wordlists.defaults)

	def test_parse_home_dir_reduce(self):
		from secator.config import Config
		with self.config_test.open('w') as f:
			f.write(yaml.dump(self.config_home_dir_reduce))
		config = Config.parse(path=self.config_test)
		self.assertIsInstance(config.dirs.data, Path)
		self.assertIsInstance(config._partial.dirs.data, str)
		config.save(self.config_test)
		data = Config.read_yaml(self.config_test)
		self.assertNotIn(str(self.home), data['dirs']['data'])

	def test_queries_field_default(self):
		from secator.config import Config
		config = Config.parse()
		self.assertEqual(config.queries, {})

	def test_set_get_unset_query(self):
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('queries.critical_vulns', 'vulnerability.severity_nb < 2')
		self.assertEqual(config.queries['critical_vulns'], 'vulnerability.severity_nb < 2')
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['queries']['critical_vulns'], 'vulnerability.severity_nb < 2')
		config.unset('queries.critical_vulns')
		self.assertNotIn('critical_vulns', config.queries)

	def test_queries_dir_resolves_under_data(self):
		from secator.config import Config
		config = Config.parse()
		self.assertEqual(config.dirs.queries, config.dirs.data / 'queries')

	def test_workspace_routes_append_new_workspace(self):
		"""Appending a route to a new workspace creates the list entry."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspace.routes.my_ws', '*vulnweb.com*', strategy='append')
		self.assertIn('my_ws', config.workspace.routes)
		self.assertEqual(config.workspace.routes['my_ws'], ['*vulnweb.com*'])

	def test_workspace_routes_append_multiple_patterns(self):
		"""Appending multiple patterns to same workspace accumulates them."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspace.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspace.routes.my_ws', '*ocervell*', strategy='append')
		self.assertEqual(config.workspace.routes['my_ws'], ['*vulnweb.com*', '*ocervell*'])

	def test_workspace_routes_append_no_duplicates(self):
		"""Appending a duplicate pattern is a no-op."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspace.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspace.routes.my_ws', '*vulnweb.com*', strategy='append')
		self.assertEqual(config.workspace.routes['my_ws'], ['*vulnweb.com*'])

	def test_workspace_routes_save_and_reload(self):
		"""Workspace routes survive a save/reload cycle."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspace.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspace.routes.my_ws', '*ocervell*', strategy='append')
		config.save()
		config2 = Config.parse(path=self.config_test)
		self.assertEqual(config2.workspace.routes['my_ws'], ['*vulnweb.com*', '*ocervell*'])


@mock.patch('sys.stderr', devnull)
class TestConfigEnv(unittest.TestCase):

	def setUp(self):
		from secator.utils_test import clear_modules
		clear_modules()
		shutil.rmtree('/tmp/.secator', ignore_errors=True)
		Path('/tmp/.secator').mkdir(parents=False)

	def tearDown(self):
		shutil.rmtree('/tmp/.secator', ignore_errors=True)

	@mock.patch.dict(os.environ, {'SECATOR_DIRS_DATA': '/tmp/.secator/new'})
	def test_dirs_data(self):
		from secator.config import CONFIG
		self.assertEqual(CONFIG.dirs.data, Path('/tmp/.secator/new'))

		# Check other dirs configured OK
		ignore_dirs = ['bin', 'share', 'data']
		for k, dir in CONFIG.dirs.items():
			if k in ignore_dirs:
				continue
			rel_target = '/'.join(k.split('_'))
			expected_path = CONFIG.dirs.data / rel_target
			self.assertEqual(dir, expected_path)

		# Check all dirs exist
		for dir in CONFIG.dirs.values():
			self.assertTrue(dir.exists())

	@mock.patch.dict(os.environ, {'SECATOR_DIRS_DATA': '/tmp/.secator/new', 'SECATOR_DIRS_PAYLOADS': '/tmp/.secator/payloads2'})
	def test_dirs_data_and_others(self):
		from secator.config import CONFIG
		self.assertEqual(CONFIG.dirs.data, Path('/tmp/.secator/new'))
		self.assertEqual(CONFIG.dirs.payloads, Path('/tmp/.secator/payloads2'))

		# Check other dirs configured OK
		ignore_dirs = ['bin', 'share', 'data', 'payloads']
		for k, dir in CONFIG.dirs.items():
			if k in ignore_dirs:
				continue
			rel_target = '/'.join(k.split('_'))
			expected_path = CONFIG.dirs.data / rel_target
			self.assertEqual(dir, expected_path)

		# Check all dirs exist
		for dir in CONFIG.dirs.values():
			self.assertTrue(dir.exists())

	@mock.patch.dict(os.environ, {'SECATOR_DIRS_PAYLOADS': '/tmp/.secator/payloads2', 'SECATOR_DIRS_TEMPLATES': '/tmp/.secator/templates2'})
	def test_dirs_others_only(self):
		from secator.config import CONFIG
		self.assertEqual(CONFIG.dirs.data, Path('/tmp/.secator'))
		self.assertEqual(CONFIG.dirs.payloads, Path('/tmp/.secator/payloads2'))
		self.assertEqual(CONFIG.dirs.templates, Path('/tmp/.secator/templates2'))

		# Check other dirs configured OK
		ignore_dirs = ['bin', 'share', 'data', 'payloads', 'templates']
		for k, dir in CONFIG.dirs.items():
			if k in ignore_dirs:
				continue
			rel_target = '/'.join(k.split('_'))
			expected_path = CONFIG.dirs.data / rel_target
			self.assertEqual(dir, expected_path)

		# Check all dirs exist
		for dir in CONFIG.dirs.values():
			self.assertTrue(dir.exists())


@mock.patch('sys.stderr', devnull)
class TestAIConfig(unittest.TestCase):

	def test_ai_config_defaults(self):
		from secator.config import Config
		config = Config.parse()
		ai = config.addons.ai
		self.assertIsNotNone(ai)
		# Test enabled and api_key fields (following addon pattern)
		self.assertEqual(ai.enabled, False)
		self.assertEqual(ai.api_key, '')
		# Test model configuration
		self.assertEqual(ai.default_model, 'claude-sonnet-4-6')
		self.assertEqual(ai.intent_model, 'claude-haiku-4-5')
		# Test generation parameters
		self.assertEqual(ai.temperature, 0.7)
		self.assertEqual(ai.max_tokens, 30000)
		# Test other settings
		self.assertEqual(ai.max_results, 500)
		self.assertEqual(ai.encrypt_pii, True)

	def test_api_finding_search_endpoint(self):
		from secator.config import Config
		config = Config.parse()
		self.assertEqual(config.addons.api.finding_search_endpoint, 'findings/_search')

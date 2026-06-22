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

	def test_set_dict_subkey_tasks_overrides(self):
		"""Test that setting a sub-key within an empty dict field works."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('tasks.overrides.nuclei.input_chunk_size', '100')
		self.assertEqual(config.tasks.overrides['nuclei']['input_chunk_size'], 100)
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['tasks']['overrides']['nuclei']['input_chunk_size'], 100)

	def _parse_with_env(self, **env):
		"""Parse a fresh config with the given SECATOR_* env vars set, then clean them up."""
		from secator.config import Config
		added = []
		try:
			for k, v in env.items():
				os.environ[k] = v
				added.append(k)
			return Config.parse(path=self.config_test)
		finally:
			for k in added:
				os.environ.pop(k, None)

	def test_env_override_task_overrides_simple_name(self):
		"""SECATOR_TASKS_OVERRIDES_NMAP_MAX_TIMEOUT maps to tasks.overrides.nmap.max_timeout (int)."""
		config = self._parse_with_env(SECATOR_TASKS_OVERRIDES_NMAP_MAX_TIMEOUT='500')
		self.assertEqual(config.tasks.overrides['nmap']['max_timeout'], 500)
		self.assertIsInstance(config.tasks.overrides['nmap']['max_timeout'], int)

	def test_env_override_task_overrides_underscore_name(self):
		"""Task names containing underscores (search_vulns) disambiguate correctly from the attr."""
		config = self._parse_with_env(SECATOR_TASKS_OVERRIDES_SEARCH_VULNS_INPUT_CHUNK_SIZE='7')
		self.assertEqual(config.tasks.overrides['search_vulns']['input_chunk_size'], 7)

	def test_env_override_unknown_task_is_ignored(self):
		"""An env override targeting an unknown task name is ignored (no crash, no key)."""
		config = self._parse_with_env(SECATOR_TASKS_OVERRIDES_NOTATASK_FOO='1')
		self.assertNotIn('notatask', config.tasks.overrides)

	def test_env_override_dynamic_dict_existing_key(self):
		"""SECATOR_PAYLOADS_TEMPLATES_LSE overrides an existing payloads.templates entry."""
		config = self._parse_with_env(SECATOR_PAYLOADS_TEMPLATES_LSE='https://mycustomtemplates.sh')
		self.assertEqual(config.payloads.templates['lse'], 'https://mycustomtemplates.sh')

	def test_env_override_dynamic_dict_new_key(self):
		"""SECATOR_PAYLOADS_TEMPLATES_MYCUSTOM adds a new payloads.templates entry."""
		config = self._parse_with_env(SECATOR_PAYLOADS_TEMPLATES_MYCUSTOM='https://new.sh')
		self.assertEqual(config.payloads.templates['mycustom'], 'https://new.sh')

	def test_env_override_direct_key_still_works(self):
		"""A non-dynamic env override (SECATOR_CELERY_TASK_MAX_TIMEOUT) still applies."""
		config = self._parse_with_env(SECATOR_CELERY_TASK_MAX_TIMEOUT='999')
		self.assertEqual(config.celery.task_max_timeout, 999)

	def test_env_override_unknown_addon_key_does_not_break_config(self):
		"""An invalid SECATOR_ADDONS_* key is ignored and leaves the typed addons model intact (#1204).

		Previously this clobbered the typed `addons` model with a plain dict, so attribute access like
		CONFIG.addons.ai.api_key raised AttributeError at import time and bricked the whole CLI.
		"""
		from secator.config import Config
		config = self._parse_with_env(SECATOR_ADDONS_NONEXISTENT_URL='test')
		self.assertIsNotNone(config)
		self.assertIsInstance(config, Config)
		# Typed addon models stay attribute-accessible (not replaced by a plain dict).
		self.assertIsInstance(config.addons, Config)
		self.assertEqual(config.addons.ai.api_key, config.addons.ai.api_key)  # no AttributeError
		self.assertIsInstance(config.addons.mongodb.url, str)
		# The bogus key was not written anywhere.
		self.assertNotIn('nonexistent', config.addons.toDict())

	def test_env_override_valid_addon_key_still_works(self):
		"""A valid SECATOR_ADDONS_* override applies and keeps the typed addons model intact."""
		from secator.config import Config
		config = self._parse_with_env(SECATOR_ADDONS_MONGODB_URL='mongodb://example:27017')
		self.assertEqual(config.addons.mongodb.url, 'mongodb://example:27017')
		self.assertIsInstance(config.addons, Config)
		self.assertEqual(config.addons.ai.api_key, config.addons.ai.api_key)  # no AttributeError

	def test_set_workspace_profiles(self):
		"""Test setting per-workspace default profiles via comma-separated string."""
		from secator.config import Config
		from unittest.mock import patch
		config = Config.parse(path=self.config_test)
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'aggressive,passive')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive', 'passive'])
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['workspaces']['profiles']['my_ws'], ['aggressive', 'passive'])

	def test_set_workspace_profiles_single(self):
		"""Test that a single profile string is coerced to a list."""
		from secator.config import Config
		from unittest.mock import patch
		config = Config.parse(path=self.config_test)
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'aggressive')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive'])

	def test_set_workspace_profiles_append(self):
		"""Test appending a profile to workspace profiles list."""
		from secator.config import Config
		from unittest.mock import patch
		config = Config.parse(path=self.config_test)
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'aggressive,passive')
			config.set('workspaces.profiles.my_ws', 'stealth', strategy='append')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive', 'passive', 'stealth'])
		# Duplicate should not be added
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'passive', strategy='append')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive', 'passive', 'stealth'])

	def test_unset_workspace_profiles_item(self):
		"""Test removing a single profile from workspace profiles list."""
		from secator.config import Config
		from unittest.mock import patch
		config = Config.parse(path=self.config_test)
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'aggressive,passive,stealth')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive', 'passive', 'stealth'])
		config.unset('workspaces.profiles.my_ws', value='passive')
		self.assertEqual(config.workspaces.profiles['my_ws'], ['aggressive', 'stealth'])
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['workspaces']['profiles']['my_ws'], ['aggressive', 'stealth'])

	def test_unset_workspace_profiles_key(self):
		"""Test removing an entire workspace entry from profiles."""
		from secator.config import Config
		from unittest.mock import patch
		config = Config.parse(path=self.config_test)
		with patch('secator.config.Config._validate_profile_names', return_value=True):
			config.set('workspaces.profiles.my_ws', 'aggressive,passive')
		self.assertIn('my_ws', config.workspaces.profiles)
		config.unset('workspaces.profiles.my_ws')
		self.assertNotIn('my_ws', config.workspaces.profiles)

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
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		self.assertIn('my_ws', config.workspaces.routes)
		self.assertEqual(config.workspaces.routes['my_ws'], ['*vulnweb.com*'])

	def test_workspace_routes_append_multiple_patterns(self):
		"""Appending multiple patterns to same workspace accumulates them."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspaces.routes.my_ws', '*ocervell*', strategy='append')
		self.assertEqual(config.workspaces.routes['my_ws'], ['*vulnweb.com*', '*ocervell*'])

	def test_workspace_routes_append_no_duplicates(self):
		"""Appending a duplicate pattern is a no-op."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		self.assertEqual(config.workspaces.routes['my_ws'], ['*vulnweb.com*'])

	def test_workspace_routes_save_and_reload(self):
		"""Workspace routes survive a save/reload cycle."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspaces.routes.my_ws', '*ocervell*', strategy='append')
		config.save()
		config2 = Config.parse(path=self.config_test)
		self.assertEqual(config2.workspaces.routes['my_ws'], ['*vulnweb.com*', '*ocervell*'])

	def test_workspace_routes_remove_existing_pattern(self):
		"""Removing an existing pattern leaves the remaining patterns intact."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='append')
		config.set('workspaces.routes.my_ws', '*ocervell*', strategy='append')
		config.set('workspaces.routes.my_ws', '*vulnweb.com*', strategy='remove')
		self.assertEqual(config.workspaces.routes['my_ws'], ['*ocervell*'])

	def test_workspace_routes_remove_missing_pattern(self):
		"""Removing a non-existent pattern is a no-op (warns but does not raise)."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*ocervell*', strategy='append')
		config.set('workspaces.routes.my_ws', '*doesnotexist*', strategy='remove')
		self.assertEqual(config.workspaces.routes['my_ws'], ['*ocervell*'])

	def test_workspace_routes_remove_workspace_key(self):
		"""Unsetting a workspace key (no value) deletes it from routes entirely."""
		from secator.config import Config
		config = Config.parse(path=self.config_test)
		config.set('workspaces.routes.my_ws', '*ocervell*', strategy='append')
		self.assertIn('my_ws', config.workspaces.routes)
		config.unset('workspaces.routes.my_ws')
		self.assertNotIn('my_ws', config.workspaces.routes)


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


@mock.patch('sys.stderr', devnull)
class TestConfigMigration(unittest.TestCase):

	def test_migrate_workspace_key_to_workspaces(self):
		"""Old top-level 'workspace' key is renamed to 'workspaces' on parse."""
		from secator.config import Config
		data = {'workspace': {'current': 'my-ws', 'routes': {}, 'profiles': {}}}
		config = Config.parse(data)
		self.assertIsNotNone(config)
		self.assertEqual(config.workspaces.current, 'my-ws')

	def test_migrate_workspaces_default_to_current(self):
		"""Intermediate 'workspaces.default' key is renamed to 'workspaces.current' on parse."""
		from secator.config import Config
		data = {'workspaces': {'default': 'my-ws', 'routes': {}, 'profiles': {}}}
		config = Config.parse(data)
		self.assertIsNotNone(config)
		self.assertEqual(config.workspaces.current, 'my-ws')

	def test_migrate_workspace_default_to_workspaces_current(self):
		"""Fully old-format 'workspace.default' migrates seamlessly to 'workspaces.current'."""
		from secator.config import Config
		data = {'workspace': {'default': 'my-ws', 'routes': {}, 'profiles': {}}}
		config = Config.parse(data)
		self.assertIsNotNone(config)
		self.assertEqual(config.workspaces.current, 'my-ws')

	def test_migrate_writes_updated_config_to_file(self):
		"""Migration persists renamed keys to the YAML file on disk."""
		import tempfile
		from secator.config import Config
		with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
			import yaml
			yaml.dump({'workspaces': {'default': 'from-file', 'routes': {}, 'profiles': {}}}, f)
			tmp_path = Path(f.name)
		try:
			config = Config.parse(path=tmp_path)
			self.assertIsNotNone(config)
			self.assertEqual(config.workspaces.current, 'from-file')
			# File on disk should now use the new key
			with tmp_path.open() as f:
				saved = yaml.safe_load(f)
			self.assertNotIn('default', saved.get('workspaces', {}))
			self.assertEqual(saved['workspaces']['current'], 'from-file')
		finally:
			tmp_path.unlink(missing_ok=True)

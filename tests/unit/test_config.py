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

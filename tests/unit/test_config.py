import unittest
import yaml
from pathlib import Path
from secator.config import Config, CONFIG


class TestConfig(unittest.TestCase):
	def setUp(self):
		self.home = Path.home()
		self.valid_config = {
			'addons': {'google': {'enabled': True}}
		}
		self.invalid_config = {
			'addons': {'google': {'enabled': 'non-boolean'}}
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

	def test_parse_empty_config(self):
		config = Config.parse()
		self.assertIsNotNone(config)
		self.assertIsInstance(config, Config)
		self.assertIsInstance(config.addons.google.enabled, bool)

	def test_parse_valid_config(self):
		config = Config.parse(self.valid_config)
		self.assertIsNotNone(config)
		self.assertIsInstance(config, Config)
		self.assertEqual(config.addons.google.enabled, True)

	def test_parse_invalid_config(self):
		config = Config.parse(self.invalid_config)
		self.assertIsNone(config)

	def test_parse_home_dir_expand(self):
		user_data_dir = self.config_home_dir['dirs']['data']
		config = Config.parse(self.config_home_dir)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())
		config.save(self.config_test)
		config = Config.parse(path=self.config_test)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())

	def test_set_config_key(self):
		config = Config.parse(path=self.config_test)
		config.set('addons.google.enabled', True)
		config.save()
		yaml_data = Config.read_yaml(self.config_test)
		self.assertEqual(yaml_data['addons']['google']['enabled'], True)
		self.assertEqual(config.get('addons.google.enabled'), True)
		config = Config.parse(path=self.config_test)
		self.assertEqual(config.addons.google.enabled, True)
		self.assertEqual(config._partial.addons.google.enabled, True)

	def test_parse_home_dir_reduce(self):
		with self.config_test.open('w') as f:
			f.write(yaml.dump(self.config_home_dir_reduce))
		config = Config.parse(path=self.config_test)
		self.assertIsInstance(config.dirs.data, Path)
		self.assertIsInstance(config._partial.dirs.data, str)
		config.save(self.config_test)
		data = Config.read_yaml(self.config_test)
		self.assertNotIn(str(self.home), data['dirs']['data'])

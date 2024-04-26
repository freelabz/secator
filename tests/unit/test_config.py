import unittest
from secator.config import Config, CONFIG


class TestConfig(unittest.TestCase):
	def setUp(self):
		self.valid_config = {
			'addons': {'google': {'enabled': True}}
		}
		self.invalid_config = {
			'addons': {'google': {'enabled': 'non-boolean'}}
		}
		self.config_home_dir = {
			'dirs': {'data': '~/test'}
		}
		pass

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
		from pathlib import Path
		user_data_dir = self.config_home_dir['dirs']['data']
		config = Config.parse(self.config_home_dir)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())

		new_path = Path('test1.yml')
		new_path.touch()
		config.save(new_path)
		config = Config.parse(path=new_path)
		self.assertEqual(config.dirs.data, Path(user_data_dir).expanduser())
		new_path.unlink()

	def test_set_config_key(self):
		from pathlib import Path
		new_path = Path('test2.yml')
		new_path.touch()
		config = Config.parse(path=new_path)
		config.set('addons.google.enabled', True)
		config.save()
		yaml_data = Config.read_yaml(new_path)
		self.assertEqual(yaml_data['addons']['google']['enabled'], True)
		self.assertEqual(config.get('addons.google.enabled'), True)
		config = Config.parse(path=new_path)
		self.assertEqual(config.addons.google.enabled, True)
		self.assertEqual(config._partial.addons.google.enabled, True)
		new_path.unlink()

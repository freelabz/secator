import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from click.testing import CliRunner

from secator.config import Config, mask_secret, mask_secrets, mask_url, SECRET_MASK

# Fake values only.
FAKE_AI_KEY = 'sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKE92d2'
FAKE_API_KEY = 'fake-api-key-0123456789abcdef'
FAKE_GH_TOKEN = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKE1234'
FAKE_TAVILY_KEY = 'tvly-FAKEFAKEFAKEFAKEFAKE'
FAKE_VULNERS_KEY = 'VULNERSFAKEFAKEFAKEFAKE'
FAKE_BOT_TOKEN = 'discord-bot-token-FAKEFAKEFAKE'
FAKE_WEBHOOK = 'https://discord.com/api/webhooks/123456/FAKEWEBHOOKTOKENFAKE'
FAKE_SUDO = 'hunter2'
FAKE_BROKER_PASS = 'brokerpassFAKE'
FAKE_MONGO_PASS = 'mongopassFAKE'
FAKE_OVERRIDE_TOKEN = 'wpscan-token-FAKE'

SECRETS = [
	FAKE_AI_KEY, FAKE_API_KEY, FAKE_GH_TOKEN, FAKE_TAVILY_KEY, FAKE_VULNERS_KEY, FAKE_BOT_TOKEN, FAKE_WEBHOOK,
	FAKE_SUDO, FAKE_BROKER_PASS, FAKE_MONGO_PASS, FAKE_OVERRIDE_TOKEN,
]

CONFIG_DATA = {
	'cli': {'github_token': FAKE_GH_TOKEN},
	'security': {'sudo_password': FAKE_SUDO},
	'celery': {'broker_url': f'redis://:{FAKE_BROKER_PASS}@localhost:6379/0'},
	'tasks': {'overrides': {'wpscan': {'api_token': FAKE_OVERRIDE_TOKEN}, 'probe': {'credentials': {'value': FAKE_SUDO}}}},
	'addons': {
		'ai': {'api_key': FAKE_AI_KEY, 'web_search': {'tavily_api_key': FAKE_TAVILY_KEY}},
		'api': {'key': FAKE_API_KEY},
		'vulners': {'api_key': FAKE_VULNERS_KEY},
		'discord': {'webhook_url': FAKE_WEBHOOK, 'bot_token': FAKE_BOT_TOKEN},
		'mongodb': {'url': f'mongodb://admin:{FAKE_MONGO_PASS}@localhost:27017'},
	},
}


class TestMaskHelpers(unittest.TestCase):

	def test_mask_secret_hint(self):
		self.assertEqual(mask_secret(FAKE_AI_KEY), 'sk-or...92d2')
		self.assertEqual(mask_secret('short'), SECRET_MASK)
		self.assertEqual(mask_secret(''), '')

	def test_mask_url(self):
		self.assertEqual(mask_url('redis://:pass@host:6379/0'), f'redis://{SECRET_MASK}@host:6379/0')
		self.assertEqual(mask_url('https://user:pass@host/x'), f'https://{SECRET_MASK}@host/x')
		self.assertEqual(mask_url('https://TOKEN:x-oauth-basic@github.com/x'), f'https://{SECRET_MASK}@github.com/x')
		self.assertEqual(mask_url('https://tok@github.com/x'), f'https://{SECRET_MASK}@github.com/x')
		self.assertEqual(mask_url('https://h/x?token=abc&page=1'), f'https://h/x?token={SECRET_MASK}&page=1')
		self.assertEqual(mask_url('https://app.example.com/api'), 'https://app.example.com/api')

	def test_nested_under_secret_key_masked(self):
		data = {'tasks': {'overrides': {'probe': {'credentials': {'value': 'hunter2', 'list': ['a-secret'], 'n': 3}}}}}
		masked = mask_secrets(data)['tasks']['overrides']['probe']['credentials']
		self.assertEqual(masked, {'value': SECRET_MASK, 'list': [SECRET_MASK], 'n': 3})
		# A dotted key path selecting a descendant of a secret key (as `config get a.credentials.value` does).
		self.assertEqual(mask_secrets({'tasks.overrides.probe.credentials.value': 'hunter2'}),
			{'tasks.overrides.probe.credentials.value': SECRET_MASK})

	def test_non_secret_fields_untouched(self):
		data = {'addons': {'ai': {'max_tokens_total': 30000, 'default_model': 'm'}, 'gdrive': {'credentials_path': '/x.json'}}}
		self.assertEqual(mask_secrets(data), data)


class TestConfigMasking(unittest.TestCase):

	def setUp(self):
		self.tmpdir = tempfile.TemporaryDirectory()
		self.path = Path(self.tmpdir.name) / 'config.yml'
		self.path.write_text(yaml.dump(CONFIG_DATA))
		self.config = Config.parse(path=self.path)
		self.assertIsNotNone(self.config)

	def tearDown(self):
		self.tmpdir.cleanup()

	def _run(self, *args):
		from secator.cli import cli
		with mock.patch('secator.cli.CONFIG', self.config):
			result = CliRunner().invoke(cli, ['config', 'get', *args])
		self.assertEqual(result.exit_code, 0, result.output)
		return result.output

	def _capture(self, fn):
		with mock.patch('secator.config.Config.print_yaml') as print_yaml:
			fn()
		return print_yaml.call_args[0][0]

	def assertNoSecrets(self, output):
		for secret in SECRETS:
			self.assertNotIn(secret, output)

	def test_full_config_get_masks_every_secret(self):
		output = self._capture(lambda: self.config.print(partial=False))
		self.assertNoSecrets(output)
		self.assertIn('sk-or...92d2', output)
		output = self._capture(lambda: self.config.print(partial=True))
		self.assertNoSecrets(output)

	def test_cli_config_get_masks_every_secret(self):
		self.assertNoSecrets(self._run())
		self.assertNoSecrets(self._run('--user'))

	def test_single_key_masks(self):
		for key in ['addons.ai.api_key', 'addons.ai', 'addons', 'cli.github_token', 'addons.discord.webhook_url',
				'celery.broker_url', 'addons.mongodb.url', 'tasks.overrides', 'security.sudo_password',
				'tasks.overrides.probe.credentials', 'tasks.overrides.probe.credentials.value']:
			self.assertNoSecrets(self._capture(lambda: self.config.get(key)))
			self.assertNoSecrets(self._run(key))

	def test_reveal_shows_value(self):
		output = self._capture(lambda: self.config.get('addons.ai.api_key', reveal=True))
		self.assertIn(FAKE_AI_KEY, output)
		self.assertIn(FAKE_AI_KEY, self._run('addons.ai.api_key', '--reveal'))
		self.assertIn(FAKE_BROKER_PASS, self._run('--reveal'))

	def test_runtime_gets_real_value(self):
		self._capture(lambda: self.config.print(partial=False))
		self.assertEqual(self.config.addons.ai.api_key, FAKE_AI_KEY)
		self.assertEqual(self.config.get('addons.ai.api_key', print=False), FAKE_AI_KEY)
		self.assertEqual(self.config.addons.discord.webhook_url, FAKE_WEBHOOK)
		self.assertIn(FAKE_BROKER_PASS, self.config.celery.broker_url)

	def test_save_keeps_real_values(self):
		self.config.save(target_path=self.path, partial=True)
		saved = yaml.safe_load(self.path.read_text())
		self.assertEqual(saved['addons']['ai']['api_key'], FAKE_AI_KEY)
		self.assertEqual(saved['security']['sudo_password'], FAKE_SUDO)


if __name__ == '__main__':
	unittest.main()

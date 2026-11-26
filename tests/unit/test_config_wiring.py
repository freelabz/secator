"""Config keys must reach the code that is documented to read them."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secator.config import CONFIG, Config
from secator.definitions import ADDONS_ENABLED


class TestWorkerCommandVerbose(unittest.TestCase):

	def _quiet(self, verbose):
		from secator import celery as celery_mod
		from secator.celery import run_command
		from secator.runners import PythonRunner

		captured = {}

		class Stub(PythonRunner):
			def __init__(self, targets, **opts):
				captured.update(opts)
				raise RuntimeError('stop')

		run_command.push_request(id='verbose-test', delivery_info={'routing_key': 'q'}, is_eager=True)
		try:
			with mock.patch.object(celery_mod, 'IN_WORKER', True), \
					mock.patch.dict(CONFIG.celery, {'worker_command_verbose': verbose}), \
					mock.patch.dict(CONFIG.celery, {'task_acks_late': False}), \
					mock.patch.object(celery_mod.Task, 'get_task_class', return_value=Stub):
				with self.assertRaises(RuntimeError):
					run_command.run([], 'stub', ['example.com'], {'context': {}})
		finally:
			run_command.pop_request()
		return captured['quiet']

	def test_verbose_off(self):
		self.assertTrue(self._quiet(False))

	def test_verbose_on(self):
		self.assertFalse(self._quiet(True))


class TestCeleryEnvOverrides(unittest.TestCase):

	def test_no_override(self):
		from secator.celery import celery_env_overrides
		env = {k: v for k, v in os.environ.items() if not k.startswith('CELERY_')}
		with mock.patch.dict(os.environ, env, clear=True):
			self.assertEqual(celery_env_overrides(), [])

	def test_same_value_is_not_reported(self):
		from secator.celery import celery_env_overrides
		with mock.patch.dict(os.environ, {'CELERY_BROKER_URL': CONFIG.celery.broker_url}):
			self.assertNotIn(('CELERY_BROKER_URL', 'celery.broker_url'), celery_env_overrides())

	def test_overrides_reported(self):
		from secator.celery import celery_env_overrides
		env = {
			'CELERY_BROKER_URL': 'redis://other:6379/0',
			'CELERY_RESULT_BACKEND': 'redis://other:6379/1',
		}
		with mock.patch.dict(os.environ, env):
			overrides = celery_env_overrides()
		self.assertIn(('CELERY_BROKER_URL', 'celery.broker_url'), overrides)
		self.assertIn(('CELERY_RESULT_BACKEND', 'celery.result_backend'), overrides)


class TestSchemaKeys(unittest.TestCase):

	def setUp(self):
		prefixes = ('SECATOR_RUNNERS_', 'SECATOR_HTTP_', 'SECATOR_ADDONS_AI_')
		env = {k: v for k, v in os.environ.items() if not k.startswith(prefixes)}
		patcher = mock.patch.dict(os.environ, env, clear=True)
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_show_subtasks(self):
		self.assertFalse(Config.parse().runners.show_subtasks)
		config = Config.parse({'runners': {'show_subtasks': True}})
		self.assertTrue(config.runners.show_subtasks)

	def test_exec_wrappers(self):
		from secator.ai import guardrails
		config = Config.parse({'addons': {'ai': {'exec_wrappers': ['firejail']}}})
		self.assertEqual(config.addons.ai.exec_wrappers, ['firejail'])
		with mock.patch.dict(CONFIG.addons.ai, {'exec_wrappers': ['firejail']}):
			wrappers = guardrails._exec_wrappers()
		self.assertIn('firejail', wrappers)
		self.assertTrue(guardrails.EXEC_WRAPPERS.issubset(wrappers))

	def test_response_max_size_bytes_default(self):
		self.assertEqual(Config.parse().http.response_max_size_bytes, 100000)


@unittest.skipUnless(ADDONS_ENABLED.get('ai', False), 'ai addon required')
class TestAiOptionDefaults(unittest.TestCase):

	def test_defaults_come_from_config(self):
		from secator.tasks.ai import ai
		self.assertEqual(ai.opts['temperature']['default'], CONFIG.addons.ai.temperature)
		self.assertEqual(ai.opts['sensitive']['default'], CONFIG.addons.ai.encrypt_pii)


class TestCveCacheDir(unittest.TestCase):

	def test_local_cve_cache_uses_dirs_cves(self):
		from secator.providers._base import CVEProvider
		with tempfile.TemporaryDirectory() as tmp:
			cve_id = 'CVE-2099-0001'
			(Path(tmp) / f'{cve_id}.json').write_text('{"name": "CVE-2099-0001", "matched_at": "x", "id": "CVE-2099-0001"}')
			with mock.patch.dict(CONFIG.dirs, {'cves': Path(tmp)}):
				vuln = CVEProvider.lookup_local_cve(cve_id)
		self.assertIsNotNone(vuln)
		self.assertEqual(vuln.id, cve_id)


class TestHttpxResponseCleanup(unittest.TestCase):

	def _on_end(self, opts):
		from secator.tasks.httpx import httpx
		with tempfile.TemporaryDirectory() as tmp:
			index = Path(tmp) / '.outputs' / 'response' / 'index.txt'
			index.parent.mkdir(parents=True)
			index.write_text('x')
			runner = mock.Mock(reports_folder=tmp)
			runner.get_opt_value.side_effect = lambda name: opts.get(name)
			with mock.patch.dict(CONFIG.http, {'store_responses': True}):
				httpx.on_end(runner)
			return index.exists()

	def test_run_option_disables_cleanup(self):
		self.assertTrue(self._on_end({'store_responses': False, 'screenshot': False}))

	def test_cleanup_when_storing(self):
		self.assertFalse(self._on_end({'store_responses': True, 'screenshot': False}))

	def test_cleanup_when_screenshot(self):
		self.assertFalse(self._on_end({'store_responses': False, 'screenshot': True}))


class TestGcsCredentials(unittest.TestCase):

	def setUp(self):
		try:
			from secator.hooks import gcs
		except ImportError:
			self.skipTest('gcs addon required')
		self.gcs = gcs
		self.gcs._gcs_client = None

	def tearDown(self):
		self.gcs._gcs_client = None

	def test_credentials_path(self):
		with mock.patch.dict(CONFIG.addons.gcs, {'credentials_path': '/tmp/sa.json'}), \
				mock.patch.object(self.gcs.storage, 'Client') as client:
			self.gcs.get_gcs_client()
		client.from_service_account_json.assert_called_once_with('/tmp/sa.json')
		client.assert_not_called()

	def test_default_credentials(self):
		with mock.patch.dict(CONFIG.addons.gcs, {'credentials_path': ''}), \
				mock.patch.object(self.gcs.storage, 'Client') as client:
			self.gcs.get_gcs_client()
		client.assert_called_once_with()
		client.from_service_account_json.assert_not_called()


if __name__ == '__main__':
	unittest.main()

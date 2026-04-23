from sysconfig import get_config_h_filename
import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
from secator.runners import Command
from secator.runners._base import HOOKS
from secator.utils_test import mock_command
from secator.output_types import OutputType, Url, Vulnerability, Tag, Target, Error
from secator.serializers.regex import RegexSerializer
from secator.serializers.json import JSONSerializer


class MyCommand(Command):
	input_types = ['slug']
	cmd = 'dummy'
	input_flag = '-u'
	file_flag = None


TARGETS = ['host1']
FIXTURE = ['test_fixture']


class TestCommandRunner(unittest.TestCase):

	def setUp(self):
		self.original_output_types = MyCommand.output_types
		self.original_item_loaders = MyCommand.item_loaders
		self.all_hooks = list(set(Command.hooks + HOOKS))

	def tearDown(self):
		MyCommand.output_types = self.original_output_types
		MyCommand.item_loaders = self.original_item_loaders
		self.cleanup_hooks()

	def mock_hooks(self, output_types=[], item_loaders=[]):
		"""Set up command for testing with customizable parameters."""
		MyCommand.output_types = output_types
		MyCommand.item_loaders = item_loaders

		mock_hooks = {}
		for hook in self.all_hooks:
			if hook in ['on_item_pre_convert', 'on_item', 'on_line', 'on_duplicate']:
				def func(self, item):
					return item
			elif hook in ['on_cmd_opts']:
				def func(self, opts):
					return opts
			else:
				def func(self):
					return None
			func = staticmethod(func)
			mock = self.mock_hook(hook, func)
			mock_hooks[hook] = mock

		# Dynamic hook generation for all serializers
		for loader in MyCommand.item_loaders:
			serializer_name = loader.__class__.__name__.lower().replace('serializer', '')
			hook = f'on_{serializer_name}_loaded'
			self.all_hooks.append(hook)
			def mock_generator(self, item):
				yield item
			mock = self.mock_hook(hook, mock_generator)
			mock_hooks[hook] = mock

		return mock_hooks

	def mock_hook(self, hook_name, hook_func):
		mock = MagicMock()
		mock.call_count = 0
		mock.__name__ = hook_name
		mock.__qualname__ = hook_name
		mock.side_effect = hook_func
		setattr(MyCommand, hook_name, mock)
		return mock

	def cleanup_hooks(self):
		"""Clean up hooks after testing."""
		for hook in self.all_hooks:
			if hasattr(MyCommand, hook):
				delattr(MyCommand, hook)

	def test_init(self):
		"""Ensure that init the command correctly inits the Runner and calls the init hooks before_init and on_init"""
		def before_init(self):
			pass

		def on_init(self):
			pass

		MyCommand.before_init = staticmethod(before_init)
		MyCommand.on_init = staticmethod(on_init)

		with patch.object(Command, 'run_hooks') as mock_run_hooks:
			MyCommand(TARGETS)
			mock_run_hooks.assert_any_call('before_init', sub='init')
			mock_run_hooks.assert_any_call('on_init', sub='init')

		# Clean up after test
		delattr(MyCommand, 'before_init')
		delattr(MyCommand, 'on_init')

	def test_opts(self):
		"""Ensure that opts are correctly defined and mapped to the right output options."""
		MyCommand.opts = {
			'test_flag': {'is_flag': True, 'default': False, 'help': 'Test flag option'},
			'test_str': {'is_flag': False, 'default': None, 'help': 'Test string option'}
		}
		MyCommand.opt_key_map = {'test_flag': 'tf', 'test_str': 'ts'}
		self.all_hooks.extend(['opts', 'opt_key_map'])

		test_opts = {'test_flag': True, 'test_str': 'test_value'}
		cmd = MyCommand(TARGETS, **test_opts)
		self.assertEqual(cmd.run_opts['test_flag'], True)
		self.assertEqual(cmd.run_opts['test_str'], 'test_value')

		# Check if the command is correctly constructed
		expected_cmd = 'dummy -u host1 -tf -ts test_value'
		self.assertEqual(cmd.cmd, expected_cmd)


	def test_hooks(self):
		"""Ensure that all hooks in the Command + Runner lifecycle are correctly called."""
		mock_hooks = self.mock_hooks(
			output_types=[Url],
			item_loaders=[JSONSerializer()],
		)
		fixture=[
			'{"url": "http://example.com"}',
			'{"url": "http://example.org"}',
			'{"url": "http://example.com"}'  # Duplicate
		]

		# Run the command using mock_command
		with mock_command(MyCommand, TARGETS, {}, fixture, 'run'):
			# on_cmd_interrupt only fires on interrupt — skip in normal-flow assertion
			for hook, mock in mock_hooks.items():
				if hook == 'on_cmd_interrupt':
					continue
				self.assertTrue(mock.called, f"Hook '{hook}' was not called")
			self.assertEqual(mock_hooks['on_json_loaded'].call_count, 3)
			self.assertGreaterEqual(mock_hooks['on_duplicate'].call_count, 1)
			for item_hook in ['on_item_pre_convert', 'on_item', 'on_line', 'on_duplicate', 'on_json_loaded']:
				for call in mock_hooks[item_hook].call_args_list:
					self.assertEqual(len(call[0]), 2)  # self and item arguments
					self.assertIsInstance(call[0][1], (str, dict, OutputType))  # result

	def test_hooks_failing(self):
		"""Ensure that failing hooks are correctly handled for all hooks in the command lifecycle."""
		fixture = [
			'{"url": "http://example.com"}',
			'{"url": "http://example.org"}',
			'{"url": "http://example.com"}'  # Duplicate
		]
		MyCommand.output_types = [Url]
		MyCommand.item_loaders = [JSONSerializer()]
		all_hooks = self.all_hooks
		for failing_hook in all_hooks:
			with self.subTest(failing_hook=failing_hook):
				def failing_hook_func(self, *args, **kwargs):
					raise Exception(f"Hook {failing_hook} failed")
				self.mock_hook(failing_hook, failing_hook_func)
				captured_output = StringIO()
				sys.stderr = captured_output
				with mock_command(MyCommand, TARGETS, {}, fixture) as command:
					command.run()
					errors = [e.message for e in command.errors]
					if errors:  # error happened during the actual execution, it will be yielded in results
						self.assertIn(f'Hook "unittest.mock.{failing_hook}" execution failed', errors)
						self.assertEqual(command.status, 'FAILURE')
				delattr(MyCommand, failing_hook)

	def test_input_loaders(self):
		"""Verify what happens when one of the input loaders fail."""
		def failing_loader(self, line):
			raise Exception("Loader failed")

		MyCommand.item_loaders = [failing_loader]
		with mock_command(MyCommand, TARGETS, {}, FIXTURE) as command:
			results = command.run()
			errors = [e.message for e in results if e._type == 'error']
			self.assertIn('Exception: Loader failed', errors)
			self.assertEqual(len(command.results), 2)
			self.assertEqual(command.status, 'FAILURE')

	def test_inputs_validator_failed_no_targets(self):
		cmd = MyCommand([])
		cmd.run()
		errors = cmd.errors
		messages = [e.message for e in errors]
		self.assertIn("Validator failed: Input is empty.", messages)
		self.assertEqual(len(cmd.results), 1)
		self.assertFalse(cmd.inputs_valid)
		self.assertEqual(cmd.status, 'FAILURE')

	def test_inputs_validator_failed_multiple_targets(self):
		targets = ['host1', 'host2']
		cmd = MyCommand(targets)
		cmd.run()
		errors = cmd.errors
		messages = [e.message for e in errors]
		self.assertIn("Validator failed: Command does not support multiple inputs in non-worker mode. Consider running with a remote worker instead.", messages)
		self.assertEqual(len(cmd.results), 3)
		self.assertFalse(cmd.inputs_valid)
		self.assertEqual(cmd.status, 'FAILURE')

	# def test_inputs_validator_failed_wrong_input_type(self):
	# 	MyCommand.input_types = [Url]
	# 	targets = ['host1', 'host2']
	# 	cmd = MyCommand(targets)
	# 	errors = cmd.errors
	# 	messages = [e.message for e in errors]
	# 	self.assertIn("Validator failed: Multiple input passed in non-worker mode.", messages)
	# 	self.assertEqual(len(cmd.results), 0)
	# 	self.assertFalse(cmd.inputs_valid)
	# 	delattr(MyCommand, 'input_types', None)

	def test_stdout_output(self):
		"""Test MyCommand with stdout output."""
		fixture = [
			"http://example.com | URL | example.com | 200 | 1000 | Example Title",
			"CVE-2021-1234 | VULNERABILITY | CVE-2021-1234 | http://example.com",
			"AWS_KEY | TAG | secret | AKIA1234567890ABCDEF | http://example.com"
		]
		MyCommand.output_types = [Url, Tag, Vulnerability]
		MyCommand.item_loaders = [
			RegexSerializer(
				r'^(?P<url>.*?) \| (?P<type>.*?) \| (?P<host>.*?) \| (?P<status_code>\d+) \| (?P<content_length>\d+)( \| (?P<title>.*))?$',
				fields=['url', 'type', 'host', 'status_code', 'content_length', 'title']
			),
			RegexSerializer(
				r'^(?P<name>.*?) \| VULNERABILITY \| (?P<id>.*?) \| (?P<matched_at>.*?)$',
				fields=['name', 'id', 'matched_at']
			),
			RegexSerializer(
				r'^(?P<name>.*?) \| TAG \| (?P<category>.*?) \| (?P<value>.*?) \| (?P<match>.*?)$',
				fields=['name', 'category', 'match', 'value', 'match']
			)
		]
		def on_regex_loaded(self, item):
			if 'status_code' in item:
				item['status_code'] = int(item['status_code'])
			yield item

		MyCommand.on_regex_loaded = staticmethod(on_regex_loaded)
		self.all_hooks.extend(['output_types', 'item_loaders', 'on_regex_loaded'])

		with mock_command(MyCommand, TARGETS, {}, fixture, 'run') as results:
			results = list(results)
			self.assertEqual(len(results), 4)
			self.assertIsInstance(results[0], Target)
			self.assertIsInstance(results[1], Url)
			self.assertIsInstance(results[2], Vulnerability)
			self.assertIsInstance(results[3], Tag)

			# Check specific attributes
			self.assertEqual(results[0].name, "host1")
			self.assertEqual(results[1].url, "http://example.com")
			self.assertEqual(results[2].id, "CVE-2021-1234")
			self.assertEqual(results[3].name, "AWS_KEY")

	def test_jsonlines_output(self):
		"""Test MyCommand with JSON-lines output."""
		fixture = [
			'{"url": "http://host1:5000/api/", "status": 200}',
			'{"vulnerability": "myvuln", "severity": "HIGH", "matched": "http://host1:5000/api/"}',
			'{"tag": "mytag", "category": "secret", "matched_at": "http://host1:5000/api/", "tag_type": "AWS_API_KEY", "value": "ACDIFOJ-ASDF"}'
		]
		MyCommand.output_types = [Url, Vulnerability, Tag]
		MyCommand.item_loaders = [JSONSerializer()]
		MyCommand.output_map = {
			Url: {
				'url': 'url',
				'status_code': 'status'
			},
			Vulnerability: {
				'name': 'vulnerability',
				'severity': 'severity',
				'matched_at': 'matched'
			},
			Tag: {
				'name': 'tag',
				'match': 'matched_at',
				'extra_data': lambda x: {k: v for k, v in x.items() if k in ['tag_type', 'value']}
			}
		}
		self.all_hooks.extend(['output_types', 'item_loaders', 'output_map'])

		with mock_command(MyCommand, TARGETS, {}, fixture, 'run') as results:
			results = list(results)
			self.assertEqual(len(results), 4)
			self.assertIsInstance(results[0], Target)
			self.assertIsInstance(results[1], Url)
			self.assertIsInstance(results[2], Vulnerability)
			self.assertIsInstance(results[3], Tag)

			# Check specific attributes
			self.assertEqual(results[0].name, "host1")
			self.assertEqual(results[1].url, "http://host1:5000/api/")
			self.assertEqual(results[2].name, "myvuln")
			self.assertEqual(results[3].name, "mytag")
			self.assertEqual(results[3].extra_data['tag_type'], "AWS_API_KEY")

	def test_json_file_output(self):
		"""Test MyCommand with JSON file output."""
		json_output = [
			{"url": "http://example.com", "status_code": 200},
			{"name": "SQL Injection", "severity": "high", "matched_at": "http://example.com"},
			{"name": "sensitive_data", "value": "1234567890", "category": "PII", "match": "http://example.com", "extra_data": {"tag_type": "PII"}}
		]

		import json
		with open('output.json', 'w') as f:
			json.dump(json_output, f)

		def on_cmd_done(self):
			with open('output.json', 'r') as f:
				data = json.load(f)

			for item in data:
				if 'url' in item:
					yield Url(**item)
				elif 'match' in item:
					yield Tag(**item)
				else:
					yield Vulnerability(**item)

		MyCommand.on_cmd_done = staticmethod(on_cmd_done)
		self.all_hooks.extend(['on_cmd_done'])

		with mock_command(MyCommand, TARGETS, {}, [], 'run') as results:
			self.assertEqual(len(results), 4)
			self.assertIsInstance(results[0], Target)
			self.assertIsInstance(results[1], Url)
			self.assertIsInstance(results[2], Vulnerability)
			self.assertIsInstance(results[3], Tag)

			# Check specific attributes
			self.assertEqual(results[0].name, "host1")
			self.assertEqual(results[1].url, "http://example.com")
			self.assertEqual(results[2].name, "SQL Injection")
			self.assertEqual(results[3].name, "sensitive_data")

		# Clean up the temporary file
		import os
		os.remove('output.json')

	def test_convert_item_schema(self):
		MyCommand.output_types = [Url, Tag, Vulnerability]
		url = TARGETS[0]
		items = [
			{
				'__test__': 'Item with _type hint should load properly and bypass other output types',
				'url': url,
				'_type': 'url',
				'__expected__': {
					'_type': 'url',
				},
			},
			{
				'__test__': 'Item with all the required fields should load properly',
				'url': url,
				'__expected__': {
					'_type': 'url',
				},
			},
			{
				'__test__': 'Items with all the required fields AND fields outside schema should load properly',
				'url': url,
				'extra_field_not_in_schema': {'new': 'added', 'field': 'old'},
				'__expected__': {
					'_type': 'url',
				},
			},
			{
				'__test__': 'Items with missing required fields should fail to load',
				'target': url,
				'__expected__': {
					'_type': 'warning',
				},
			},
			{
				'__test__': 'Items with missing required fields AND _type hint should fail to load',
				'_type': 'vulnerability',
				'__expected__': {
					'_type': 'warning',
				},
			},
			{
				'__test__': 'Item with all the required fields should load properly',
				'name': 'SQL Injection',
				'severity': 'high',
				'matched_at': 'http://example.com',
				'__expected__': {
					'_type': 'vulnerability'
				},
			},
			{
				'__test__': ' Trying to load a Vulnerability as a Tag should output a warning',
				"name": "SQL Injection",
				"severity": "high",
				"matched_at": "http://example.com",
				"_type": "tag",
				'__expected__': {
					'_type': 'warning'
				},
			},
			{
				'__test__': 'Item of type vulnerability with no _type hint should be incorrectly loaded as Tag',
				'name': 'sensitive_data',
				'match': 'http://example.com',
				'value': 'sensitive',
				'category': 'PII',
				'extra_data': {
					'tag_type': 'PII',
					'value': 'SSN'
				},
				'__expected__': {
					'_type': 'tag'
				},
			},
			{
				'__test__': 'Item of type vulnerability with _type hint will be loaded properly',
				'name': 'sensitive_data',
				'match': 'http://example.com',
				'extra_data': {
					'tag_type': 'PII',
					'value': 'SSN'
				},
				'_type': 'vulnerability',
				'__expected__': {
					'_type': 'vulnerability',
				}
			}
		]
		with mock_command(MyCommand, TARGETS, {}, []) as cmd:
			for item in items:
				msg = item.pop('__test__')
				expected_fields = item.pop('__expected__')
				converted = cmd._convert_item_schema(item)
				with self.subTest(msg=msg, item=item, converted=converted.toDict()):
					for k, v in expected_fields.items():
						self.assertEqual(getattr(converted, k), v)
		delattr(MyCommand, 'output_types')

	def test_custom_profiles(self):
		"""Test that custom profiles (TemplateLoader instances) can be passed to runners."""
		from secator.template import TemplateLoader

		# Create a custom profile using TemplateLoader
		custom_profile = TemplateLoader(input={
			'name': 'custom_test_profile',
			'type': 'profile',
			'description': 'Custom test profile',
			'opts': {
				'timeout': 120,
				'retries': 3
			}
		})

		# Create a command with the custom profile
		with mock_command(MyCommand, TARGETS, {'profiles': [custom_profile]}, []) as cmd:
			# Verify the profile was loaded
			self.assertEqual(len(cmd.profiles), 1)
			self.assertEqual(cmd.profiles[0].name, 'custom_test_profile')
			# Verify the profile options were applied
			self.assertEqual(cmd.run_opts.get('timeout'), 120)
			self.assertEqual(cmd.run_opts.get('retries'), 3)

	def test_mixed_profiles(self):
		"""Test that both string profile names and TemplateLoader instances can be mixed."""
		from secator.utils_test import clear_modules
		clear_modules()

		from secator.runners import Command
		from secator.template import TemplateLoader
		from secator.utils_test import mock_command
		from unittest.mock import patch

		class LocalMyCommand(Command):
			input_types = ['slug']
			cmd = 'dummy'
			input_flag = '-u'
			file_flag = None

		custom_profile = TemplateLoader(input={
			'name': 'custom_mixed_profile',
			'type': 'profile',
			'description': 'Custom mixed profile',
			'opts': {'timeout': 90}
		})
		mock_profile = TemplateLoader(input={
			'name': 'test_string_profile',
			'type': 'profile',
			'description': 'String profile',
			'opts': {'retries': 2}
		})
		with unittest.mock.patch('secator.runners.task.Task.get_task_class', return_value=LocalMyCommand):
			with patch('secator.runners._base.get_configs_by_type') as mock_get_configs:
				mock_get_configs.return_value = [mock_profile]
				with mock_command(LocalMyCommand, TARGETS, {'profiles': [custom_profile, 'test_string_profile']}, []) as cmd:
					self.assertEqual(len(cmd.profiles), 2)
					profile_names = [p.name for p in cmd.profiles]
					self.assertIn('custom_mixed_profile', profile_names)
					self.assertIn('test_string_profile', profile_names)
					self.assertEqual(cmd.run_opts.get('timeout'), 90)
					self.assertEqual(cmd.run_opts.get('retries'), 2)

	def test_custom_profile_no_duplicate_defaults(self):
		"""Test that custom profiles with same name as defaults don't get duplicated."""
		from secator.utils_test import clear_modules
		clear_modules()

		from secator.runners import Command
		from secator.template import TemplateLoader
		from secator.utils_test import mock_command
		from unittest.mock import patch

		class LocalMyCommand(Command):
			input_types = ['slug']
			cmd = 'dummy'
			input_flag = '-u'
			file_flag = None

		custom_profile = TemplateLoader(input={
			'name': 'test_default',
			'type': 'profile',
			'description': 'Custom profile',
			'opts': {'timeout': 100}
		})

		with unittest.mock.patch('secator.runners.task.Task.get_task_class', return_value=LocalMyCommand):
			with patch('secator.runners._base.CONFIG.profiles.defaults', ['test_default']):
				with patch('secator.runners._base.get_configs_by_type') as mock_get_configs:
					default_profile = TemplateLoader(input={
						'name': 'test_default',
						'type': 'profile',
						'opts': {'timeout': 50}
					})
					mock_get_configs.return_value = [default_profile]
					with mock_command(LocalMyCommand, TARGETS, {'profiles': [custom_profile]}, []) as cmd:
						self.assertEqual(len(cmd.profiles), 1)
						self.assertEqual(cmd.profiles[0].name, 'test_default')
						self.assertEqual(cmd.run_opts.get('timeout'), 100)


class TestIsOwnSource(unittest.TestCase):
	"""Verify _is_own_source correctly scopes errors to the owning runner."""

	def _make_cmd(self, name):
		with mock_command(MyCommand, TARGETS, {}, []) as cmd:
			cmd.name = name
			cmd.unique_name = name
			return cmd

	def test_exact_match(self):
		cmd = self._make_cmd('nmap')
		self.assertTrue(cmd._is_own_source('nmap'))

	def test_chunk_suffix_digit(self):
		cmd = self._make_cmd('nmap')
		self.assertTrue(cmd._is_own_source('nmap_1'))
		self.assertTrue(cmd._is_own_source('nmap_42'))

	def test_rejects_prefix_sibling(self):
		"""nmap_light must NOT be considered a chunk of nmap."""
		cmd = self._make_cmd('nmap')
		self.assertFalse(cmd._is_own_source('nmap_light'))

	def test_rejects_unrelated(self):
		cmd = self._make_cmd('nuclei')
		self.assertFalse(cmd._is_own_source('nmap'))
		self.assertFalse(cmd._is_own_source('nmap_light'))

	def test_self_errors_excludes_prefix_sibling_errors(self):
		"""Errors from nmap_light must not appear in nmap's self_errors (the prefix-collision bug)."""
		prior_error = Error(message='nmap/light failed', _source='nmap_light')
		with mock_command(MyCommand, TARGETS, {}, []) as cmd:
			cmd.name = 'nmap'
			cmd.unique_name = 'nmap'
			cmd.results.append(prior_error)
			self.assertEqual(cmd.self_errors, [])

	def test_self_errors_includes_own_errors(self):
		"""Errors with the runner's own _source must appear in self_errors."""
		own_error = Error(message='nmap failed', _source='nmap')
		with mock_command(MyCommand, TARGETS, {}, []) as cmd:
			cmd.name = 'nmap'
			cmd.unique_name = 'nmap'
			cmd.results.append(own_error)
			self.assertEqual(cmd.self_errors, [own_error])

	def test_self_errors_includes_chunk_errors(self):
		"""Errors from numeric chunks (nmap_1, nmap_2) must appear in nmap's self_errors."""
		chunk_error = Error(message='chunk failed', _source='nmap_1')
		with mock_command(MyCommand, TARGETS, {}, []) as cmd:
			cmd.name = 'nmap'
			cmd.unique_name = 'nmap'
			cmd.results.append(chunk_error)
			self.assertEqual(cmd.self_errors, [chunk_error])


class TestRunnerStatus(unittest.TestCase):
	"""Verify runner status property handles PAUSED state correctly."""

	def test_runner_status_paused(self):
		runner = Command.__new__(Command)
		runner.started = True
		runner.done = False
		runner.revoked = False
		runner.paused = True
		runner.skipped = False
		assert runner.status == 'PAUSED'

	def test_runner_paused_takes_priority_over_revoked(self):
		runner = Command.__new__(Command)
		runner.started = True
		runner.done = False
		runner.revoked = True
		runner.paused = True
		runner.skipped = False
		assert runner.status == 'PAUSED'


class TestResumeCfg(unittest.TestCase):
	"""Verify resume.cfg is correctly written on interrupt."""

	def test_write_resume_cfg_creates_file(self):
		import json
		import os
		import tempfile
		from secator.output_types import Checkpoint

		runner = Command.__new__(Command)
		runner.config = MagicMock()
		runner.config.name = 'test_scan'
		runner.config.type = 'scan'
		runner.inputs = ['example.com']
		runner.run_opts = {'threads': 10}
		runner.celery_ids_map = {}
		runner.no_process = True
		runner.sync = True
		runner.context = {}

		with tempfile.TemporaryDirectory() as tmpdir:
			runner._reports_folder = tmpdir
			cp = Checkpoint(task_id='t1', task_name='nmap_1', resume_file_path='/tmp/nmap.xml')
			runner.checkpoints = [cp]
			runner._write_resume_cfg()
			resume_path = os.path.join(tmpdir, 'resume.cfg')
			assert os.path.exists(resume_path)
			with open(resume_path) as f:
				data = json.load(f)
			assert data['runner_type'] == 'scan'
			assert data['runner_name'] == 'test_scan'
			assert data['targets'] == ['example.com']
			assert len(data['tasks']) == 1
			assert data['tasks'][0]['task_name'] == 'nmap_1'
			assert data['tasks'][0]['status'] == 'PAUSED'
			assert data['tasks'][0]['resume_file_path'] == '/tmp/nmap.xml'

	def test_write_resume_cfg_includes_celery_task_states(self):
		import json
		import os
		import tempfile

		runner = Command.__new__(Command)
		runner.config = MagicMock()
		runner.config.name = 'test_wf'
		runner.config.type = 'workflow'
		runner.inputs = ['10.0.0.1']
		runner.run_opts = {}
		runner.checkpoints = []
		runner.celery_ids_map = {
			'celery-id-1': {'name': 'httpx_1', 'id': 'celery-id-1', 'state': 'SUCCESS'},
			'celery-id-2': {'name': 'nuclei_1', 'id': 'celery-id-2', 'state': 'RUNNING'},
		}
		runner.no_process = True
		runner.sync = True
		runner.context = {}
		with tempfile.TemporaryDirectory() as tmpdir:
			runner._reports_folder = tmpdir
			runner._write_resume_cfg()
			with open(os.path.join(tmpdir, 'resume.cfg')) as f:
				data = json.load(f)
			task_names = {t['task_name'] for t in data['tasks']}
			assert 'httpx_1' in task_names
			assert 'nuclei_1' in task_names
			httpx_task = next(t for t in data['tasks'] if t['task_name'] == 'httpx_1')
			assert httpx_task['status'] == 'SUCCESS'

import copy
import json
import logging
import unittest
import unittest.mock
import warnings

from secator.config import CONFIG
from secator.definitions import (DEBUG, DELAY, FOLLOW_REDIRECT, HEADER, HOST,
							   MATCH_CODES, OPT_NOT_SUPPORTED, RATE_LIMIT,
							   THREADS, TIMEOUT)
from secator.output_types import Url
from secator.rich import console
from secator.runners import Command
from secator.tasks import httpx
from secator.utils import setup_logging
from secator.utils_test import (FIXTURES_TASKS, FIXTURES_DIR, INPUTS_TASKS, META_OPTS,
							  TEST_TASKS, CommandOutputTester, load_fixture,
							  mock_command, mock_subprocess_popen)

level = logging.DEBUG if DEBUG > 0 else logging.ERROR
setup_logging(level)


class FakeCmd(Command):
	opts = {
		'opt1': {'type': int, 'default': 10},
		'opt2': {'type': str, 'default': '1,2,3'},
		'opt3': {'is_flag': True, 'default': False}, # optional
		'opt_with_underscore': {'type': str}, # optional
		'opt-with-hyphen': {'type': str}
	}
	opt_prefix = '-' # all options have '-' as option char
	opt_key_map = {
		'opt3': '--opt3', # but opt3 has '--' prefix
		'opt4': OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		'opt1': lambda x: float(x) # actually opt1 value should be cast to a float
	}


class TestCommandProcessOpts(unittest.TestCase):
	
	def setUp(self):
		self.maxDiff = None

	def test_process_opts_defaults(self):
		run_opts = {}
		opts_str = FakeCmd._process_opts(
			run_opts,
			FakeCmd.opts,
			FakeCmd.opt_key_map,
			FakeCmd.opt_value_map)
		self.assertEqual(opts_str, '-opt1 10.0 -opt2 1,2,3')

	def test_process_opts(self):
		run_opts = {
			'opt1': 41,
			'opt2': False, # intentionally omit arg, overriding default value
			'opt3': True
		}
		opts_str = FakeCmd._process_opts(
			run_opts,
			FakeCmd.opts,
			FakeCmd.opt_key_map,
			FakeCmd.opt_value_map)
		self.assertEqual(opts_str, '-opt1 41.0 --opt3')

	def test_process_opts_with_prefix(self):
		run_opts = {
			'fakecmd_opt1': 41, # should override opt1 below
			'opt1': 45,
			'opt2': False, # intentionally omit arg, overriding default value
			'opt3': True
		}
		opts_str = FakeCmd._process_opts(
			run_opts,
			FakeCmd.opts,
			FakeCmd.opt_key_map,
			FakeCmd.opt_value_map,
			command_name='fakecmd')
		self.assertEqual(opts_str, '-opt1 41.0 --opt3')

	def test_process_opts_with_unsupported(self):
		run_opts = {
			'fakecmd_opt1': 41, # should override opt1 below
			'opt1': 45,
			'opt2': False, # intentionally omit arg, overriding default value
			'opt3': True,
			'opt4': 'test_unsupported'
		}
		opts_str = FakeCmd._process_opts(
			run_opts,
			FakeCmd.opts,
			FakeCmd.opt_key_map,
			FakeCmd.opt_value_map,
			command_name='fakecmd')
		self.assertEqual(opts_str, '-opt1 41.0 --opt3')

	def test_process_opts_with_convert_underscore(self):
		run_opts = {
			'fakecmd_opt1': 41, # should override opt1 below
			'opt1': 45,
			'opt2': False, # intentionally omit arg, overriding default value
			'opt3': True,
			'opt4': 'test_unsupported',
			'opt_with_underscore': 'test'
		}
		opts_str = FakeCmd._process_opts(
			run_opts,
			FakeCmd.opts,
			FakeCmd.opt_key_map,
			FakeCmd.opt_value_map,
			command_name='fakecmd')
		self.assertEqual(opts_str, '-opt1 41.0 --opt3 -opt-with-underscore test')

	def test_get_opt_value(self):
		run_opts = {
			'fakecmd_opt1': 41,
			'opt1': 45
		}
		opt_value = FakeCmd._get_opt_value(
			run_opts,
			opt_name='opt1',
			opt_prefix='fakecmd',
			default=10)
		self.assertEqual(opt_value, 41)

	def test_get_opt_value_false(self):
		run_opts = {
			'fakecmd_opt1': False,
			'opt1': 45
		}
		opt_value = FakeCmd._get_opt_value(
			run_opts,
			opt_name='opt1',
			opt_prefix='fakecmd',
			default=10)
		self.assertEqual(opt_value, False)

	def test_get_opt_value_not_supported(self):
		run_opts = {
			'fakecmd_opt1': False,
			'opt1': 45,
			'opt4': OPT_NOT_SUPPORTED
		}
		opt_value = FakeCmd._get_opt_value(
			run_opts,
			opt_name='opt4',
			opt_prefix='fakecmd',
			default=10)
		self.assertEqual(opt_value, None)

	# def test_httpx_build_cmd_defaults(self):
	# 	if httpx not in TEST_TASKS:
	# 		return
	# 	run_opts = {}
	# 	host = 'test.synology.me'
	# 	cls = httpx(host, **run_opts)
	# 	default_threads = cls.meta_opts[THREADS]['default']
	# 	expected_cmd = f'httpx {DEFAULT_HTTPX_FLAGS} -u {host} -json -rstr {CONFIG.http.response_max_size_bytes} -rsts {CONFIG.http.response_max_size_bytes} -threads {default_threads}'
	# 	self.assertEqual(cls.cmd, expected_cmd)
	# 	self.assertEqual(cls.print_line, False)
	# 	self.assertEqual(cls.print_item, False)

	# def test_httpx_build_cmd_with_opts(self):
	# 	if httpx not in TEST_TASKS:
	# 		return
	# 	run_opts = {
	# 		FOLLOW_REDIRECT: False,
	# 		DELAY: 1,
	# 		RATE_LIMIT: 120,
	# 		THREADS: 10,
	# 		TIMEOUT: 1,
	# 		HEADER: 'Content-Type: application/xml',
	# 		MATCH_CODES: False, # intentionally omit arg, overriding default value
	# 		'filter_codes': '500',
	# 		'filter_size': '23,33'
	# 	}
	# 	host = 'test.synology.me'
	# 	cls = httpx(host, **run_opts)
	# 	expected_cmd = f"httpx {DEFAULT_HTTPX_FLAGS} -u {host} -json -rstr {CONFIG.http.response_max_size_bytes} -rsts {CONFIG.http.response_max_size_bytes} -header 'Content-Type: application/xml' -delay 1s -rate-limit 120 -threads 10 -timeout 1 -filter-code 500 -filter-length 23,33"
	# 	self.assertEqual(cls.cmd, expected_cmd)
	# 	self.assertEqual(cls.print_line, False)
	# 	self.assertEqual(cls.print_item, False)

	# def test_httpx_build_cmd_with_opts_with_prefix(self):
	# 	if httpx not in TEST_TASKS:
	# 		return
	# 	run_opts = {
	# 		FOLLOW_REDIRECT: False,
	# 		DELAY: 1,
	# 		RATE_LIMIT: 120,
	# 		THREADS: 10,
	# 		TIMEOUT: 1,
	# 		HEADER: 'Content-Type: application/xml',
	# 		MATCH_CODES: False, # intentionally omit arg, overriding default value
	# 		'filter_code': '200',
	# 		'filter_length': 50,
	# 		'httpx.filter_codes': '500',    # prefixed option keys should override
	# 		'httpx_filter_size': '23,33' # prefixed option keys should override
	# 	}
	# 	host = 'test.synology.me'
	# 	cls = httpx(host, **run_opts)
	# 	expected_cmd = f"httpx {DEFAULT_HTTPX_FLAGS} -u {host} -json -rstr {CONFIG.http.response_max_size_bytes} -rsts {CONFIG.http.response_max_size_bytes} -header 'Content-Type: application/xml' -delay 1s -rate-limit 120 -threads 10 -timeout 1 -filter-code 500 -filter-length 23,33"
	# 	self.assertEqual(cls.cmd, expected_cmd)
	# 	self.assertEqual(cls.print_line, False)
	# 	self.assertEqual(cls.print_item, False)


class TestCommandRun(unittest.TestCase, CommandOutputTester):

	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def _valid_fixture(self, cls, fixture):
		if not fixture:
			if len(FIXTURES_TASKS.keys()) == 1: # make test fail.
				raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory (must not be an empty file / empty json / empty list).')
			console.print('[dim gold3] skipped (no fixture)[/]')
			return False
		return True

	def test_cmd_converted_schema(self):
		console.print('')

		for cls, fixture in FIXTURES_TASKS.items():
			console.print(f'\t[bold grey35]{cls.__name__} ...[/] ', end='')
			with self.subTest(name=cls.__name__):
				# Validate fixture
				if not self._valid_fixture(cls, fixture):
					continue

				# Run command
				targets = INPUTS_TASKS[cls.input_type]
				with mock_command(cls, targets, META_OPTS, fixture) as runner:
					self._test_runner_output(
						runner,
						expected_output_types=cls.output_types
					)


class TestCommandHooks(unittest.TestCase):

	def test_cmd_hooks(self):
		if httpx not in TEST_TASKS:
			return

		def on_item_pre_convert(self, item):
			item['url'] = 'test_changed_url'
			return item

		def on_item(self, item):
			item.status_code = 500
			return item

		def on_end(self):
			self.results = [{'url': 'test_changed_result'}]

		def on_init(self):
			self.cmd = 'test_changed_cmd_init'
			self.run_opts = {}

		def on_start(self):
			self.cmd = 'test_changed_cmd_start'

		hooks = {
			'on_init': [on_init],
			'on_start': [on_start],
			'on_end': [on_end],
			'on_item_pre_convert': [on_item_pre_convert],
			'on_item': [on_item],
		}
		fixture = load_fixture('httpx_output', FIXTURES_DIR)
		with mock_subprocess_popen([json.dumps(fixture)]):
			input = INPUTS_TASKS[HOST]
			cls = httpx(input, hooks=hooks)
			self.assertEqual(cls.cmd.split(' ')[0], 'test_changed_cmd_init')
			items = cls.run()
			item = items[1]
			self.assertIsInstance(item, Url)
			self.assertEqual(item.status_code, 500)
			self.assertEqual(item.url, 'test_changed_url')
			self.assertEqual(cls.cmd.split(' ')[0], 'test_changed_cmd_start')
			self.assertEqual(cls.results, [{'url': 'test_changed_result'}])

	def test_cmd_failed_hook(self):
		if httpx not in TEST_TASKS:
			return

		def raise_exc(self):
			raise Exception('Test passed')

		hooks = {
			'on_init': [raise_exc]
		}
		fixture = FIXTURES_TASKS[httpx]
		with mock_subprocess_popen([json.dumps(fixture)]):
			with self.assertRaises(Exception, msg='Test passed'):
				input = INPUTS_TASKS[HOST]
				httpx(input, hooks=hooks, raise_on_error=True) 
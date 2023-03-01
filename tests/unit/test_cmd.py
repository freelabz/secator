import json
import logging
import os
import unittest
import unittest.mock
import warnings

from secsy.cmd import CommandRunner
from secsy.definitions import *
from secsy.rich import console
from secsy.tasks import httpx
from secsy.utils import setup_logging, load_fixture
from secsy.utils_test import mock_subprocess_popen, FIXTURES, INPUTS, META_OPTS, OUTPUT_VALIDATORS

TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = f'{TEST_DIR}/fixtures'
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
DEBUG = bool(int(os.environ.get('DEBUG', '0')))
level = logging.DEBUG if DEBUG else logging.ERROR
setup_logging(level)


class FakeCmd(CommandRunner):
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


class TestCmdBuild(unittest.TestCase):
    def test_process_opts_defaults(self):
        cmd_opts = {}
        opts_str = FakeCmd._process_opts(
            cmd_opts,
            FakeCmd.opts,
            FakeCmd.opt_key_map,
            FakeCmd.opt_value_map)
        self.assertEqual(opts_str, '-opt1 10.0 -opt2 1,2,3')

    def test_process_opts(self):
        cmd_opts = {
            'opt1': 41,
            'opt2': False, # intentionally omit arg, overriding default value
            'opt3': True
        }
        opts_str = FakeCmd._process_opts(
            cmd_opts,
            FakeCmd.opts,
            FakeCmd.opt_key_map,
            FakeCmd.opt_value_map)
        self.assertEqual(opts_str, '-opt1 41.0 --opt3')

    def test_process_opts_with_prefix(self):
        cmd_opts = {
            'fakecmd_opt1': 41, # should override opt1 below
            'opt1': 45,
            'opt2': False, # intentionally omit arg, overriding default value
            'opt3': True
        }
        opts_str = FakeCmd._process_opts(
            cmd_opts,
            FakeCmd.opts,
            FakeCmd.opt_key_map,
            FakeCmd.opt_value_map,
            command_name='fakecmd')
        self.assertEqual(opts_str, '-opt1 41.0 --opt3')

    def test_process_opts_with_unsupported(self):
        cmd_opts = {
            'fakecmd_opt1': 41, # should override opt1 below
            'opt1': 45,
            'opt2': False, # intentionally omit arg, overriding default value
            'opt3': True,
            'opt4': 'test_unsupported'
        }
        opts_str = FakeCmd._process_opts(
            cmd_opts,
            FakeCmd.opts,
            FakeCmd.opt_key_map,
            FakeCmd.opt_value_map,
            command_name='fakecmd')
        self.assertEqual(opts_str, '-opt1 41.0 --opt3')

    def test_process_opts_with_convert_underscore(self):
        cmd_opts = {
            'fakecmd_opt1': 41, # should override opt1 below
            'opt1': 45,
            'opt2': False, # intentionally omit arg, overriding default value
            'opt3': True,
            'opt4': 'test_unsupported',
            'opt_with_underscore': 'test'
        }
        opts_str = FakeCmd._process_opts(
            cmd_opts,
            FakeCmd.opts,
            FakeCmd.opt_key_map,
            FakeCmd.opt_value_map,
            command_name='fakecmd')
        self.assertEqual(opts_str, '-opt1 41.0 --opt3 -opt-with-underscore test')

    def test_get_opt_value(self):
        cmd_opts = {
            'fakecmd_opt1': 41,
            'opt1': 45
        }
        opt_value = FakeCmd._get_opt_value(
            cmd_opts,
            opt_name='opt1',
            opt_prefix='fakecmd',
            default=10)
        self.assertEqual(opt_value, 41)

    def test_get_opt_value_false(self):
        cmd_opts = {
            'fakecmd_opt1': False,
            'opt1': 45
        }
        opt_value = FakeCmd._get_opt_value(
            cmd_opts,
            opt_name='opt1',
            opt_prefix='fakecmd',
            default=10)
        self.assertEqual(opt_value, False)

    def test_get_opt_value_not_supported(self):
        cmd_opts = {
            'fakecmd_opt1': False,
            'opt1': 45,
            'opt4': OPT_NOT_SUPPORTED
        }
        opt_value = FakeCmd._get_opt_value(
            cmd_opts,
            opt_name='opt4',
            opt_prefix='fakecmd',
            default=10)
        self.assertEqual(opt_value, None)

    def test_httpx_build_cmd_defaults(self):
        cmd_opts = {}
        host = 'test.synology.me'
        cls = httpx(host, **cmd_opts)
        default_match_codess = cls.meta_opts[MATCH_CODES]['default']
        default_threads = cls.meta_opts[THREADS]['default']
        expected_cmd = f'httpx -u {host} -json -td -cdn -follow-redirects -match-code {default_match_codess} -threads {default_threads}'
        self.assertEqual(cls.cmd, expected_cmd)
        self.assertEqual(cls._print_timestamp, False)
        self.assertEqual(cls._print_line, False)
        self.assertEqual(cls._print_item, False)
        self.assertEqual(cls._print_item_count, False)
        self.assertEqual(cls._print_cmd, False)
        self.assertEqual(cls._print_cmd_prefix, False)
        self.assertEqual(cls._json_output, True)

    def test_httpx_build_cmd_with_opts(self):
        cmd_opts = {
            FOLLOW_REDIRECT: False,
            DELAY: 1,
            RATE_LIMIT: 120,
            THREADS: 10,
            TIMEOUT: 1,
            HEADER: 'Content-Type: application/xml',
            MATCH_CODES: False, # intentionally omit arg, overriding default value
            'filter_code': '500',
            'filter_length': '23,33'
        }
        host = 'test.synology.me'
        cls = httpx(host, **cmd_opts)
        expected_cmd = f"httpx -u {host} -json -td -cdn -filter-code 500 -filter-length 23,33 -header 'Content-Type: application/xml' -delay 1s -rate-limit 120 -threads 10 -timeout 1"
        self.assertEqual(cls.cmd, expected_cmd)
        self.assertEqual(cls._print_timestamp, False)
        self.assertEqual(cls._print_line, False)
        self.assertEqual(cls._print_item, False)
        self.assertEqual(cls._print_item_count, False)
        self.assertEqual(cls._print_cmd, False)
        self.assertEqual(cls._print_cmd_prefix, False)
        self.assertEqual(cls._json_output, True)

    def test_httpx_build_cmd_with_opts_with_prefix(self):
        cmd_opts = {
            FOLLOW_REDIRECT: False,
            DELAY: 1,
            RATE_LIMIT: 120,
            THREADS: 10,
            TIMEOUT: 1,
            HEADER: 'Content-Type: application/xml',
            MATCH_CODES: False, # intentionally omit arg, overriding default value
            'filter_code': '200',
            'filter_length': 50,
            'httpx.filter_code': '500',    # prefixed option keys should override
            'httpx_filter_length': '23,33' # prefixed option keys should override
        }
        host = 'test.synology.me'
        cls = httpx(host, **cmd_opts)
        expected_cmd = f"httpx -u {host} -json -td -cdn -filter-code 500 -filter-length 23,33 -header 'Content-Type: application/xml' -delay 1s -rate-limit 120 -threads 10 -timeout 1"
        self.assertEqual(cls.cmd, expected_cmd)
        self.assertEqual(cls._print_timestamp, False)
        self.assertEqual(cls._print_line, False)
        self.assertEqual(cls._print_item, False)
        self.assertEqual(cls._print_item_count, False)
        self.assertEqual(cls._print_cmd, False)
        self.assertEqual(cls._print_cmd_prefix, False)
        self.assertEqual(cls._json_output, True)


class TestCmdSchema(unittest.TestCase):

    def setUp(self):
        warnings.simplefilter('ignore', category=ResourceWarning)
        warnings.simplefilter('ignore', category=DeprecationWarning)

    def test_cmd_converted_schema(self):
        console.print('')
        for cls, fixture in FIXTURES.items():
            if not fixture:
                if len(FIXTURES.keys()) == 1: # make test fail.
                    raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory.')
                console.print(f'\t[bold grey35]Testing {cls.__name__} ...[/] [bold red]No fixture ! Skipping test.[/]')
                continue
            console.print(f'\t[bold grey35]Testing {cls.__name__} ...[/]')
            with self.subTest(name=cls.__name__):
                self._test_cmd_mock(
                    cls,
                    fixture,
                    expected_output_keys=cls.output_schema,
                    expected_output_type=dict,
                    **META_OPTS)
        console.print('')

    def test_cmd_original_schema(self):
        console.print('')
        for cls, fixture in FIXTURES.items():
            if not fixture:
                if len(FIXTURES.keys()) == 1: # make test fail.
                    raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory.')
                console.print(f'\t[bold grey35]Testing {cls.__name__} ...[/] [bold red]No fixture ! Skipping test.[/]')
                continue
            console.print(f'\t[bold grey35]Testing {cls.__name__} ...[/]')
            with self.subTest(name=cls.__name__):
                expected_output_keys = None
                if isinstance(fixture, dict):
                    if 'results' in fixture: # fix for JSON files having a 'results' key
                        expected_output_keys = fixture['results'][0].keys()
                    else:
                        expected_output_keys = fixture.keys()
                self._test_cmd_mock(
                    cls,
                    fixture,
                    expected_output_keys=expected_output_keys,
                    expected_output_type=type(fixture),
                    orig=True,
                    raw=isinstance(fixture, str),
                    **META_OPTS)
        console.print('')

    def test_cmd_raw_mode(self):
        console.print('')
        for cls, fixture in FIXTURES.items():
            if not fixture:
                if len(FIXTURES.keys()) == 1: # make test fail.
                    raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory.')
                console.print(f'\t[bold grey35]Testing {cls.__name__} ...[/] [bold red]No fixture ! Skipping test.[/]')
                continue
            with self.subTest(name=cls.__name__):
                self._test_cmd_mock(
                    cls,
                    fixture,
                    output_validator=OUTPUT_VALIDATORS[cls.output_field],
                    raw=True,
                    **META_OPTS)
        console.print('')

    def _test_cmd_mock(
            self,
            cls,
            fixture,
            expected_output_keys=None,
            expected_output_type=None,
            output_validator=None,
            **opts):
        is_dict = isinstance(fixture, dict)
        mock = json.dumps(fixture) if is_dict else fixture
        with mock_subprocess_popen([mock]):
            input = INPUTS[cls.input_type]
            command = cls(input, **opts)
            items = command.run()
            self.assertGreater(len(items), 0)
            for item in items:
                if DEBUG:
                    console.log('debug', log_locals=True)
                if expected_output_type:
                    self.assertEqual(type(item), expected_output_type)
                if expected_output_keys: # test schema against fixture
                    keys = [k for k in item.keys() if not k.startswith('_')]
                    self.assertEqual(
                        set(keys).difference(set(expected_output_keys)),
                        set())
                if callable(output_validator):
                    self.assertTrue(output_validator(item))


class TestCmdHooks(unittest.TestCase):

    def test_cmd_hooks(self):

        def on_item(self, item):
            item['url'] = 'test_changed_url'
            return item

        def on_item_converted(self, item):
            item['status_code'] = 500
            return item

        def on_end(self):
            self.results = [{'url': 'test_changed_result'}]

        def on_init(self):
            self.cmd = 'test_changed_cmd_init'
            self.cmd_opts = {}

        def on_start(self):
            self.cmd = 'test_changed_cmd_start'

        hooks = {
            'on_init': [on_init],
            'on_start': [on_start],
            'on_end': [on_end],
            'on_item': [on_item],
            'on_item_converted': [on_item_converted],
            'on_end': [on_end],
        }
        fixture = load_fixture('httpx_output', FIXTURES_DIR)
        with mock_subprocess_popen([json.dumps(fixture)]):
            input = INPUTS[HOST]
            cls = httpx(input, hooks=hooks)
            self.assertEqual(cls.cmd.split(' ')[0], 'test_changed_cmd_init')
            item = cls.first()
            self.assertEqual(item['status_code'], 500)
            self.assertEqual(item['url'], 'test_changed_url')
            self.assertEqual(cls.cmd.split(' ')[0], 'test_changed_cmd_start')
            self.assertEqual(cls.results, [{'url': 'test_changed_result'}])

    def test_cmd_failed_hook(self):
        def on_init(self):
            raise Exception('Test passed')
        hooks = {
            'on_init': [on_init]
        }
        fixture = load_fixture('httpx_output', FIXTURES_DIR)
        with mock_subprocess_popen([json.dumps(fixture)]):
            with self.assertRaises(Exception, msg='Test passed'):
                input = INPUTS[HOST]
                cls = httpx(input, hooks=hooks)
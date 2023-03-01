import json
import logging
import os
import unittest
import unittest.mock
import validators
import warnings

from fp.fp import FreeProxy

from secsy.cmd import CommandRunner
from secsy.definitions import *
from secsy.tasks.http import *
from secsy.tasks.recon import *
from secsy.tasks.vuln import *
from secsy.rich import console
from secsy.utils import setup_logging, find_internal_tasks

TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = f'{TEST_DIR}/fixtures'
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
DEBUG = bool(int(os.environ.get('DEBUG', '0')))
level = logging.DEBUG if DEBUG else logging.ERROR
setup_logging(level)


def mock_subprocess_popen(output_list):
    mock_process = unittest.mock.MagicMock()
    mock_process.wait.return_value = 0
    mock_process.stdout.readline.side_effect = output_list
    mock_process.returncode = 0
    def mock_popen(*args, **kwargs):
        return mock_process
    return unittest.mock.patch('subprocess.Popen', mock_popen)


def load_fixture(name, ext=None, path=False):
    fixture_path = f'{FIXTURES_DIR}/{name}'
    exts = ['.json', '.txt', '.xml', '.rc']
    if ext:
        exts = [ext]
    for ext in exts:
        fixture_path = f'{fixture_path}{ext}'
        if os.path.exists(fixture_path):
            if path:
                return fixture_path
            with open(fixture_path) as f:
                content = f.read()
            if fixture_path.endswith(('.json', '.yaml')):
                return yaml.load(content, Loader=yaml.Loader)
            else:
                return content


#---------#
# GLOBALS #
#---------#
ALL_CMDS = find_internal_tasks()
TEST_COMMANDS = os.environ.get('TEST_COMMANDS', '')
if TEST_COMMANDS:
    TEST_COMMANDS = TEST_COMMANDS.split(',')
else:
    TEST_COMMANDS = [cls.__name__ for cls in ALL_CMDS]
TEST_HOST = 'fake.com'
TEST_URL = 'https://fake.com'
TEST_USER = 'test'
FIXTURES = {
    tool_cls: load_fixture(f'{tool_cls.__name__}_output')
    for tool_cls in ALL_CMDS
    if tool_cls.__name__ in TEST_COMMANDS
}
INPUTS = {
    URL: TEST_URL,
    HOST: TEST_HOST,
    USERNAME: TEST_USER
}
OUTPUT_VALIDATORS = {
    URL: lambda url: validators.url(url),
    HOST: lambda host: validators.domain(host),
    USER_ACCOUNT: lambda url: validators.url(url),
    PORT: lambda port: isinstance(port, int),
    None: lambda x: True,
}
meta_opts = {
    HEADER: 'User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',
    DELAY: 0,
    DEPTH: 2,
    FOLLOW_REDIRECT: True,
    METHOD: 'GET',
    MATCH_CODES: '200',
    PROXY: FreeProxy(timeout=0.5).get() if USE_PROXY else False,
    RATE_LIMIT: 10000,
    RETRIES: 0,
    THREADS: 50,
    TIMEOUT: 1,
    USER_AGENT: 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',

    # Individual tasks options
    'gf_pattern': 'xss',
    'nmap_output_path': load_fixture('nmap_output', path=True, ext='.xml'), # nmap XML fixture
    'msfconsole_resource_script': load_fixture('msfconsole_input', path=True),
    'dirsearch_output_path': load_fixture('dirsearch_output', path=True),
    'maigret_output_path': load_fixture('maigret_output', path=True)
}


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
        default_match_codess = HTTP_META_OPTS[MATCH_CODES]['default']
        default_threads = HTTP_META_OPTS[THREADS]['default']
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
            'httpx_filter_code': '500', # prefixed option keys should override
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
                console.print(f'Testing {cls.__name__} ... [bold red]No fixture ![/] [bold gold3]Skipping test.[/]')
                continue
            console.print(f'Testing {cls.__name__} ...')
            with self.subTest(name=cls.__name__):
                self._test_cmd_mock(
                    cls,
                    fixture,
                    expected_output_keys=cls.output_schema,
                    expected_output_type=dict,
                    **meta_opts)
        console.print('')

    def test_cmd_original_schema(self):
        console.print('')
        for cls, fixture in FIXTURES.items():
            if not fixture:
                console.print(f'Testing {cls.__name__} ... [bold red]No fixture ![/] [bold gold3]Skipping test.[/]')
                continue
            console.print(f'Testing {cls.__name__} ...')
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
                    expected_output_type=dict,
                    orig=True,
                    **meta_opts)
        console.print('')

    def test_cmd_raw_mode(self):
        console.print('')
        for cls, fixture in FIXTURES.items():
            if not fixture:
                console.print(f'Testing {cls.__name__} ... [bold red]No fixture ![/] [bold gold3]Skipping test.[/]')
                continue
            with self.subTest(name=cls.__name__):
                self._test_cmd_mock(
                    cls,
                    fixture,
                    output_validator=OUTPUT_VALIDATORS[cls.output_field],
                    raw=True,
                    **meta_opts)
        console.print('')

    def _test_cmd_mock(
            self,
            cls,
            fixture,
            expected_output_keys=None,
            expected_output_type=None,
            output_validator=None,
            **opts):
        fixture_data = fixture
        if isinstance(fixture, dict):
            fixture_data = json.dumps(fixture)
        with mock_subprocess_popen([fixture_data]):
            input = INPUTS[cls.input_type]
            command = cls(
                input,
                **opts)
            items = command.run()
            self.assertGreater(len(items), 0)
            for item in items:
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
        fixture = load_fixture('httpx_output')
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
        fixture = load_fixture('httpx_output')
        with mock_subprocess_popen([json.dumps(fixture)]):
            with self.assertRaises(Exception, msg='Test passed'):
                input = INPUTS[HOST]
                cls = httpx(input, hooks=hooks)
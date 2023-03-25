import logging
import contextlib

import json
import logging
import os
import unittest.mock
import validators
import yaml

from fp.fp import FreeProxy

from secsy.definitions import *
from secsy.rich import console
from secsy.utils import setup_logging, discover_internal_tasks, load_fixture


#---------#
# GLOBALS #
#---------#
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/tests/'
FIXTURES_DIR = f'{TEST_DIR}/fixtures'
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
ALL_CMDS = discover_internal_tasks()
TEST_COMMANDS = os.environ.get('TEST_COMMANDS', '')
if TEST_COMMANDS:
    TEST_COMMANDS = TEST_COMMANDS.split(',')
else:
    TEST_COMMANDS = [cls.__name__ for cls in ALL_CMDS]


INPUTS = {
    URL: 'https://fake.com',
    HOST: 'fake.com',
    USERNAME: 'test',
    IP: '192.168.1.23',
    CIDR_RANGE: '192.168.1.0/24'
}

OUTPUT_VALIDATORS = {
    URL: lambda url: validators.url(url),
    HOST: lambda host: validators.domain(host),
    USERNAME: lambda url: validators.url(url),
    PORT: lambda port: isinstance(port, int),
    IP: lambda ip: validators.ipv4(ip) or validators.ipv6(ip),
    None: lambda x: True,
}

FIXTURES = {
    tool_cls: load_fixture(f'{tool_cls.__name__}_output', FIXTURES_DIR)
    for tool_cls in ALL_CMDS
    if tool_cls.__name__ in TEST_COMMANDS
}

META_OPTS = {
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
    'gf.pattern': 'xss',
    'nmap.output_path': load_fixture('nmap_output', FIXTURES_DIR, only_path=True, ext='.xml'), # nmap XML fixture
    'msfconsole.resource_script': load_fixture('msfconsole_input', FIXTURES_DIR, only_path=True),
    'dirsearch.output_path': load_fixture('dirsearch_output', FIXTURES_DIR, only_path=True),
    'maigret.output_path': load_fixture('maigret_output', FIXTURES_DIR, only_path=True)
}


def mock_subprocess_popen(output_list):
    mock_process = unittest.mock.MagicMock()
    mock_process.wait.return_value = 0
    mock_process.stdout.readline.side_effect = output_list
    mock_process.returncode = 0
    def mock_popen(*args, **kwargs):
        return mock_process
    return unittest.mock.patch('subprocess.Popen', mock_popen)


@contextlib.contextmanager
def mock_command(cls, targets=[], opts={}, fixture=None, method=''):
        mocks = []
        if isinstance(fixture, dict):
            fixture = [fixture]
        
        is_list = isinstance(fixture, list)
        if is_list:
            for item in fixture:
                if isinstance(item, dict):
                    mocks.append(json.dumps(item))
                else:
                    mocks.append(item)
        else:
            mocks.append(fixture)

        with mock_subprocess_popen(mocks):
            command = cls(targets, **opts)
            if method == 'run':
                yield cls(targets, **opts).run()
            elif method == 'si':
                yield cls.si([], targets, **opts)
            elif method in ['s', 'delay']:
                yield getattr(cls, method)(targets, **opts)
            else:
                yield command


class CommandOutputTester: # Mixin for unittest.TestCase

    def _test_command_output(
            self,
            items,
            expected_output_keys=None,
            expected_output_types=None,
            output_validator=None):

        if not isinstance(items, list):
            items = [items]

        try:
            self.assertGreater(len(items), 0)

            for item in items:

                if DEBUG:
                    console.log('\n', log_locals=True)

                if expected_output_types:
                    self.assertIn(type(item), expected_output_types)

                if expected_output_keys:
                    self.assertEqual(
                        set(item.keys()).difference(set(expected_output_keys)),
                        set())

                if callable(output_validator):
                    self.assertTrue(output_validator(item))

        except Exception:
            console.print('[bold red] failed[/]')
            raise
        
        console.print('[bold green] ok[/]')
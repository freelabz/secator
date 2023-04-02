import json
import logging
import os
import unittest
import validators
import warnings
from time import sleep

from fp.fp import FreeProxy

from secsy.runners import Command
from secsy.utils import setup_logging, discover_internal_tasks
from secsy.utils_test import CommandOutputTester
from secsy.definitions import *
from secsy.rich import console
from secsy.celery import app
from secsy.tasks import httpx

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = f'{TEST_DIR}/fixtures'
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
DEBUG = bool(int(os.environ.get('DEBUG', '0')))
level = logging.DEBUG if DEBUG else logging.INFO
setup_logging(level)


def load_fixture(name):
    fixture_path = f'{FIXTURES_DIR}/{name}'
    if not os.path.exists(fixture_path):
        return None
    with open(f'{FIXTURES_DIR}/{name}', 'r') as f:
        content = f.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return content


TEST_HOST = 'localhost'
TEST_URL = f'http://localhost:3000?q=test'
TEST_USER = 'test'
ALL_CMDS = discover_internal_tasks()
TEST_COMMANDS = os.environ.get('TEST_COMMANDS', '')
if TEST_COMMANDS:
    TEST_COMMANDS = TEST_COMMANDS.split(',')
else:
    TEST_COMMANDS = [cls.__name__ for cls in ALL_CMDS]
FIXTURES = {
    tool_cls: load_fixture(f'{tool_cls.__name__}_output.json')
    for tool_cls in ALL_CMDS
    if tool_cls.__name__ in TEST_COMMANDS
}
INPUTS = {
    URL: TEST_URL,
    HOST: TEST_HOST,
    USERNAME: TEST_USER,
}
OUTPUT_VALIDATORS = {
    URL: lambda url: validators.url(url),
    HOST: lambda host: validators.domain(host),
    USERNAME: lambda url: validators.url(url),
    PORT: lambda port: isinstance(port, int),
    None: lambda x: True,
}
OPTIONS = {
    HEADER: 'User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',
    DELAY: 0,
    DEPTH: 2,
    FOLLOW_REDIRECT: True,
    METHOD: 'GET',
    MATCH_CODES: '200',
    PROXY: FreeProxy(timeout=0.5).get() if USE_PROXY else False,
    RATE_LIMIT: 10000,
    RETRIES: 0,
    THREADS: 200,
    TIMEOUT: 1,
    USER_AGENT: 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',
    'msfconsole_resource_script': load_fixture('msfconsole_input.rc'),
    'pattern': 'xss'
}


class TestCommand(unittest.TestCase, CommandOutputTester):
    def setUp(self):
        warnings.simplefilter('ignore', category=ResourceWarning)
        warnings.simplefilter('ignore', category=DeprecationWarning)
        Command.run_command(
            f'sh {INTEGRATION_DIR}/setup.sh',
            cwd=INTEGRATION_DIR
        )
        sleep(10)

    def tearDown(self):
        Command.run_command(
            f'sh {INTEGRATION_DIR}/teardown.sh',
            cwd=INTEGRATION_DIR
        )

    def test_all_commands(self):
        all_items = []
        for cls, _ in FIXTURES.items():
            with self.subTest(name=cls.__name__):
                self._test_cmd(
                    cls,
                    expected_output_keys=cls.output_schema,
                    expected_output_type=dict,
                    expected_return_code=0,
                    **OPTIONS)

    def _test_cmd(
            self,
            cls,
            expected_return_code=None,
            **opts):
        input = INPUTS[cls.input_type]
        command = cls(input, **opts)
        results = command.run()
        console.print(f'Testing {cls.__name__} ...')
        if expected_return_code:
            self.assertEqual(command.return_code, expected_return_code)
        if not results:
            console.print(
                f'No results from {cls.__name__} ! Skipping item check.')
        self._test_command_output(
            results,
            expected_output_types=cls.output_types)

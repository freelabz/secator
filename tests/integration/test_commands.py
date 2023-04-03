import logging
import os
import unittest
import warnings
from time import sleep

from secsy.celery import app
from secsy.definitions import *
from secsy.output_types import Port, Vulnerability, Ip, Subdomain, Tag, Target, Url, UserAccount
from secsy.rich import console
from secsy.runners import Command
from secsy.utils import setup_logging
from secsy.utils_test import FIXTURES, META_OPTS, CommandOutputTester

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


INPUTS = {
    URL: f'http://localhost:3000?q=test',
    HOST: 'localhost',
    USERNAME: 'test',
    IP: '127.0.0.1',
    CIDR_RANGE: '192.168.1.0/24',
    'ffuf': 'http://localhost:3000/FUZZ',
}

OUTPUTS = {
    'naabu': [
        Port(port=3000, host='localhost', ip='127.0.0.1', _source='naabu'),
        Port(port=8080, host='localhost', ip='127.0.0.1', _source='naabu'),
    ],
    'nmap': [
        Port(port=3000, host='localhost', ip='127.0.0.1', service_name='ppp', _source='nmap'),
        Port(port=8080, host='localhost', ip='127.0.0.1', service_name='nagios-nsca',  _source='nmap'),
        Vulnerability(matched_at='localhost:8080', name='OS Command Injection', provider='cve.circl.lu', id='CVE-2013-4781', severity='critical', confidence='low', cvss_score=10.0, _source='nmap')
    ]
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
        opts = META_OPTS.copy()
        opts['print_item'] = DEBUG > 1
        opts['print_cmd'] = DEBUG > 0
        opts['print_line'] = DEBUG > 1
        opts['table'] = DEBUG > 0
        del opts['nmap.output_path']
        for cls, _ in FIXTURES.items():
            with self.subTest(name=cls.__name__):
                console.print(f'Testing {cls.__name__} ...')
                input = INPUTS[cls.__name__] if cls.__name__ in INPUTS else INPUTS[cls.input_type]
                outputs = OUTPUTS[cls.__name__] if cls.__name__ in OUTPUTS else []
                command = cls(input, **opts)
                results = command.run()

                # Check return code
                if not command.ignore_return_code:
                    self.assertEqual(command.return_code, 0)

                if not results:
                    console.print(
                        f'No results from {cls.__name__} ! Skipping item check.')

                # Test result types
                self._test_command_output(
                    results,
                    expected_output_types=cls.output_types,
                    expected_results=outputs)
 
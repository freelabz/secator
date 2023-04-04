import logging
import os
import unittest
import warnings

from secsy.definitions import DEBUG
from secsy.rich import console
from secsy.runners import Command
from secsy.utils import setup_logging
from secsy.utils_test import FIXTURES, META_OPTS, CommandOutputTester, load_fixture
from tests.integration.inputs import INPUTS
from tests.integration.outputs import OUTPUTS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


class TestCommand(unittest.TestCase, CommandOutputTester):
    def setUp(self):
        warnings.simplefilter('ignore', category=ResourceWarning)
        warnings.simplefilter('ignore', category=DeprecationWarning)
        Command.run_command(
            f'sh {INTEGRATION_DIR}/setup.sh',
            cwd=INTEGRATION_DIR
        )
        # sleep(10)

    def tearDown(self):
        Command.run_command(
            f'sh {INTEGRATION_DIR}/teardown.sh',
            cwd=INTEGRATION_DIR
        )

    def test_all_commands(self):
        opts = META_OPTS.copy()

        # Set extra opts for clarity
        opts['print_item'] = DEBUG > 1
        opts['print_cmd'] = DEBUG > 0
        opts['print_line'] = DEBUG > 1
        opts['table'] = DEBUG > 0
        opts['ffuf.fs'] = 1987
        opts['wordlist'] = load_fixture('wordlist', INTEGRATION_DIR, only_path=True)
        opts['match_codes'] = '200'
        opts['maigret.site'] = 'github'
        opts['nmap.ports'] = '3000,8080'

        # Remove unit tests options
        del opts['nmap.output_path']
        del opts['maigret.output_path']
        del opts['dirsearch.output_path']
        del opts['timeout']

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
 
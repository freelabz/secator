import logging
import os
import unittest
import warnings
from time import sleep

from secsy.definitions import DEBUG
from secsy.rich import console
from secsy.runners import Command
from secsy.utils import setup_logging, merge_opts
from secsy.utils_test import (META_OPTS, TEST_TASKS, CommandOutputTester,
                              load_fixture)
from tests.integration.inputs import INPUTS_TASKS
from tests.integration.outputs import OUTPUTS_TASKS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


class TestTasks(unittest.TestCase, CommandOutputTester):
	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		Command.run_command(
			f'sh {INTEGRATION_DIR}/setup.sh',
			cwd=INTEGRATION_DIR
		)
		sleep(15)

	def tearDown(self):
		Command.run_command(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			cwd=INTEGRATION_DIR
		)

	def test_tasks(self):
		opts = META_OPTS.copy()
		fmt_opts = {
			'print_item': DEBUG > 1,
			'print_cmd': DEBUG > 0,
			'print_line': DEBUG > 1,
			'table': DEBUG > 0,
		}
		extra_opts = {
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'dirsearch.filter_size': 1987,
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
			'match_codes': '200',
			'maigret.site': 'github',
			'nmap.port': '3000,8080'
		}

		# Merge opts
		opts = merge_opts(opts, fmt_opts, extra_opts)

		# Remove unit tests options
		del opts['nmap.output_path']
		del opts['maigret.output_path']
		del opts['dirsearch.output_path']
		del opts['timeout']

		for cls in TEST_TASKS:
			with self.subTest(name=cls.__name__):
				console.print(f'Testing {cls.__name__} ...')
				input = INPUTS_TASKS.get(cls.__name__) or INPUTS_TASKS[cls.input_type]
				outputs = OUTPUTS_TASKS.get(cls.__name__, [])
				task = cls(input, **opts)
				results = task.run()

				# Check return code
				if not task.ignore_return_code:
					self.assertEqual(task.return_code, 0)

				if not results:
					console.print(f'No results from {cls.__name__} ! Skipping item check.')

				# Test result types
				self._test_task_output(
					results,
					expected_output_types=cls.output_types,
					expected_results=outputs,
					empty_results_allowed=True)

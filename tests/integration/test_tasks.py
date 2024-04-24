import logging
import os
import unittest
import warnings
from time import sleep

from secator.definitions import DEBUG
from secator.rich import console
from secator.runners import Command
from secator.utils import setup_logging, merge_opts
from secator.utils_test import (META_OPTS, TEST_TASKS, CommandOutputTester,
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
		Command.execute(
			f'sh {INTEGRATION_DIR}/setup.sh',
			cwd=INTEGRATION_DIR
		)
		sleep(15)

	def tearDown(self):
		Command.execute(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			cwd=INTEGRATION_DIR
		)

	def test_tasks(self):
		opts = META_OPTS.copy()
		fmt_opts = {
			'print_cmd': DEBUG > 0,
			'print_item': DEBUG > 1,
			'print_item_count': DEBUG > 0,
			'json': DEBUG > 2
		}
		extra_opts = {
			'dirsearch.filter_size': 1987,
			'dnsxbrute.wordlist': load_fixture('wordlist_dns', INTEGRATION_DIR, only_path=True),
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'h8mail.local_breach': load_fixture('h8mail_breach', INTEGRATION_DIR, only_path=True),
			'nmap.port': '3000,8080',
			'match_codes': '200',
			'maigret.site': 'github',
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
		}

		# Merge opts
		opts = merge_opts(opts, fmt_opts, extra_opts)

		# Remove unit tests options
		del opts['nmap.output_path']
		del opts['maigret.output_path']
		del opts['dirsearch.output_path']
		del opts['wpscan.output_path']
		del opts['timeout']

		for cls in TEST_TASKS:
			if cls.__name__ == 'msfconsole':  # skip msfconsole test as it's stuck
				continue
			with self.subTest(name=cls.__name__):
				console.print(f'Testing {cls.__name__} ...')

				# Get task input
				input = INPUTS_TASKS.get(cls.__name__) or INPUTS_TASKS.get(cls.input_type)
				if not input:
					console.print(f'No input for {cls.__name__} ! Skipping')
					continue

				# Get task output
				outputs = OUTPUTS_TASKS.get(cls.__name__, [])

				# Init task
				task = cls(input, **opts)

				# Run task
				results = task.run()
				if DEBUG > 2:
					console.print([list(r.toDict() for r in results)])

				# Check return code
				if not task.ignore_return_code:
					self.assertEqual(task.return_code, 0)

				if not results:
					console.print(f'No results from {cls.__name__} ! Skipping item check.')
					continue

				# Test result types
				self._test_task_output(
					results,
					expected_output_types=cls.output_types,
					expected_results=outputs,
					empty_results_allowed=True)

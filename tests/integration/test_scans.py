import logging
import os
import unittest
import warnings
from time import sleep

from secator.definitions import DEBUG
from secator.rich import console
from secator.runners import Command, Scan
from secator.utils import setup_logging, merge_opts
from secator.utils_test import TEST_SCANS, CommandOutputTester, load_fixture
from tests.integration.inputs import INPUTS_SCANS
from tests.integration.outputs import OUTPUTS_SCANS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


class TestScans(unittest.TestCase, CommandOutputTester):

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

	def test_scans(self):
		fmt_opts = {
			'print_item': DEBUG > 1,
			'print_cmd': DEBUG > 0,
			'print_line': DEBUG > 1,
			'table': DEBUG > 1,
			'output': 'table' if DEBUG > 0 else ''
		}
		opts = {
			'filter_size': 1987,
			'follow_redirect': True,
			'match_codes': '200',
			'httpx.match_codes': False,
			'httpx.filter_size': False,
			'nuclei.retries': 5,
			'nuclei.timeout': 15,
			'rate_limit': 1000,
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
			'timeout': 7,
			'depth': 2
		}
		opts = merge_opts(opts, fmt_opts)

		for conf in TEST_SCANS:
			with self.subTest(name=conf.name):
				console.print(f'Testing scan {conf.name} ...')
				inputs = INPUTS_SCANS.get(conf.name, [])
				outputs = OUTPUTS_SCANS.get(conf.name, [])
				if not inputs:
					console.print(
						f'No inputs for scan {conf.name} ! Skipping.', style='dim red'
					)
					continue
				scan = Scan(conf, targets=inputs, run_opts=opts)
				results = scan.run()
				if DEBUG > 0:
					for result in results:
						print(repr(result))
				if not outputs:
					console.print(
						f'No outputs for scan {conf.name} ! Skipping.', style='dim red'
					)
					continue
				self._test_task_output(
					results,
					expected_results=outputs)
import logging
import os
import unittest
import warnings
from time import sleep

from secsy.cli import ALL_WORKFLOWS
from secsy.definitions import DEBUG
from secsy.rich import console
from secsy.runners import Command, Workflow
from secsy.utils import setup_logging
from secsy.utils_test import CommandOutputTester, load_fixture
from tests.integration.inputs import INPUTS_WORKFLOWS
from tests.integration.outputs import OUTPUTS_WORKFLOWS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


class TestWorkflows(unittest.TestCase, CommandOutputTester):

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

	def test_all_workflows(self):
		opts = {
			'filter_size': 1987,
			# 'filter_regex': 'Unexpected path',
			'follow_redirect': True,
			'match_codes': '200',
			'httpx.match_codes': False,
			'httpx.filter_size': False,
			'rate_limit': 1000,
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
			'timeout': 7,
			'depth': 2
		}
		for conf in ALL_WORKFLOWS:
			with self.subTest(name=conf.name):
				console.print(f'Testing workflow {conf.name} ...')
				inputs = INPUTS_WORKFLOWS.get(conf.name, [])
				outputs = OUTPUTS_WORKFLOWS.get(conf.name, [])
				if not inputs:
					console.print(
						f'No inputs for workflow {conf.name} ! Skipping.', style='dim red'
					)
					continue
				workflow = Workflow(conf, targets=inputs, **opts)
				results = workflow.run()
				if DEBUG > 0:
					for result in results:
						print(repr(result))
				if not outputs:
					console.print(
						f'No outputs for workflow {conf.name} ! Skipping.', style='dim red'
					)
					continue
				self._test_task_output(
					results,
					expected_results=outputs)
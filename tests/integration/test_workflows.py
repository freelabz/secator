import logging
import os
import unittest
import warnings
from time import sleep

from secsy.definitions import DEBUG
from secsy.rich import console
from secsy.runners import Command, Workflow
from secsy.utils import setup_logging, merge_opts
from secsy.utils_test import TEST_WORKFLOWS, CommandOutputTester, load_fixture
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

	def test_default_workflows(self):
		fmt_opts = {
			'print_item': DEBUG > 1,
			'print_cmd': DEBUG > 0,
			'print_line': DEBUG > 1,
			'table': DEBUG > 1,
			'output': 'table' if DEBUG > 0 else ''
		}
		opts = {
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'dirsearch.filter_size': 1987,
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

		for conf in TEST_WORKFLOWS:
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

	def test_adhoc_workflow(self):
		from secsy.config import ConfigLoader
		from secsy.output_types import Port, Url
		config = {
			'name': 'my_workflow',
			'description': 'Test workflow',
			'tasks': {
				'naabu': {},
				'httpx': {
					'targets_': {'type': 'port', 'field': '{host}:{port}'}
				}
			}
		}
		config = ConfigLoader(config)
		expected_results = [
			Port(port=9999, host='localhost', service_name='fake', _source='unknown'),
			Port(port=3000, host='localhost', ip='127.0.0.1', _source='naabu'),
			Port(port=8080, host='localhost', ip='127.0.0.1', _source='naabu'),
			Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', content_type='text/html', _source='httpx'),
			Url(url='http://localhost:8080', host='127.0.0.1', status_code=400, title='', content_type='application/json', _source='httpx'),
		]
		workflow = Workflow(
			config,
			targets=['localhost'],
			results=[Port(port=9999, host='localhost', service_name='fake', _source='unknown')]
		)
		uuids = []
		results = []
		for result in workflow:
			self.assertNotIn(result._uuid, uuids)
			uuids.append(result._uuid)
			results.append(result)
		self.assertEqual(results, workflow.results)
		for res in expected_results:
			self.assertIn(res, workflow.results)
import logging
import os

from secator.definitions import DEBUG
from secator.runners import Scan
from secator.utils import setup_logging
from secator.utils_test import TEST_SCANS, CommandOutputTester, load_fixture, SecatorTestCase
from tests.integration.inputs import INPUTS_SCANS
from tests.integration.outputs import OUTPUTS_SCANS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


class TestScans(SecatorTestCase, CommandOutputTester):

	celery_worker = True

	def test_scans(self):
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

		for conf in TEST_SCANS:
			with self.subTest(name=conf.name):
				inputs = INPUTS_SCANS.get(conf.name, [])
				outputs = OUTPUTS_SCANS.get(conf.name, [])
				scan = Scan(conf, inputs=inputs, run_opts=opts)
				self._test_runner_output(
					scan,
					expected_results=outputs)

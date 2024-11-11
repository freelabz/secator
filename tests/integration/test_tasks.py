import os
import unittest
import warnings
from time import sleep

from secator.rich import console
from secator.runners import Command
from secator.utils import merge_opts
from secator.utils_test import (META_OPTS, TEST_TASKS, CommandOutputTester,
                              load_fixture)
from tests.integration.inputs import INPUTS_TASKS
from tests.integration.outputs import OUTPUTS_TASKS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))


class TestTasks(unittest.TestCase, CommandOutputTester):
	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		Command.execute(
			f'sh {INTEGRATION_DIR}/setup.sh',
			quiet=True,
			cwd=INTEGRATION_DIR
		)
		sleep(15)

	def tearDown(self):
		Command.execute(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			quiet=True,
			cwd=INTEGRATION_DIR
		)

	def test_tasks(self):
		opts = META_OPTS.copy()
		extra_opts = {
			'dirsearch.filter_size': 1987,
			'dnsxbrute.wordlist': load_fixture('wordlist_dns', INTEGRATION_DIR, only_path=True),
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'gau.providers': 'wayback',
			'h8mail.local_breach': load_fixture('h8mail_breach', INTEGRATION_DIR, only_path=True),
			'nmap.port': '3000,8080',
			'nmap.tcp_connect': True,
			'nmap.version_detection': True,
			'nmap.skip_host_discovery': True,
			'match_codes': '200',
			'maigret.site': 'github',
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
		}

		# Merge opts
		opts = merge_opts(opts, extra_opts)

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
				input = INPUTS_TASKS.get(cls.__name__) or INPUTS_TASKS.get(cls.input_type, [])
				outputs = OUTPUTS_TASKS.get(cls.__name__, [])
				task = cls(input, **opts)
				self._test_runner_output(
					task,
					expected_output_types=cls.output_types,
					expected_results=outputs,
					empty_results_allowed=True)

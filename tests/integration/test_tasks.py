import os
import unittest
import warnings
from time import sleep

from secator.loader import discover_tasks
from secator.rich import console
from secator.runners import Command
from secator.utils import merge_opts
from secator.utils_test import (META_OPTS, TEST_TASKS, CommandOutputTester,
                              load_fixture)
from tests.integration.inputs import INPUTS_TASKS
from tests.integration.outputs import OUTPUTS_TASKS, OUTPUTS_CHECKS

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
NO_CLEANUP = bool(os.environ.get('TEST_NO_CLEANUP', '0'))


class TestTasks(unittest.TestCase, CommandOutputTester):
	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		Command.execute(
			f'sh {INTEGRATION_DIR}/setup.sh',
			quiet=False,
			cwd=INTEGRATION_DIR
		)
		sleep(5)

	def tearDown(self):
		Command.execute(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			quiet=False,
			cwd=INTEGRATION_DIR
		)

	def test_tasks(self):
		opts = META_OPTS.copy()
		extra_opts = {
			'dirsearch.filter_size': 1987,
			'dnsx.wordlist': load_fixture('wordlist_dns', INTEGRATION_DIR, only_path=True),
			'ffuf.filter_size': 1987,
			'feroxbuster.filter_size': 1987,
			'arjun.wordlist': False,
			'gau.providers': 'wayback',
			'h8mail.local_breach': load_fixture('h8mail_breach', INTEGRATION_DIR, only_path=True),
			'nmap.port': '3000,8080',
			'nmap.tcp_connect': True,
			'nmap.version_detection': True,
			'nmap.skip_host_discovery': True,
			'match_codes': '200',
			'maigret.site': 'github',
			'trivy.mode': 'repo',
			'testssl.server_defaults': True,
			'wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
		}
		# TODO: copy profile and test with profile
		# opts['profiles'] = ['all']

		# Merge opts
		opts = merge_opts(opts, extra_opts)

		# Remove unit tests options
		del opts['nmap.output_path']
		del opts['dirsearch.output_path']
		del opts['gitleaks_output_path']
		del opts['maigret.output_path']
		del opts['wpscan.output_path']
		del opts['h8mail.output_path']
		del opts['wpprobe.output_path']
		del opts['arjun.output_path']
		del opts['trivy.output_path']
		del opts['wafw00f.output_path']
		del opts['testssl.output_path']
		del opts['timeout']

		failures = []

		tasks = discover_tasks()
		test_tasks_names = [t.name for t in TEST_TASKS]
		TASKS = [t for t in tasks if t.__name__ in test_tasks_names]

		for cls in TASKS:
			if cls.__name__ == 'msfconsole':  # skip msfconsole test as it's stuck
				continue
			with self.subTest(name=cls.__name__):
				input = INPUTS_TASKS.get(cls.__name__)
				if input is None:
					input = INPUTS_TASKS.get(cls.input_types[0], [])
				if not input:
					console.print(f'\tTesting task {cls.__name__} ... [dim gold3] skipped (no input)[/]')
					continue
				outputs = OUTPUTS_TASKS.get(cls.__name__, [])
				task = cls(input, **opts)
				try:
					self._test_runner_output(
						task,
						expected_output_types=cls.output_types,
						expected_results=outputs,
						empty_results_allowed=False,
						additional_checks=OUTPUTS_CHECKS
					)
				except AssertionError as e:
					failures.append(f'ERROR ({cls.__name__}): {e}')

		if failures:
			raise AssertionError("\n\n" + "\n\n".join(failures))
